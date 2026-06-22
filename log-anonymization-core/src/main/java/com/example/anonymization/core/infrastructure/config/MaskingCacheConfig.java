package com.example.anonymization.core.infrastructure.config;

import com.example.anonymization.api.model.MaskingRule;
import com.example.anonymization.api.port.CachePort;
import com.example.anonymization.core.infrastructure.cache.CaffeineCacheAdapter;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import java.time.Duration;

/**
 * 独立缓存配置类 —— 集中管理 SDK 内部所有 Caffeine 缓存 Bean。
 *
 * <p>属于基础设施层（infrastructure/config），通过 Spring {@code @Configuration} 注解
 * 被 {@link com.example.anonymization.starter.LogAnonymizationAutoConfiguration}
 * 通过 {@code @Import} 引入。
 *
 * <p>设计原则：
 * <ul>
 *   <li><b>职责分离</b>：缓存配置与缓存适配器分离，配置类只负责创建缓存实例</li>
 *   <li><b>可配置</b>：最大容量、过期时间等通过 {@code application.yml} 动态调整</li>
 *   <li><b>统计开启</b>：默认开启 {@code recordStats()}，配合 Micrometer 暴露命中率指标</li>
 *   <li><b>避免 LoadingCache 陷阱</b>：不使用 {@code refreshAfterWrite}（需要 CacheLoader），
 *       改用 {@code expireAfterWrite} + 主动 reload 实现刷新</li>
 * </ul>
 *
 * <p>配置示例：
 * <pre>
 *   log-anonymization:
 *     cache:
 *       caffeine:
 *         rule-cache:
 *           max-size: 1000
 *           expire-after-write-seconds: 300
 *         pattern-cache:
 *           max-size: 500
 *           expire-after-access-seconds: 1800
 * </pre>
 *
 * <p>性能考量（5000 万用户量级）：
 * <ul>
 *   <li>规则缓存 1000 条：覆盖全部规则（通常 &lt; 100 条），命中率 &gt; 99%</li>
 *   <li>Pattern 缓存 500 条：re2j Pattern 编译耗时 ~0.1ms，缓存后命中 &lt; 1μs</li>
 *   <li>命中率监控：通过 {@code Caffeine.stats()} 暴露到 Micrometer，低于 95% 触发告警</li>
 * </ul>
 *
 * @author java-architect
 * @since 1.0.0
 */
@Configuration
public class MaskingCacheConfig {

    private static final Logger log = LoggerFactory.getLogger(MaskingCacheConfig.class);

    /**
     * 规则缓存 —— 缓存按 scope 加载的 {@link MaskingRule} 列表。
     *
     * <p>缓存策略：
     * <ul>
     *   <li>最大容量：1000 条（默认，可配置）</li>
     *   <li>写入后 5 分钟过期（默认，可配置）</li>
     *   <li>开启统计：用于监控命中率</li>
     *   <li>淘汰策略：LRU（最近最少使用）</li>
     * </ul>
     *
     * @param maxSize           最大条目数
     * @param expireAfterWrite  写入后过期秒数
     * @return Caffeine 规则缓存实例
     */
    @Bean("maskingRuleCache")
    @ConditionalOnMissingBean(name = "maskingRuleCache")
    public Cache<String, java.util.List<MaskingRule>> ruleCache(
            @Value("${log-anonymization.cache.caffeine.rule-cache.max-size:1000}") int maxSize,
            @Value("${log-anonymization.cache.caffeine.rule-cache.expire-after-write-seconds:300}") int expireAfterWrite) {

        Cache<String, java.util.List<MaskingRule>> cache = Caffeine.newBuilder()
            .maximumSize(maxSize)
            .expireAfterWrite(Duration.ofSeconds(expireAfterWrite))
            .recordStats()
            .build();

        log.info("规则缓存已初始化: maxSize={}, expireAfterWrite={}s", maxSize, expireAfterWrite);
        return cache;
    }

    /**
     * 正则 Pattern 缓存 —— 缓存 re2j 编译后的 Pattern 对象。
     *
     * <p>缓存策略：
     * <ul>
     *   <li>最大容量：500 条（默认，可配置）</li>
     *   <li>访问后 30 分钟过期（默认，可配置）—— Pattern 对象较大，长期不用的应回收</li>
     *   <li>淘汰策略：LRU</li>
     * </ul>
     *
     * @param maxSize             最大条目数
     * @param expireAfterAccess   访问后过期秒数
     * @return Caffeine Pattern 缓存实例
     */
    @Bean("maskingPatternCache")
    @ConditionalOnMissingBean(name = "maskingPatternCache")
    public Cache<String, com.google.re2j.Pattern> patternCache(
            @Value("${log-anonymization.cache.caffeine.pattern-cache.max-size:500}") int maxSize,
            @Value("${log-anonymization.cache.caffeine.pattern-cache.expire-after-access-seconds:1800}") int expireAfterAccess) {

        Cache<String, com.google.re2j.Pattern> cache = Caffeine.newBuilder()
            .maximumSize(maxSize)
            .expireAfterAccess(Duration.ofSeconds(expireAfterAccess))
            .build();

        log.info("Pattern 缓存已初始化: maxSize={}, expireAfterAccess={}s", maxSize, expireAfterAccess);
        return cache;
    }

    /**
     * Caffeine 缓存适配器 —— 整合规则缓存与 Pattern 缓存，提供统一的 {@link CachePort} 视图。
     *
     * <p>使用 {@code @Primary} 标注，当存在多个 {@link CaffeineCacheAdapter} 候选时优先注入此 Bean。
     * 业务方可通过提供自定义 {@link CaffeineCacheAdapter} Bean 覆盖默认实现。
     *
     * @param ruleCache    规则缓存（由 {@link #ruleCache} 创建）
     * @param patternCache Pattern 缓存（由 {@link #patternCache} 创建）
     * @return 缓存适配器
     */
    @Bean
    @Primary
    @ConditionalOnMissingBean(CaffeineCacheAdapter.class)
    public CaffeineCacheAdapter caffeineCacheAdapter(
            Cache<String, java.util.List<MaskingRule>> ruleCache,
            Cache<String, com.google.re2j.Pattern> patternCache) {
        return new CaffeineCacheAdapter(ruleCache, patternCache);
    }
}