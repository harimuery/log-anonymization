package com.example.anonymization.core.infrastructure.cache;

import com.example.anonymization.api.model.MaskingRule;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.time.Duration;
import java.util.List;

/**
 * Caffeine 缓存适配器 —— 提供规则与编译后正则 Pattern 的本地缓存。
 *
 * <p>使用场景：业务方按需通过 {@link #getRuleCache} / {@link #getPatternCache}
 * 获取 Caffeine {@link Cache} 实例，配合规则加载器/检测器使用。
 *
 * <p>缓存策略：
 * <ul>
 *   <li>{@code ruleCache}：最大 1000 条，写入 30s 后自动刷新，5 分钟过期（适合规则列表这种低频写高频读）</li>
 *   <li>{@code patternCache}：最大 500 条，30 分钟无访问过期（适合 re2j 编译后的 Pattern 对象）</li>
 * </ul>
 *
 * @author log-anonymization
 */
public class CaffeineCacheAdapter {

    private final Cache<String, List<MaskingRule>> ruleCache;
    private final Cache<String, com.google.re2j.Pattern> patternCache;

    /**
     * 构造 Caffeine 缓存适配器（按既定策略初始化两个缓存实例）。
     *
     * <p>典型使用：通过 Spring 自动装配注入后，业务方调用 {@link #getRuleCache} / {@link #getPatternCache}。
     */
    public CaffeineCacheAdapter() {
        this.ruleCache = Caffeine.newBuilder()
            .maximumSize(1000)
            .refreshAfterWrite(Duration.ofSeconds(30))
            .expireAfterWrite(Duration.ofMinutes(5))
            .recordStats()
            .build();

        this.patternCache = Caffeine.newBuilder()
            .maximumSize(500)
            .expireAfterAccess(Duration.ofMinutes(30))
            .build();
    }

    /**
     * 获取规则缓存实例。
     *
     * @return Caffeine {@link Cache}，键为规则 ID/分类标识，值为规则列表
     */
    public Cache<String, List<MaskingRule>> getRuleCache() {
        return ruleCache;
    }

    /**
     * 获取正则 Pattern 缓存实例。
     *
     * @return Caffeine {@link Cache}，键为正则字符串，值为 re2j 编译后的 Pattern
     */
    public Cache<String, com.google.re2j.Pattern> getPatternCache() {
        return patternCache;
    }
}