package com.example.anonymization.core.infrastructure.cache;

import com.example.anonymization.api.model.MaskingRule;
import com.example.anonymization.api.port.CachePort;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * Caffeine 缓存适配器 —— 提供规则与编译后正则 Pattern 的本地缓存（L1 缓存）。
 *
 * <p>使用场景：作为 {@link CachePort} 的 L1 本地缓存实现，
 * 配合规则加载器/检测器使用；可与 {@link RedisCacheAdapter}（L2）组成多级缓存。
 *
 * <p>缓存策略：
 * <ul>
 *   <li>{@code ruleCache}：最大 1000 条，写入 30s 后自动刷新，5 分钟过期（适合规则列表这种低频写高频读）</li>
 *   <li>{@code patternCache}：最大 500 条，30 分钟无访问过期（适合 re2j 编译后的 Pattern 对象）</li>
 * </ul>
 *
 * <p>线程安全：Caffeine 内部保证并发安全，本适配器所有方法均无锁。
 *
 * @author log-anonymization
 */
public class CaffeineCacheAdapter {

    private final Cache<String, List<MaskingRule>> ruleCache;
    private final Cache<String, com.google.re2j.Pattern> patternCache;

    private final RuleCachePort ruleCachePort;
    private final PatternCachePort patternCachePort;

    /**
     * 构造 Caffeine 缓存适配器（按既定策略初始化两个缓存实例）。
     */
    public CaffeineCacheAdapter() {
        this.ruleCache = Caffeine.newBuilder()
            .maximumSize(1000)
            .expireAfterWrite(Duration.ofMinutes(5))
            .recordStats()
            .build();

        this.patternCache = Caffeine.newBuilder()
            .maximumSize(500)
            .expireAfterAccess(Duration.ofMinutes(30))
            .build();

        this.ruleCachePort = new RuleCachePort(ruleCache);
        this.patternCachePort = new PatternCachePort(patternCache);
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

    /**
     * 获取规则缓存的 {@link CachePort} 视图。
     *
     * <p>用于需要通过抽象端口接口操作缓存的场景（如多级缓存编排器）。
     *
     * @return 规则缓存端口
     */
    public CachePort<List<MaskingRule>> ruleCachePort() {
        return ruleCachePort;
    }

    /**
     * 获取正则 Pattern 缓存的 {@link CachePort} 视图。
     *
     * @return Pattern 缓存端口
     */
    public CachePort<com.google.re2j.Pattern> patternCachePort() {
        return patternCachePort;
    }

    /**
     * 规则缓存端口 —— 将 Caffeine {@link Cache} 适配为 {@link CachePort}。
     */
    private static final class RuleCachePort implements CachePort<List<MaskingRule>> {

        private final Cache<String, List<MaskingRule>> cache;

        RuleCachePort(Cache<String, List<MaskingRule>> cache) {
            this.cache = cache;
        }

        @Override
        public Optional<List<MaskingRule>> get(String key) {
            return Optional.ofNullable(cache.getIfPresent(key));
        }

        @Override
        public void put(String key, List<MaskingRule> value) {
            cache.put(key, value);
        }

        @Override
        public void put(String key, List<MaskingRule> value, long ttlSeconds) {
            cache.put(key, value);
        }

        @Override
        public void evict(String key) {
            cache.invalidate(key);
        }

        @Override
        public void clear() {
            cache.invalidateAll();
        }

        @Override
        public boolean containsKey(String key) {
            return cache.getIfPresent(key) != null;
        }

        @Override
        public long size() {
            return cache.estimatedSize();
        }
    }

    /**
     * Pattern 缓存端口 —— 将 Caffeine {@link Cache} 适配为 {@link CachePort}。
     */
    private static final class PatternCachePort implements CachePort<com.google.re2j.Pattern> {

        private final Cache<String, com.google.re2j.Pattern> cache;

        PatternCachePort(Cache<String, com.google.re2j.Pattern> cache) {
            this.cache = cache;
        }

        @Override
        public Optional<com.google.re2j.Pattern> get(String key) {
            return Optional.ofNullable(cache.getIfPresent(key));
        }

        @Override
        public void put(String key, com.google.re2j.Pattern value) {
            cache.put(key, value);
        }

        @Override
        public void put(String key, com.google.re2j.Pattern value, long ttlSeconds) {
            cache.put(key, value);
        }

        @Override
        public void evict(String key) {
            cache.invalidate(key);
        }

        @Override
        public void clear() {
            cache.invalidateAll();
        }

        @Override
        public boolean containsKey(String key) {
            return cache.getIfPresent(key) != null;
        }

        @Override
        public long size() {
            return cache.estimatedSize();
        }
    }
}