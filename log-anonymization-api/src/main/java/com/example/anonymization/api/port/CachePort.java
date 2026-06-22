package com.example.anonymization.api.port;

import java.util.List;
import java.util.Optional;

/**
 * 缓存出站端口 —— 抽象缓存读写操作，解耦 Domain 层与具体缓存实现（Caffeine / Redis 等）。
 *
 * <p>使用场景：
 * <ul>
 *   <li>规则缓存：{@code key=appName/appProfile}，{@code value=List<MaskingRule>}</li>
 *   <li>正则 Pattern 缓存：{@code key=patternString}，{@code value=编译后 Pattern}</li>
 *   <li>多级缓存体系中的 L1（Caffeine 本地）和 L2（Redis 分布式）均实现本接口</li>
 * </ul>
 *
 * <p>设计原则：
 * <ul>
 *   <li>泛型化：支持不同值类型（规则列表、Pattern 对象等）</li>
 *   <li>可选性：{@link #get} 返回 {@link Optional}，避免 null 判断散落调用方</li>
 *   <li>零外部依赖：本接口位于 api 模块，不得引入 Caffeine/Redis 等具体实现依赖</li>
 * </ul>
 *
 * @param <V> 缓存值类型
 * @author log-anonymization
 */
public interface CachePort<V> {

    /**
     * 获取缓存值。
     *
     * @param key 缓存键，不可为 null
     * @return 缓存值的 Optional 包装（未命中时为空 Optional）
     */
    Optional<V> get(String key);

    /**
     * 写入缓存。
     *
     * @param key   缓存键，不可为 null
     * @param value 缓存值，不可为 null
     */
    void put(String key, V value);

    /**
     * 写入缓存（带 TTL）。
     *
     * <p>实现方应根据 TTL 决定过期策略；不支持 TTL 的实现（如 Caffeine 全局配置）
     * 可忽略此参数，以全局配置为准。
     *
     * @param key     缓存键
     * @param value   缓存值
     * @param ttlSeconds 生存时间（秒），{@code <= 0} 表示永不过期
     */
    default void put(String key, V value, long ttlSeconds) {
        put(key, value);
    }

    /**
     * 移除指定缓存条目。
     *
     * @param key 缓存键
     */
    void evict(String key);

    /**
     * 清空所有缓存条目。
     */
    void clear();

    /**
     * 判断指定键是否存在于缓存中。
     *
     * @param key 缓存键
     * @return {@code true} 表示存在
     */
    boolean containsKey(String key);

    /**
     * 获取当前缓存条目数（近似值，用于监控指标）。
     *
     * @return 条目数
     */
    long size();
}