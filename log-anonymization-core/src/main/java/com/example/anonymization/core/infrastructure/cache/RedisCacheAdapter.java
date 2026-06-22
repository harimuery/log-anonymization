package com.example.anonymization.core.infrastructure.cache;

import com.example.anonymization.api.model.MaskingRule;
import com.example.anonymization.api.port.CachePort;
import com.google.re2j.Pattern;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * Redis 分布式缓存适配器 —— {@link CachePort} 的 L2 远端缓存实现。
 *
 * <p>使用场景：多实例部署时，通过 Redis 共享规则缓存与编译后 Pattern 缓存，
 * 避免每个实例独立从 Nacos/本地文件加载规则，减少规则变更时各实例刷新不一致。
 *
 * <p>设计要点：
 * <ul>
 *   <li>Key 模式：{@code masking:rules:{appName}} / {@code masking:pattern:{hash}}</li>
 *   <li>序列化：Java 原生序列化（规则列表）+ Base64 编码（Pattern 对象）</li>
 *   <li>TTL：默认 60s，通过配置 {@code cache.redis.ttl-seconds} 调整</li>
 *   <li>可选性：classpath 下需存在 Spring Data Redis，否则不装配</li>
 * </ul>
 *
 * <p>线程安全：RedisTemplate 本身线程安全，本适配器无状态可并发调用。
 *
 * @author log-anonymization
 */
public class RedisCacheAdapter<V> implements CachePort<V> {

    private static final String KEY_PREFIX = "masking:";
    private static final String RULES_KEY_SUFFIX = ":rules";
    private static final String PATTERN_KEY_SUFFIX = ":pattern";

    private final Object redisTemplate;
    private final long ttlSeconds;
    private final Function<V, byte[]> serializer;
    private final Function<byte[], V> deserializer;

    /**
     * 构造 Redis 缓存适配器。
     *
     * <p>使用 Spring Data Redis 的 {@code RedisTemplate} 进行操作。
     * 由于本模块不直接依赖 {@code spring-data-redis}（保持可选性），
     * 通过 {@code Object} 类型接收 RedisTemplate 实例，
     * 在运行时通过反射调用其方法。
     *
     * @param redisTemplate Spring Data Redis 的 RedisTemplate 实例
     * @param ttlSeconds    缓存 TTL（秒）
     * @param serializer    值序列化函数
     * @param deserializer  值反序列化函数
     */
    public RedisCacheAdapter(Object redisTemplate, long ttlSeconds,
                             Function<V, byte[]> serializer,
                             Function<byte[], V> deserializer) {
        this.redisTemplate = redisTemplate;
        this.ttlSeconds = ttlSeconds;
        this.serializer = serializer;
        this.deserializer = deserializer;
    }

    /**
     * 创建规则列表缓存适配器。
     *
     * @param redisTemplate RedisTemplate 实例
     * @param appName       应用名（作为 Key 的一部分）
     * @param ttlSeconds    TTL 秒数
     * @return 规则缓存适配器
     */
    public static RedisCacheAdapter<List<MaskingRule>> forRules(Object redisTemplate,
                                                                  String appName,
                                                                  long ttlSeconds) {
        return new RedisCacheAdapter<>(
            redisTemplate, ttlSeconds,
            RedisCacheAdapter::serializeObject,
            RedisCacheAdapter::deserializeRules
        );
    }

    /**
     * 创建 Pattern 缓存适配器。
     *
     * @param redisTemplate RedisTemplate 实例
     * @param ttlSeconds    TTL 秒数
     * @return Pattern 缓存适配器
     */
    public static RedisCacheAdapter<Pattern> forPatterns(Object redisTemplate, long ttlSeconds) {
        return new RedisCacheAdapter<>(
            redisTemplate, ttlSeconds,
            RedisCacheAdapter::serializeObject,
            RedisCacheAdapter::deserializePattern
        );
    }

    @Override
    public Optional<V> get(String key) {
        try {
            byte[] rawKey = buildKey(key);
            byte[] rawValue = invokeRedisGet(rawKey);
            if (rawValue == null) return Optional.empty();
            return Optional.of(deserializer.apply(rawValue));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    @Override
    public void put(String key, V value) {
        put(key, value, ttlSeconds);
    }

    @Override
    public void put(String key, V value, long ttlSeconds) {
        try {
            byte[] rawKey = buildKey(key);
            byte[] rawValue = serializer.apply(value);
            invokeRedisSet(rawKey, rawValue, ttlSeconds);
        } catch (Exception e) {
            System.err.println("[RedisCache] Failed to put key=" + key + ": " + e.getMessage());
        }
    }

    @Override
    public void evict(String key) {
        try {
            byte[] rawKey = buildKey(key);
            invokeRedisDelete(rawKey);
        } catch (Exception e) {
            System.err.println("[RedisCache] Failed to evict key=" + key + ": " + e.getMessage());
        }
    }

    @Override
    public void clear() {
        throw new UnsupportedOperationException(
            "RedisCacheAdapter.clear() is not supported for safety reasons. Use evict(key) instead.");
    }

    @Override
    public boolean containsKey(String key) {
        return get(key).isPresent();
    }

    @Override
    public long size() {
        return -1;
    }

    private byte[] buildKey(String key) {
        return (KEY_PREFIX + key).getBytes();
    }

    @SuppressWarnings("unchecked")
    private byte[] invokeRedisGet(byte[] key) throws Exception {
        var conn = redisTemplate.getClass().getMethod("getConnectionFactory").invoke(redisTemplate);
        var redisConn = conn.getClass().getMethod("getConnection").invoke(conn);
        try {
            return (byte[]) redisConn.getClass().getMethod("get", byte[].class).invoke(redisConn, key);
        } finally {
            redisConn.getClass().getMethod("close").invoke(redisConn);
        }
    }

    @SuppressWarnings("unchecked")
    private void invokeRedisSet(byte[] key, byte[] value, long ttl) throws Exception {
        var conn = redisTemplate.getClass().getMethod("getConnectionFactory").invoke(redisTemplate);
        var redisConn = conn.getClass().getMethod("getConnection").invoke(conn);
        try {
            redisConn.getClass().getMethod("setEx", byte[].class, long.class, byte[].class)
                .invoke(redisConn, key, ttl, value);
        } finally {
            redisConn.getClass().getMethod("close").invoke(redisConn);
        }
    }

    @SuppressWarnings("unchecked")
    private void invokeRedisDelete(byte[] key) throws Exception {
        var conn = redisTemplate.getClass().getMethod("getConnectionFactory").invoke(redisTemplate);
        var redisConn = conn.getClass().getMethod("getConnection").invoke(conn);
        try {
            redisConn.getClass().getMethod("del", byte[].class).invoke(redisConn, key);
        } finally {
            redisConn.getClass().getMethod("close").invoke(redisConn);
        }
    }

    @SuppressWarnings("unchecked")
    private static byte[] serializeObject(Object obj) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(obj);
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Serialization failed", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static List<MaskingRule> deserializeRules(byte[] data) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bis)) {
            return (List<MaskingRule>) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException("Deserialization failed", e);
        }
    }

    private static Pattern deserializePattern(byte[] data) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bis)) {
            return (Pattern) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException("Deserialization failed", e);
        }
    }
}