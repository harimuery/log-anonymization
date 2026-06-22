package com.example.anonymization.core.infrastructure.cache;

import com.example.anonymization.api.model.MaskingRule;
import com.example.anonymization.api.port.CachePort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class CaffeineCacheAdapterTest {

    private CaffeineCacheAdapter adapter;

    @BeforeEach
    void setUp() {
        adapter = new CaffeineCacheAdapter();
    }

    @Test
    @DisplayName("规则缓存端口：put后get可获取")
    void ruleCachePort_putAndGet() {
        CachePort<List<MaskingRule>> port = adapter.ruleCachePort();
        List<MaskingRule> rules = List.of();
        port.put("test-key", rules);
        Optional<List<MaskingRule>> result = port.get("test-key");
        assertTrue(result.isPresent());
    }

    @Test
    @DisplayName("规则缓存端口：未put的key返回空Optional")
    void ruleCachePort_getMissing() {
        CachePort<List<MaskingRule>> port = adapter.ruleCachePort();
        assertTrue(port.get("non-existent").isEmpty());
    }

    @Test
    @DisplayName("规则缓存端口：evict后key不存在")
    void ruleCachePort_evict() {
        CachePort<List<MaskingRule>> port = adapter.ruleCachePort();
        port.put("test-key", List.of());
        port.evict("test-key");
        assertTrue(port.get("test-key").isEmpty());
    }

    @Test
    @DisplayName("规则缓存端口：clear清空所有条目")
    void ruleCachePort_clear() {
        CachePort<List<MaskingRule>> port = adapter.ruleCachePort();
        port.put("key1", List.of());
        port.put("key2", List.of());
        port.clear();
        assertEquals(0, port.size());
    }

    @Test
    @DisplayName("规则缓存端口：containsKey判断正确")
    void ruleCachePort_containsKey() {
        CachePort<List<MaskingRule>> port = adapter.ruleCachePort();
        assertFalse(port.containsKey("key1"));
        port.put("key1", List.of());
        assertTrue(port.containsKey("key1"));
    }

    @Test
    @DisplayName("规则缓存端口：size返回条目数")
    void ruleCachePort_size() {
        CachePort<List<MaskingRule>> port = adapter.ruleCachePort();
        assertEquals(0, port.size());
        port.put("key1", List.of());
        assertEquals(1, port.size());
    }

    @Test
    @DisplayName("Pattern缓存端口：put后get可获取")
    void patternCachePort_putAndGet() {
        CachePort<com.google.re2j.Pattern> port = adapter.patternCachePort();
        com.google.re2j.Pattern pattern = com.google.re2j.Pattern.compile("\\d+");
        port.put("digit-pattern", pattern);
        Optional<com.google.re2j.Pattern> result = port.get("digit-pattern");
        assertTrue(result.isPresent());
    }

    @Test
    @DisplayName("getRuleCache返回Caffeine Cache实例")
    void getRuleCache() {
        assertNotNull(adapter.getRuleCache());
    }

    @Test
    @DisplayName("getPatternCache返回Caffeine Cache实例")
    void getPatternCache() {
        assertNotNull(adapter.getPatternCache());
    }
}