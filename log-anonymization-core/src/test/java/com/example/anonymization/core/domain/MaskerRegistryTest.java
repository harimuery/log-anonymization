package com.example.anonymization.core.domain;

import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.model.MaskerConfig;
import com.example.anonymization.api.model.MaskingResult;
import com.example.anonymization.api.spi.SensitiveDataMasker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class MaskerRegistryTest {

    private MaskerRegistry registry;
    private SensitiveDataMasker partialMasker;
    private SensitiveDataMasker fullMasker;

    @BeforeEach
    void setUp() {
        partialMasker = new StubMasker(MaskerType.PARTIAL_MASK);
        fullMasker = new StubMasker(MaskerType.FULL_MASK);
        registry = new MaskerRegistry(List.of(partialMasker, fullMasker));
    }

    @Test
    @DisplayName("按类型获取已注册脱敏器")
    void getMasker_byType() {
        Optional<SensitiveDataMasker> found = registry.getMasker(MaskerType.PARTIAL_MASK);
        assertTrue(found.isPresent());
        assertEquals(partialMasker, found.get());
    }

    @Test
    @DisplayName("未注册类型返回空Optional")
    void getMasker_unregisteredType() {
        Optional<SensitiveDataMasker> found = registry.getMasker(MaskerType.HASH);
        assertTrue(found.isEmpty());
    }

    @Test
    @DisplayName("hasMasker正确判断注册状态")
    void hasMasker() {
        assertTrue(registry.hasMasker(MaskerType.PARTIAL_MASK));
        assertFalse(registry.hasMasker(MaskerType.HASH));
    }

    @Test
    @DisplayName("运行期动态注册脱敏器")
    void register_dynamic() {
        assertFalse(registry.hasMasker(MaskerType.DISCARD));
        registry.register(new StubMasker(MaskerType.DISCARD));
        assertTrue(registry.hasMasker(MaskerType.DISCARD));
    }

    @Test
    @DisplayName("getAllMaskers返回所有已注册脱敏器")
    void getAllMaskers() {
        assertEquals(2, registry.getAllMaskers().size());
    }

    private static class StubMasker implements SensitiveDataMasker {
        private final MaskerType type;

        StubMasker(MaskerType type) { this.type = type; }

        @Override
        public MaskingResult mask(String original, MaskerConfig config) {
            return MaskingResult.masked(original, "***");
        }

        @Override
        public MaskerType getMaskerType() { return type; }

        @Override
        public boolean isReversible() { return false; }
    }
}