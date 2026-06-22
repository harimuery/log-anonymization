package com.example.anonymization.core.domain;

import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.model.MaskingRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class DetectorRegistryTest {

    private DetectorRegistry registry;
    private com.example.anonymization.api.spi.SensitiveDataDetector bankCardDetector;
    private com.example.anonymization.api.spi.SensitiveDataDetector phoneDetector;

    @BeforeEach
    void setUp() {
        bankCardDetector = new StubDetector(SensitiveDataType.BANK_CARD, "STUB-BANK_CARD");
        phoneDetector = new StubDetector(SensitiveDataType.PHONE, "STUB-PHONE");
        registry = new DetectorRegistry(List.of(bankCardDetector, phoneDetector));
    }

    @Test
    @DisplayName("按类型获取已注册检测器")
    void getDetector_byType() {
        Optional<com.example.anonymization.api.spi.SensitiveDataDetector> found =
            registry.getDetector(SensitiveDataType.BANK_CARD);
        assertTrue(found.isPresent());
        assertEquals(bankCardDetector, found.get());
    }

    @Test
    @DisplayName("未注册类型返回空Optional")
    void getDetector_unregisteredType() {
        Optional<com.example.anonymization.api.spi.SensitiveDataDetector> found =
            registry.getDetector(SensitiveDataType.CVV);
        assertTrue(found.isEmpty());
    }

    @Test
    @DisplayName("hasDetector正确判断注册状态")
    void hasDetector() {
        assertTrue(registry.hasDetector(SensitiveDataType.BANK_CARD));
        assertFalse(registry.hasDetector(SensitiveDataType.CVV));
    }

    @Test
    @DisplayName("运行期动态注册检测器")
    void register_dynamic() {
        assertFalse(registry.hasDetector(SensitiveDataType.EMAIL));
        registry.register(new StubDetector(SensitiveDataType.EMAIL, "STUB-EMAIL"));
        assertTrue(registry.hasDetector(SensitiveDataType.EMAIL));
    }

    @Test
    @DisplayName("getAllDetectors返回所有已注册检测器")
    void getAllDetectors() {
        List<com.example.anonymization.api.spi.SensitiveDataDetector> all = registry.getAllDetectors();
        assertEquals(2, all.size());
    }

    @Test
    @DisplayName("同类型后注册覆盖先注册")
    void register_overwrite() {
        com.example.anonymization.api.spi.SensitiveDataDetector newBankCardDetector =
            new StubDetector(SensitiveDataType.BANK_CARD, "STUB-BANK_CARD-V2");
        registry.register(newBankCardDetector);
        assertEquals(newBankCardDetector, registry.getDetector(SensitiveDataType.BANK_CARD).get());
    }

    private static class StubDetector implements com.example.anonymization.api.spi.SensitiveDataDetector {
        private final SensitiveDataType type;
        private final String name;

        StubDetector(SensitiveDataType type, String name) {
            this.type = type;
            this.name = name;
        }

        @Override
        public List<com.example.anonymization.api.model.DetectionResult> detect(
            com.example.anonymization.api.model.LogContext context) {
            return List.of();
        }

        @Override
        public SensitiveDataType getSupportedType() { return type; }

        @Override
        public String getDetectorName() { return name; }
    }
}