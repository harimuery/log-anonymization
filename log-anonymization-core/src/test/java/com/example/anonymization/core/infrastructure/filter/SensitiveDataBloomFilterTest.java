package com.example.anonymization.core.infrastructure.filter;

import com.example.anonymization.api.enums.DetectorType;
import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.model.DetectorConfig;
import com.example.anonymization.api.model.MaskerConfig;
import com.example.anonymization.api.model.MaskingRule;
import com.example.anonymization.api.model.MaskingScope;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SensitiveDataBloomFilterTest {

    private SensitiveDataBloomFilter bloomFilter;

    @BeforeEach
    void setUp() {
        bloomFilter = new SensitiveDataBloomFilter();
    }

    @Test
    @DisplayName("rebuild后关键词可被检测到")
    void mightContain_afterRebuild() {
        MaskingRule rule = MaskingRule.builder()
            .ruleId("TEST-001").name("test").dataType(SensitiveDataType.BANK_CARD)
            .detector(DetectorType.REGEX, DetectorConfig.builder()
                .patterns(List.of("\\b\\d{16,19}\\b"))
                .keywords(List.of("card", "bankcard"))
                .build())
            .masker(MaskerType.PARTIAL_MASK, MaskerConfig.builder()
                .dataType(SensitiveDataType.BANK_CARD).build())
            .scope(MaskingScope.global()).priority(100).enabled(true).build();
        bloomFilter.rebuild(List.of(rule));
        assertTrue(bloomFilter.mightContainSensitiveData("card=6222021234567890"));
    }

    @Test
    @DisplayName("空消息返回false")
    void mightContain_emptyMessage() {
        assertFalse(bloomFilter.mightContainSensitiveData(""));
        assertFalse(bloomFilter.mightContainSensitiveData(null));
    }

    @Test
    @DisplayName("无关消息可能返回false")
    void mightContain_irrelevantMessage() {
        assertFalse(bloomFilter.mightContainSensitiveData("hello world"));
    }

    @Test
    @DisplayName("多次rebuild不抛异常")
    void rebuild_multipleTimes() {
        MaskingRule rule = MaskingRule.builder()
            .ruleId("TEST-001").name("test").dataType(SensitiveDataType.BANK_CARD)
            .detector(DetectorType.REGEX, DetectorConfig.builder()
                .patterns(List.of("\\b\\d{16,19}\\b"))
                .keywords(List.of("card"))
                .build())
            .masker(MaskerType.PARTIAL_MASK, MaskerConfig.builder()
                .dataType(SensitiveDataType.BANK_CARD).build())
            .scope(MaskingScope.global()).priority(100).enabled(true).build();
        assertDoesNotThrow(() -> {
            bloomFilter.rebuild(List.of(rule));
            bloomFilter.rebuild(List.of());
            bloomFilter.rebuild(List.of(rule));
        });
    }
}