package com.example.anonymization.core.infrastructure.masker;

import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.model.MaskerConfig;
import com.example.anonymization.api.model.MaskingResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class FullMaskMaskerTest {

    private FullMaskMasker masker;
    private MaskerConfig config;

    @BeforeEach
    void setUp() {
        masker = new FullMaskMasker();
        config = MaskerConfig.builder().maskChar('*').build();
    }

    @Test
    @DisplayName("全量打码替换为等长星号")
    void mask_fullMask() {
        MaskingResult result = masker.mask("secret", config);
        assertTrue(result.isChanged());
        assertEquals("******", result.getMasked());
    }

    @Test
    @DisplayName("空字符串走短路返回原值")
    void mask_empty() {
        MaskingResult result = masker.mask("", config);
        assertEquals("", result.getMasked());
    }

    @Test
    @DisplayName("null走短路返回null")
    void mask_null() {
        MaskingResult result = masker.mask(null, config);
        assertNull(result.getMasked());
    }

    @Test
    @DisplayName("getMaskerType返回FULL_MASK")
    void getMaskerType() {
        assertEquals(MaskerType.FULL_MASK, masker.getMaskerType());
    }

    @Test
    @DisplayName("isReversible返回false")
    void isReversible() {
        assertFalse(masker.isReversible());
    }

    @Test
    @DisplayName("不同maskChar使用不同字符")
    void mask_differentChar() {
        MaskerConfig hashConfig = MaskerConfig.builder().maskChar('#').build();
        MaskingResult result = masker.mask("abc", hashConfig);
        assertEquals("###", result.getMasked());
    }
}