package com.example.anonymization.core.infrastructure.masker;

import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.model.MaskerConfig;
import com.example.anonymization.api.model.MaskingResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PartialMaskMaskerTest {

    private PartialMaskMasker masker;
    private MaskerConfig bankCardConfig;

    @BeforeEach
    void setUp() {
        masker = new PartialMaskMasker();
        bankCardConfig = MaskerConfig.builder()
            .keepPrefixLen(4)
            .keepSuffixLen(4)
            .maskChar('*')
            .dataType(SensitiveDataType.BANK_CARD)
            .build();
    }

    @Test
    @DisplayName("银行卡号部分遮盖：前4后4中间掩码")
    void mask_bankCard() {
        MaskingResult result = masker.mask("6222021234567890", bankCardConfig);
        assertTrue(result.isChanged());
        String expected = "6222********7890";
        assertEquals(expected, result.getMasked());
    }

    @Test
    @DisplayName("手机号部分遮盖：前3后4中间掩码")
    void mask_phone() {
        MaskerConfig phoneConfig = MaskerConfig.builder()
            .keepPrefixLen(3).keepSuffixLen(4).maskChar('*')
            .dataType(SensitiveDataType.PHONE).build();
        MaskingResult result = masker.mask("13800138000", phoneConfig);
        assertTrue(result.isChanged());
        assertTrue(result.getMasked().startsWith("138"));
        assertTrue(result.getMasked().endsWith("8000"));
    }

    @Test
    @DisplayName("空字符串返回unchanged")
    void mask_emptyString() {
        MaskingResult result = masker.mask("", bankCardConfig);
        assertEquals("", result.getMasked());
    }

    @Test
    @DisplayName("null返回unchanged")
    void mask_null() {
        MaskingResult result = masker.mask(null, bankCardConfig);
        assertNull(result.getMasked());
    }

    @Test
    @DisplayName("getMaskerType返回PARTIAL_MASK")
    void getMaskerType() {
        assertEquals(MaskerType.PARTIAL_MASK, masker.getMaskerType());
    }

    @Test
    @DisplayName("isReversible返回false")
    void isReversible() {
        assertFalse(masker.isReversible());
    }

    @Test
    @DisplayName("prefix+suffix>=length时退化为全掩码")
    void mask_degenerateToFullMask() {
        MaskerConfig config = MaskerConfig.builder()
            .keepPrefixLen(5).keepSuffixLen(5).maskChar('*')
            .dataType(SensitiveDataType.BANK_CARD).build();
        MaskingResult result = masker.mask("12345", config);
        assertEquals("*****", result.getMasked());
    }
}