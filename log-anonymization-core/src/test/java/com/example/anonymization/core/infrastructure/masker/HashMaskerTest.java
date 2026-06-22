package com.example.anonymization.core.infrastructure.masker;

import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.model.MaskerConfig;
import com.example.anonymization.api.model.MaskingResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HashMaskerTest {

    private HashMasker masker;

    @BeforeEach
    void setUp() {
        masker = new HashMasker("test-salt");
    }

    @Test
    @DisplayName("SHA-256哈希产生64位十六进制字符串")
    void mask_sha256() {
        MaskerConfig config = MaskerConfig.builder().build();
        MaskingResult result = masker.mask("6222021234567890", config);
        assertTrue(result.isChanged());
        assertEquals(64, result.getMasked().length());
        assertTrue(result.getMasked().matches("[0-9a-f]+"));
    }

    @Test
    @DisplayName("相同输入产生相同哈希（幂等性）")
    void mask_idempotent() {
        MaskerConfig config = MaskerConfig.builder().build();
        MaskingResult r1 = masker.mask("6222021234567890", config);
        MaskingResult r2 = masker.mask("6222021234567890", config);
        assertEquals(r1.getMasked(), r2.getMasked());
    }

    @Test
    @DisplayName("不同输入产生不同哈希")
    void mask_differentInputs() {
        MaskerConfig config = MaskerConfig.builder().build();
        MaskingResult r1 = masker.mask("6222021234567890", config);
        MaskingResult r2 = masker.mask("6222021234567891", config);
        assertNotEquals(r1.getMasked(), r2.getMasked());
    }

    @Test
    @DisplayName("盐值影响哈希结果")
    void mask_saltAffectsResult() {
        HashMasker otherMasker = new HashMasker("different-salt");
        MaskerConfig config = MaskerConfig.builder().build();
        MaskingResult r1 = masker.mask("6222021234567890", config);
        MaskingResult r2 = otherMasker.mask("6222021234567890", config);
        assertNotEquals(r1.getMasked(), r2.getMasked());
    }

    @Test
    @DisplayName("getMaskerType返回HASH")
    void getMaskerType() {
        assertEquals(MaskerType.HASH, masker.getMaskerType());
    }

    @Test
    @DisplayName("isReversible返回false")
    void isReversible() {
        assertFalse(masker.isReversible());
    }
}