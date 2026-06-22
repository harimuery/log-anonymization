package com.example.anonymization.core.infrastructure.masker;

import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.model.MaskerConfig;
import com.example.anonymization.api.model.MaskingResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DiscardMaskerTest {

    private DiscardMasker masker;

    @BeforeEach
    void setUp() {
        masker = new DiscardMasker();
    }

    @Test
    @DisplayName("丢弃型打码返回空字符串")
    void mask_discard() {
        MaskerConfig config = MaskerConfig.builder().build();
        MaskingResult result = masker.mask("sensitive-data", config);
        assertTrue(result.isChanged());
        assertEquals("", result.getMasked());
    }

    @Test
    @DisplayName("getMaskerType返回DISCARD")
    void getMaskerType() {
        assertEquals(MaskerType.DISCARD, masker.getMaskerType());
    }

    @Test
    @DisplayName("isReversible返回false")
    void isReversible() {
        assertFalse(masker.isReversible());
    }
}