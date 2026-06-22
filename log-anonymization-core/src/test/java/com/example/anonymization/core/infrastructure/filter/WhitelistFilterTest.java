package com.example.anonymization.core.infrastructure.filter;

import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.model.DetectionResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class WhitelistFilterTest {

    private WhitelistFilter filter;

    @BeforeEach
    void setUp() {
        filter = new WhitelistFilter();
    }

    @Test
    @DisplayName("UUID被白名单过滤")
    void filter_uuid() {
        DetectionResult uuidResult = new DetectionResult(
            0, 36, SensitiveDataType.BANK_CARD, 0.9, "550e8400-e29b-41d4-a716-446655440000");
        List<DetectionResult> filtered = filter.filter(List.of(uuidResult));
        assertTrue(filtered.isEmpty());
    }

    @Test
    @DisplayName("真实银行卡号不被过滤")
    void filter_realBankCard() {
        DetectionResult bankCardResult = new DetectionResult(
            0, 16, SensitiveDataType.BANK_CARD, 1.0, "6222021234567890");
        List<DetectionResult> filtered = filter.filter(List.of(bankCardResult));
        assertFalse(filtered.isEmpty());
    }

    @Test
    @DisplayName("时间戳被白名单过滤")
    void filter_timestamp() {
        DetectionResult tsResult = new DetectionResult(
            0, 13, SensitiveDataType.BANK_CARD, 0.5, "1700000000000");
        List<DetectionResult> filtered = filter.filter(List.of(tsResult));
        assertTrue(filtered.isEmpty());
    }

    @Test
    @DisplayName("空列表安全返回空列表")
    void filter_emptyList() {
        assertEquals(List.of(), filter.filter(List.of()));
    }

    @Test
    @DisplayName("null安全返回空列表")
    void filter_null() {
        assertEquals(List.of(), filter.filter(null));
    }

    @Test
    @DisplayName("isWhitelisted对UUID返回true")
    void isWhitelisted_uuid() {
        assertTrue(filter.isWhitelisted("550e8400-e29b-41d4-a716-446655440000"));
    }

    @Test
    @DisplayName("isWhitelisted对银行卡号返回false")
    void isWhitelisted_bankCard() {
        assertFalse(filter.isWhitelisted("6222021234567890"));
    }

    @Test
    @DisplayName("patternCount返回正数")
    void patternCount() {
        assertTrue(filter.patternCount() > 0);
    }
}