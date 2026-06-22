package com.example.anonymization.core.infrastructure.detector;

import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.model.DetectionResult;
import com.example.anonymization.api.model.DetectorConfig;
import com.example.anonymization.api.model.LogContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class Re2jBankCardDetectorTest {

    private Re2jBankCardDetector detector;

    @BeforeEach
    void setUp() {
        DetectorConfig config = DetectorConfig.builder()
            .patterns(List.of("\\b(\\d{16,19})\\b"))
            .enableLuhnCheck(true)
            .build();
        detector = new Re2jBankCardDetector(config);
    }

    @Test
    @DisplayName("检测Luhn有效的银行卡号")
    void detect_bankCard() {
        String text = "card=4111111111111111 paid";
        List<DetectionResult> results = detect(text);
        assertFalse(results.isEmpty());
        assertTrue(results.stream().anyMatch(r -> r.dataType() == SensitiveDataType.BANK_CARD));
    }

    @Test
    @DisplayName("Luhn校验过滤无效卡号")
    void detect_invalidCardFiltered() {
        String text = "invalid=1234567890123456";
        List<DetectionResult> results = detect(text);
        assertTrue(results.isEmpty());
    }

    @Test
    @DisplayName("无敏感数据返回空列表")
    void detect_noSensitiveData() {
        String text = "normal log message without sensitive data";
        List<DetectionResult> results = detect(text);
        assertTrue(results.isEmpty());
    }

    @Test
    @DisplayName("getSupportedType返回BANK_CARD")
    void getSupportedType() {
        assertEquals(SensitiveDataType.BANK_CARD, detector.getSupportedType());
    }

    @Test
    @DisplayName("getDetectorName返回RE2J-BANK_CARD")
    void getDetectorName() {
        assertEquals("RE2J-BANK_CARD", detector.getDetectorName());
    }

    private List<DetectionResult> detect(String text) {
        LogContext ctx = LogContext.builder().message(text).loggerName("test").threadName("main").build();
        return detector.detect(ctx);
    }
}