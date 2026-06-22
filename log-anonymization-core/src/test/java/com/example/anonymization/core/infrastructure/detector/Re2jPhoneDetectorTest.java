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

class Re2jPhoneDetectorTest {

    private Re2jPhoneDetector detector;

    @BeforeEach
    void setUp() {
        DetectorConfig config = DetectorConfig.builder()
            .patterns(List.of("\\b(1[3-9]\\d{9})\\b"))
            .build();
        detector = new Re2jPhoneDetector(config);
    }

    @Test
    @DisplayName("检测手机号")
    void detect_phone() {
        String text = "phone=13800138000 called";
        List<DetectionResult> results = detect(text);
        assertFalse(results.isEmpty());
        assertEquals(SensitiveDataType.PHONE, results.get(0).dataType());
    }

    @Test
    @DisplayName("不同号段均可识别")
    void detect_differentPrefixes() {
        for (String phone : List.of("13800138000", "15912345678", "18612345678", "19912345678")) {
            List<DetectionResult> results = detect("mobile=" + phone);
            assertFalse(results.isEmpty(), "Should detect phone: " + phone);
        }
    }

    @Test
    @DisplayName("12开头号码不识别")
    void detect_nonPhonePrefix() {
        String text = "number=12000138000";
        List<DetectionResult> results = detect(text);
        assertTrue(results.isEmpty());
    }

    @Test
    @DisplayName("getSupportedType返回PHONE")
    void getSupportedType() {
        assertEquals(SensitiveDataType.PHONE, detector.getSupportedType());
    }

    private List<DetectionResult> detect(String text) {
        LogContext ctx = LogContext.builder().message(text).loggerName("test").threadName("main").build();
        return detector.detect(ctx);
    }
}