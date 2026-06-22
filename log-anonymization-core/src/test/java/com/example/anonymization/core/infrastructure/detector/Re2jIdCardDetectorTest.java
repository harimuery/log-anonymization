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

class Re2jIdCardDetectorTest {

    private Re2jIdCardDetector detector;

    @BeforeEach
    void setUp() {
        DetectorConfig config = DetectorConfig.builder()
            .patterns(List.of("\\b(\\d{17}[0-9Xx])\\b"))
            .enableChecksum(true)
            .build();
        detector = new Re2jIdCardDetector(config);
    }

    @Test
    @DisplayName("检测身份证号")
    void detect_idCard() {
        String text = "id=11010519491231002X verified";
        List<DetectionResult> results = detect(text);
        assertFalse(results.isEmpty());
        assertEquals(SensitiveDataType.ID_CARD, results.get(0).dataType());
    }

    @Test
    @DisplayName("校验位不通过的身份证被过滤")
    void detect_invalidChecksum() {
        String text = "id=123456789012345678";
        List<DetectionResult> results = detect(text);
        assertTrue(results.isEmpty());
    }

    @Test
    @DisplayName("getSupportedType返回ID_CARD")
    void getSupportedType() {
        assertEquals(SensitiveDataType.ID_CARD, detector.getSupportedType());
    }

    private List<DetectionResult> detect(String text) {
        LogContext ctx = LogContext.builder().message(text).loggerName("test").threadName("main").build();
        return detector.detect(ctx);
    }
}