package com.example.anonymization.core.infrastructure.detector;

import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.model.DetectionResult;
import com.example.anonymization.api.model.LogContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CompositeDetectorTest {

    private CompositeDetector compositeDetector;
    private StubDetector bankCardDetector;
    private StubDetector phoneDetector;

    @BeforeEach
    void setUp() {
        bankCardDetector = new StubDetector(SensitiveDataType.BANK_CARD, "STUB-BANK_CARD",
            List.of(new DetectionResult(5, 21, SensitiveDataType.BANK_CARD, 1.0, "6222021234567890")));
        phoneDetector = new StubDetector(SensitiveDataType.PHONE, "STUB-PHONE",
            List.of(new DetectionResult(26, 37, SensitiveDataType.PHONE, 1.0, "13800138000")));
        compositeDetector = new CompositeDetector(List.of(bankCardDetector, phoneDetector));
    }

    @Test
    @DisplayName("聚合所有检测器结果")
    void detect_aggregatesAll() {
        LogContext ctx = LogContext.builder()
            .message("card=6222021234567890 phone=13800138000")
            .loggerName("test").threadName("main").build();
        List<DetectionResult> results = compositeDetector.detect(ctx);
        assertEquals(2, results.size());
    }

    @Test
    @DisplayName("无命中返回空列表")
    void detect_noHits() {
        StubDetector emptyDetector = new StubDetector(SensitiveDataType.BANK_CARD, "EMPTY", List.of());
        CompositeDetector single = new CompositeDetector(List.of(emptyDetector));
        LogContext ctx = LogContext.builder()
            .message("no sensitive data").loggerName("test").threadName("main").build();
        assertTrue(single.detect(ctx).isEmpty());
    }

    @Test
    @DisplayName("空检测器列表安全返回")
    void detect_emptyDetectors() {
        CompositeDetector empty = new CompositeDetector(List.of());
        LogContext ctx = LogContext.builder()
            .message("test").loggerName("test").threadName("main").build();
        assertTrue(empty.detect(ctx).isEmpty());
    }

    @Test
    @DisplayName("getDetectorName返回COMPOSITE")
    void getDetectorName() {
        assertEquals("COMPOSITE", compositeDetector.getDetectorName());
    }

    private static class StubDetector implements com.example.anonymization.api.spi.SensitiveDataDetector {
        private final SensitiveDataType type;
        private final String name;
        private final List<DetectionResult> results;

        StubDetector(SensitiveDataType type, String name, List<DetectionResult> results) {
            this.type = type;
            this.name = name;
            this.results = results;
        }

        @Override
        public List<DetectionResult> detect(LogContext context) { return results; }

        @Override
        public SensitiveDataType getSupportedType() { return type; }

        @Override
        public String getDetectorName() { return name; }
    }
}