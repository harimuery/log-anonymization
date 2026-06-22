package com.example.anonymization.core.infrastructure.exception;

import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.model.MaskingResult;
import com.example.anonymization.api.port.MaskingPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ExceptionSanitizerTest {

    private ExceptionSanitizer sanitizer;

    @BeforeEach
    void setUp() {
        MaskingPort mockEngine = (message, context) -> {
            String masked = message.replaceAll("\\d{16,19}", "****CARD****");
            masked = masked.replaceAll("1[3-9]\\d{9}", "****PHONE****");
            return MaskingResult.masked(message, masked);
        };
        sanitizer = new ExceptionSanitizer(mockEngine);
    }

    @Test
    @DisplayName("异常消息中的银行卡号被脱敏")
    void sanitize_bankCardInMessage() {
        Throwable t = new RuntimeException("Card 6222021234567890 processing failed");
        Throwable sanitized = sanitizer.sanitize(t);
        assertTrue(sanitized.getMessage().contains("****CARD****"));
        assertFalse(sanitized.getMessage().contains("6222021234567890"));
    }

    @Test
    @DisplayName("异常消息中的手机号被脱敏")
    void sanitize_phoneInMessage() {
        Throwable t = new RuntimeException("Call 13800138000 failed");
        Throwable sanitized = sanitizer.sanitize(t);
        assertTrue(sanitized.getMessage().contains("****PHONE****"));
        assertFalse(sanitized.getMessage().contains("13800138000"));
    }

    @Test
    @DisplayName("无敏感数据的异常消息不变")
    void sanitize_noSensitiveData() {
        Throwable t = new RuntimeException("Normal error message");
        Throwable sanitized = sanitizer.sanitize(t);
        assertEquals("Normal error message", sanitized.getMessage());
    }

    @Test
    @DisplayName("cause链中的敏感数据也被脱敏")
    void sanitize_causeChain() {
        Throwable cause = new RuntimeException("Card 6222021234567890 in cause");
        Throwable t = new RuntimeException("Top level", cause);
        Throwable sanitized = sanitizer.sanitize(t);
        assertTrue(sanitized.getCause().getMessage().contains("****CARD****"));
        assertFalse(sanitized.getCause().getMessage().contains("6222021234567890"));
    }

    @Test
    @DisplayName("null输入返回null")
    void sanitize_null() {
        assertNull(sanitizer.sanitize(null));
    }

    @Test
    @DisplayName("null消息的异常不抛NPE")
    void sanitize_nullMessage() {
        Throwable t = new RuntimeException((String) null);
        assertDoesNotThrow(() -> sanitizer.sanitize(t));
    }

    @Test
    @DisplayName("循环引用不导致栈溢出")
    void sanitize_circularReference() {
        RuntimeException a = new RuntimeException("A");
        RuntimeException b = new RuntimeException("B", a);
        a.initCause(b);
        assertDoesNotThrow(() -> sanitizer.sanitize(a));
    }

    @Test
    @DisplayName("suppressed异常也被脱敏")
    void sanitize_suppressed() {
        Throwable suppressed = new RuntimeException("Card 6222021234567890 suppressed");
        RuntimeException t = new RuntimeException("Main error");
        t.addSuppressed(suppressed);
        Throwable sanitized = sanitizer.sanitize(t);
        assertTrue(sanitized.getSuppressed().length > 0);
        assertTrue(sanitized.getSuppressed()[0].getMessage().contains("****CARD****"));
    }
}