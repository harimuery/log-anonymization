package com.example.anonymization.test;

import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.model.MaskingResult;
import com.example.anonymization.api.port.MaskingPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AnonymizationTestExtensionTest {

    private AnonymizationTestExtension extension;

    @BeforeEach
    void setUp() {
        MaskingPort mockPort = (message, context) ->
            MaskingResult.masked(message, message.replaceAll("\\d{16,19}", "****CARD****"));
        extension = new AnonymizationTestExtension(mockPort);
    }

    @Test
    @DisplayName("mask方法返回脱敏后字符串")
    void mask() {
        String masked = extension.mask("card=6222021234567890");
        assertTrue(masked.contains("****CARD****"));
        assertFalse(masked.contains("6222021234567890"));
    }

    @Test
    @DisplayName("mask带LogContext参数返回脱敏后字符串")
    void mask_withContext() {
        LogContext ctx = LogContext.builder()
            .message("card=6222021234567890")
            .loggerName("test")
            .threadName("main")
            .build();
        String masked = extension.mask("card=6222021234567890", ctx);
        assertTrue(masked.contains("****CARD****"));
    }

    @Test
    @DisplayName("assertNoSensitiveData对无敏感数据字符串不抛异常")
    void assertNoSensitiveData_clean() {
        assertDoesNotThrow(() -> extension.assertNoSensitiveData("normal log message"));
    }

    @Test
    @DisplayName("assertNoSensitiveData对含手机号字符串抛AssertionError")
    void assertNoSensitiveData_phone() {
        assertThrows(AssertionError.class,
            () -> extension.assertNoSensitiveData("phone=13800138000"));
    }

    @Test
    @DisplayName("assertNoSensitiveData对含身份证号字符串抛AssertionError")
    void assertNoSensitiveData_idCard() {
        assertThrows(AssertionError.class,
            () -> extension.assertNoSensitiveData("id=11010519491231002X"));
    }

    @Test
    @DisplayName("assertNoSensitiveData对含邮箱字符串抛AssertionError")
    void assertNoSensitiveData_email() {
        assertThrows(AssertionError.class,
            () -> extension.assertNoSensitiveData("email=user@example.com"));
    }

    @Test
    @DisplayName("assertMasked对未脱敏值抛AssertionError")
    void assertMasked_unmasked() {
        assertThrows(AssertionError.class,
            () -> extension.assertMasked("card=6222021234567890", "6222021234567890"));
    }

    @Test
    @DisplayName("assertMasked对已脱敏值不抛异常")
    void assertMasked_masked() {
        assertDoesNotThrow(() -> extension.assertMasked("****CARD****", "6222021234567890"));
    }

    @Test
    @DisplayName("getMaskingPort返回非null")
    void getMaskingPort() {
        assertNotNull(extension.getMaskingPort());
    }

    @Test
    @DisplayName("assertNoSensitiveData对null和空字符串安全")
    void assertNoSensitiveData_nullAndEmpty() {
        assertDoesNotThrow(() -> extension.assertNoSensitiveData(null));
        assertDoesNotThrow(() -> extension.assertNoSensitiveData(""));
    }
}