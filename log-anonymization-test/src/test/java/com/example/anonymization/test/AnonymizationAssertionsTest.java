package com.example.anonymization.test;

import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.model.MaskerConfig;
import com.example.anonymization.api.model.MaskingResult;
import com.example.anonymization.api.port.MaskingPort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class AnonymizationAssertionsTest {

    @Nested
    @DisplayName("StringAssert")
    class StringAssertTest {

        private final MaskingPort mockPort = (message, context) ->
            MaskingResult.masked(message, message.replaceAll("\\d{16,19}", "****CARD****"));

        @Test
        @DisplayName("afterMaskingWith执行脱敏并记录耗时")
        void afterMaskingWith() {
            AnonymizationAssertions.assertThat("card=6222021234567890")
                .afterMaskingWith(mockPort)
                .isMasked();
        }

        @Test
        @DisplayName("doesNotContain断言脱敏后不含指定子串")
        void doesNotContain() {
            AnonymizationAssertions.assertThat("card=6222021234567890")
                .afterMaskingWith(mockPort)
                .doesNotContain("6222021234567890");
        }

        @Test
        @DisplayName("doesNotContain断言失败时抛AssertionError")
        void doesNotContain_fails() {
            assertThrows(AssertionError.class, () ->
                AnonymizationAssertions.assertThat("card=6222021234567890")
                    .afterMaskingWith(mockPort)
                    .doesNotContain("****CARD****"));
        }

        @Test
        @DisplayName("contains断言脱敏后包含指定子串")
        void contains() {
            AnonymizationAssertions.assertThat("card=6222021234567890")
                .afterMaskingWith(mockPort)
                .contains("****CARD****");
        }

        @Test
        @DisplayName("matchesRegex断言脱敏后匹配正则")
        void matchesRegex() {
            AnonymizationAssertions.assertThat("card=6222021234567890")
                .afterMaskingWith(mockPort)
                .matchesRegex("\\*+CARD\\*+");
        }

        @Test
        @DisplayName("doesNotMatchRegex断言脱敏后不匹配正则")
        void doesNotMatchRegex() {
            AnonymizationAssertions.assertThat("card=6222021234567890")
                .afterMaskingWith(mockPort)
                .doesNotMatchRegex("\\d{16}");
        }

        @Test
        @DisplayName("processingTimeLessThan断言处理耗时在阈值内")
        void processingTimeLessThan() {
            AnonymizationAssertions.assertThat("normal message")
                .afterMaskingWith(mockPort)
                .processingTimeLessThan(10, TimeUnit.SECONDS);
        }

        @Test
        @DisplayName("isUnchanged断言脱敏后字符串不变")
        void isUnchanged() {
            MaskingPort noChangePort = (message, context) -> MaskingResult.unchanged(message);
            AnonymizationAssertions.assertThat("normal message")
                .afterMaskingWith(noChangePort)
                .isUnchanged();
        }

        @Test
        @DisplayName("未调用afterMaskingWith时isMasked抛IllegalStateException")
        void isMasked_withoutAfterMasking() {
            assertThrows(IllegalStateException.class, () ->
                AnonymizationAssertions.assertThat("test").isMasked());
        }

        @Test
        @DisplayName("未调用afterMaskingWith时processingTimeLessThan抛IllegalStateException")
        void processingTimeLessThan_withoutAfterMasking() {
            assertThrows(IllegalStateException.class, () ->
                AnonymizationAssertions.assertThat("test").processingTimeLessThan(1, TimeUnit.SECONDS));
        }
    }

    @Nested
    @DisplayName("MaskingResultAssert")
    class MaskingResultAssertTest {

        @Test
        @DisplayName("isMasked断言脱敏结果已变更")
        void isMasked() {
            AnonymizationAssertions.assertThat(MaskingResult.masked("original", "masked"))
                .isMasked();
        }

        @Test
        @DisplayName("isMasked断言失败时抛AssertionError")
        void isMasked_fails() {
            assertThrows(AssertionError.class, () ->
                AnonymizationAssertions.assertThat(MaskingResult.unchanged("original")).isMasked());
        }

        @Test
        @DisplayName("isUnchanged断言脱敏结果未变更")
        void isUnchanged() {
            AnonymizationAssertions.assertThat(MaskingResult.unchanged("original"))
                .isUnchanged();
        }

        @Test
        @DisplayName("isDegraded断言降级结果")
        void isDegraded() {
            AnonymizationAssertions.assertThat(MaskingResult.degraded("original", "***DEGRADED***"))
                .isDegraded();
        }

        @Test
        @DisplayName("hasMaskedValue断言脱敏值精确匹配")
        void hasMaskedValue() {
            AnonymizationAssertions.assertThat(MaskingResult.masked("original", "masked"))
                .hasMaskedValue("masked");
        }

        @Test
        @DisplayName("containsMaskedValue断言脱敏值包含子串")
        void containsMaskedValue() {
            AnonymizationAssertions.assertThat(MaskingResult.masked("original", "6222************7890"))
                .containsMaskedValue("****");
        }

        @Test
        @DisplayName("doesNotContainMaskedValue断言脱敏值不包含子串")
        void doesNotContainMaskedValue() {
            AnonymizationAssertions.assertThat(MaskingResult.masked("original", "6222************7890"))
                .doesNotContainMaskedValue("6222021234567890");
        }
    }
}