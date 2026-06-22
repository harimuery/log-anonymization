package com.example.anonymization.test;

import com.example.anonymization.api.model.MaskingResult;

import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

public final class AnonymizationAssertions {

    private AnonymizationAssertions() {}

    public static StringAssert assertThat(String actual) {
        return new StringAssert(actual);
    }

    public static MaskingResultAssert assertThat(MaskingResult actual) {
        return MaskingResultAssert.assertThat(actual);
    }

    public static final class StringAssert {

        private String original;
        private String masked;
        private long processingTimeNanos;
        private boolean afterMaskingCalled;

        StringAssert(String actual) {
            this.original = actual;
        }

        public StringAssert afterMaskingWith(com.example.anonymization.api.port.MaskingPort maskingPort,
                                               com.example.anonymization.api.model.LogContext context) {
            Objects.requireNonNull(maskingPort, "maskingPort must not be null");
            Objects.requireNonNull(context, "context must not be null");
            long start = System.nanoTime();
            MaskingResult result = maskingPort.process(original, context);
            this.processingTimeNanos = System.nanoTime() - start;
            this.masked = result.getMasked();
            this.afterMaskingCalled = true;
            return this;
        }

        public StringAssert afterMaskingWith(com.example.anonymization.api.port.MaskingPort maskingPort) {
            com.example.anonymization.api.model.LogContext ctx =
                com.example.anonymization.api.model.LogContext.builder()
                    .message(original)
                    .loggerName("TestLogger")
                    .threadName("main")
                    .build();
            return afterMaskingWith(maskingPort, ctx);
        }

        public StringAssert doesNotContain(String substring) {
            String target = afterMaskingCalled ? masked : original;
            if (target != null && target.contains(substring)) {
                throw new AssertionError(
                    "Expected masked string NOT to contain <" + substring + "> but it did");
            }
            return this;
        }

        public StringAssert contains(String substring) {
            String target = afterMaskingCalled ? masked : original;
            if (target == null || !target.contains(substring)) {
                throw new AssertionError(
                    "Expected masked string to contain <" + substring + "> but was <" + target + ">");
            }
            return this;
        }

        public StringAssert matchesRegex(String regex) {
            String target = afterMaskingCalled ? masked : original;
            if (target == null || !Pattern.compile(regex).matcher(target).find()) {
                throw new AssertionError(
                    "Expected masked string to match regex <" + regex + "> but was <" + target + ">");
            }
            return this;
        }

        public StringAssert doesNotMatchRegex(String regex) {
            String target = afterMaskingCalled ? masked : original;
            if (target != null && Pattern.compile(regex).matcher(target).find()) {
                throw new AssertionError(
                    "Expected masked string NOT to match regex <" + regex + "> but it did: <" + target + ">");
            }
            return this;
        }

        public StringAssert processingTimeLessThan(long timeout, TimeUnit unit) {
            if (!afterMaskingCalled) {
                throw new IllegalStateException("processingTimeLessThan requires afterMaskingWith() to be called first");
            }
            long thresholdNanos = unit.toNanos(timeout);
            if (processingTimeNanos > thresholdNanos) {
                throw new AssertionError(
                    "Expected processing time < " + timeout + " " + unit.name().toLowerCase() +
                    " but was " + TimeUnit.NANOSECONDS.toMicros(processingTimeNanos) + " microseconds");
            }
            return this;
        }

        public StringAssert isMasked() {
            if (!afterMaskingCalled) {
                throw new IllegalStateException("isMasked requires afterMaskingWith() to be called first");
            }
            if (Objects.equals(original, masked)) {
                throw new AssertionError("Expected string to be masked but it was unchanged");
            }
            return this;
        }

        public StringAssert isUnchanged() {
            if (!afterMaskingCalled) {
                throw new IllegalStateException("isUnchanged requires afterMaskingWith() to be called first");
            }
            if (!Objects.equals(original, masked)) {
                throw new AssertionError("Expected string to be unchanged but it was masked");
            }
            return this;
        }

        public String getMasked() {
            return masked;
        }
    }
}