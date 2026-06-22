package com.example.anonymization.test;

import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.model.DetectionResult;
import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.model.MaskingResult;
import com.example.anonymization.api.port.MaskingPort;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.regex.Pattern;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

public final class AnonymizationTestExtension implements BeforeEachCallback, AfterEachCallback {

    private static final String MASKING_PORT_KEY = "MASKING_PORT";
    private static final String VIOLATIONS_KEY = "VIOLATIONS";

    private final MaskingPort maskingPort;
    private final List<Pattern> sensitivePatterns;
    private final boolean failOnViolation;

    public AnonymizationTestExtension(MaskingPort maskingPort) {
        this(maskingPort, true);
    }

    public AnonymizationTestExtension(MaskingPort maskingPort, boolean failOnViolation) {
        this.maskingPort = maskingPort;
        this.sensitivePatterns = buildDefaultSensitivePatterns();
        this.failOnViolation = failOnViolation;
    }

    @Override
    public void beforeEach(ExtensionContext context) {
        ConcurrentLinkedQueue<String> violations = new ConcurrentLinkedQueue<>();
        context.getStore(ExtensionContext.Namespace.GLOBAL)
            .put(VIOLATIONS_KEY, violations);
        context.getStore(ExtensionContext.Namespace.GLOBAL)
            .put(MASKING_PORT_KEY, maskingPort);
    }

    @Override
    public void afterEach(ExtensionContext context) {
        @SuppressWarnings("unchecked")
        ConcurrentLinkedQueue<String> violations =
            (ConcurrentLinkedQueue<String>) context.getStore(ExtensionContext.Namespace.GLOBAL)
                .get(VIOLATIONS_KEY);

        if (violations != null && !violations.isEmpty() && failOnViolation) {
            StringBuilder msg = new StringBuilder("Log anonymization violations detected:\n");
            violations.forEach(v -> msg.append("  - ").append(v).append("\n"));
            throw new AssertionError(msg.toString());
        }
    }

    public MaskingPort getMaskingPort() {
        return maskingPort;
    }

    public String mask(String message, LogContext context) {
        MaskingResult result = maskingPort.process(message, context);
        return result.getMasked();
    }

    public String mask(String message) {
        LogContext ctx = LogContext.builder()
            .message(message)
            .loggerName("AnonymizationTestExtension")
            .threadName(Thread.currentThread().getName())
            .build();
        return mask(message, ctx);
    }

    public void assertNoSensitiveData(String output) {
        if (output == null || output.isEmpty()) return;
        for (Pattern pattern : sensitivePatterns) {
            if (pattern.matcher(output).find()) {
                throw new AssertionError(
                    "Output contains potential sensitive data matching pattern <"
                    + pattern.pattern() + ">: <" + output + ">");
            }
        }
    }

    public void assertMasked(String output, String originalSensitiveValue) {
        if (output != null && output.contains(originalSensitiveValue)) {
            throw new AssertionError(
                "Output still contains unmasked sensitive value <" + originalSensitiveValue + ">");
        }
    }

    private static List<Pattern> buildDefaultSensitivePatterns() {
        List<Pattern> patterns = new ArrayList<>();
        patterns.add(Pattern.compile("\\b1[3-9]\\d{9}\\b"));
        patterns.add(Pattern.compile("\\b\\d{17}[0-9Xx]\\b"));
        patterns.add(Pattern.compile("\\b\\d{16,19}\\b"));
        patterns.add(Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"));
        return Collections.unmodifiableList(patterns);
    }
}