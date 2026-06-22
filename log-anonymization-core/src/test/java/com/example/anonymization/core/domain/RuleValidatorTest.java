package com.example.anonymization.core.domain;

import com.example.anonymization.api.enums.DetectorType;
import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.model.DetectorConfig;
import com.example.anonymization.api.model.MaskerConfig;
import com.example.anonymization.api.model.MaskingRule;
import com.example.anonymization.api.model.MaskingScope;
import com.example.anonymization.api.model.ValidationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RuleValidatorTest {

    private RuleValidator validator;

    @BeforeEach
    void setUp() {
        DetectorRegistry detectorRegistry = new DetectorRegistry(List.of());
        MaskerRegistry maskerRegistry = new MaskerRegistry(List.of());
        validator = new RuleValidator(detectorRegistry, maskerRegistry, false);
    }

    @Nested
    @DisplayName("正则语法校验")
    class RegexValidation {

        @Test
        @DisplayName("合法正则通过校验")
        void validRegex() {
            MaskingRule rule = createRegexRule("\\b\\d{16,19}\\b");
            ValidationResult result = validator.validate(rule);
            assertTrue(result.isValid());
            assertTrue(result.getErrors().isEmpty());
        }

        @Test
        @DisplayName("非法正则报告错误")
        void invalidRegex() {
            MaskingRule rule = createRegexRule("[invalid((((");
            ValidationResult result = validator.validate(rule);
            assertFalse(result.isValid());
            assertFalse(result.getErrors().isEmpty());
        }

        @Test
        @DisplayName("嵌套量词产生ReDoS警告")
        void nestedQuantifiers_warning() {
            MaskingRule rule = createRegexRule(".*.*\\d+");
            ValidationResult result = validator.validate(rule);
            assertTrue(result.isValid());
            assertFalse(result.getWarnings().isEmpty());
            assertTrue(result.getWarnings().stream()
                .anyMatch(w -> w.contains("ReDoS")));
        }
    }

    @Nested
    @DisplayName("优先级校验")
    class PriorityValidation {

        @Test
        @DisplayName("正常优先级无警告")
        void normalPriority() {
            MaskingRule rule = createRegexRule("\\b\\d+\\b");
            ValidationResult result = validator.validate(rule);
            assertTrue(result.getWarnings().stream()
                .noneMatch(w -> w.contains("priority")));
        }

        @Test
        @DisplayName("优先级<0产生警告")
        void negativePriority() {
            MaskingRule rule = createRegexRule("\\b\\d+\\b");
            rule = MaskingRule.builder()
                .ruleId("TEST-001").name("test").dataType(SensitiveDataType.BANK_CARD)
                .detector(DetectorType.REGEX, DetectorConfig.builder().patterns(List.of("\\b\\d+\\b")).build())
                .masker(MaskerType.PARTIAL_MASK, MaskerConfig.builder().dataType(SensitiveDataType.BANK_CARD).build())
                .scope(MaskingScope.global()).priority(-1).enabled(true).build();
            ValidationResult result = validator.validate(rule);
            assertTrue(result.getWarnings().stream()
                .anyMatch(w -> w.contains("priority")));
        }

        @Test
        @DisplayName("优先级>1000产生警告")
        void excessivePriority() {
            MaskingRule rule = MaskingRule.builder()
                .ruleId("TEST-001").name("test").dataType(SensitiveDataType.BANK_CARD)
                .detector(DetectorType.REGEX, DetectorConfig.builder().patterns(List.of("\\b\\d+\\b")).build())
                .masker(MaskerType.PARTIAL_MASK, MaskerConfig.builder().dataType(SensitiveDataType.BANK_CARD).build())
                .scope(MaskingScope.global()).priority(1001).enabled(true).build();
            ValidationResult result = validator.validate(rule);
            assertTrue(result.getWarnings().stream()
                .anyMatch(w -> w.contains("priority")));
        }
    }

    @Nested
    @DisplayName("批量校验与failFast")
    class ValidateAll {

        @Test
        @DisplayName("failFast=false时不抛异常")
        void validateAll_noFailFast() {
            RuleValidator nonFailFast = new RuleValidator(
                new DetectorRegistry(List.of()), new MaskerRegistry(List.of()), false);
            MaskingRule badRule = createRegexRule("[invalid(((");
            List<ValidationResult> results = nonFailFast.validateAll(List.of(badRule));
            assertEquals(1, results.size());
            assertFalse(results.get(0).isValid());
        }

        @Test
        @DisplayName("failFast=true时抛异常")
        void validateAll_failFast() {
            RuleValidator failFastValidator = new RuleValidator(
                new DetectorRegistry(List.of()), new MaskerRegistry(List.of()), true);
            MaskingRule badRule = createRegexRule("[invalid(((");
            assertThrows(RuleValidator.RuleValidationException.class,
                () -> failFastValidator.validateAll(List.of(badRule)));
        }
    }

    private MaskingRule createRegexRule(String pattern) {
        return MaskingRule.builder()
            .ruleId("TEST-REGEX-001")
            .name("Test Regex Rule")
            .dataType(SensitiveDataType.BANK_CARD)
            .detector(DetectorType.REGEX, DetectorConfig.builder()
                .patterns(List.of(pattern)).build())
            .masker(MaskerType.PARTIAL_MASK, MaskerConfig.builder()
                .keepPrefixLen(4).keepSuffixLen(4).maskChar('*')
                .dataType(SensitiveDataType.BANK_CARD).build())
            .scope(MaskingScope.global())
            .priority(100)
            .enabled(true)
            .build();
    }
}