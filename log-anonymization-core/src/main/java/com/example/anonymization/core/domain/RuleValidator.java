package com.example.anonymization.core.domain;

import com.example.anonymization.api.enums.DetectorType;
import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.model.MaskingRule;
import com.example.anonymization.api.model.ValidationResult;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 规则校验器 —— 启动期与配置变更期对 {@link MaskingRule} 列表进行合法性校验。
 *
 * <p>使用场景：在 Spring 启动流程中由
 * {@link com.example.anonymization.starter.LogAnonymizationAutoConfiguration#threadSafeRuleManager}
 * 在加载完首批规则后调用 {@link #validateAll}，确保无语法错误/性能风险的规则上线。
 *
 * <p>校验维度：
 * <ol>
 *   <li>正则语法（re2j 编译测试）</li>
 *   <li>ReDoS 风险（嵌套量词检测）</li>
 *   <li>优先级合理性（{@code 0~1000}）</li>
 * </ol>
 *
 * @author log-anonymization
 */
public class RuleValidator {

    /** 检测器注册表（用于校验 DetectorType 对应的实现是否已注册） */
    private final DetectorRegistry detectorRegistry;
    /** 脱敏器注册表（用于校验 MaskerType 对应的实现是否已注册） */
    private final MaskerRegistry maskerRegistry;
    /** 是否快速失败（true = 校验不通过则抛 {@link RuleValidationException} 阻止启动） */
    private final boolean failFast;

    /**
     * 构造规则校验器。
     *
     * @param detectorRegistry 检测器注册表
     * @param maskerRegistry   脱敏器注册表
     * @param failFast         true 表示任一规则失败即抛异常
     */
    public RuleValidator(DetectorRegistry detectorRegistry, MaskerRegistry maskerRegistry, boolean failFast) {
        this.detectorRegistry = detectorRegistry;
        this.maskerRegistry = maskerRegistry;
        this.failFast = failFast;
    }

    /**
     * 校验单条规则。
     *
     * <p>校验项：
     * <ul>
     *   <li>REGEX 类型规则的每个 pattern 必须能通过 re2j 编译</li>
     *   <li>pattern 包含嵌套量词（如 {@code ".*.*"}）时发出 ReDoS 警告</li>
     *   <li>priority 不在 0~1000 时发出警告</li>
     * </ul>
     *
     * @param rule 待校验规则
     * @return 校验结果（valid=true 表示无错误）
     */
    public ValidationResult validate(MaskingRule rule) {
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        if (rule.getDetectorType() == DetectorType.REGEX) {
            for (String pattern : rule.getDetectorConfig().getPatterns()) {
                try {
                    com.google.re2j.Pattern.compile(pattern);
                } catch (com.google.re2j.PatternSyntaxException e) {
                    errors.add("Regex syntax error: " + pattern + " - " + e.getMessage());
                }
                if (hasNestedQuantifiers(pattern)) {
                    warnings.add("Regex contains nested quantifiers, potential ReDoS risk: " + pattern);
                }
            }
        }

        if (rule.getPriority() < 0 || rule.getPriority() > 1000) {
            warnings.add("Abnormal priority value: " + rule.getPriority());
        }

        return new ValidationResult(rule.getRuleId(), errors.isEmpty(), errors, warnings);
    }

    /**
     * 批量校验所有规则。
     *
     * <p>当 {@code failFast=true} 且任一规则未通过时抛出 {@link RuleValidationException}，
     * 阻止应用启动，避免"错误规则生效导致敏感数据未脱敏"的合规事故。
     *
     * @param rules 规则列表
     * @return 所有规则的校验结果列表
     * @throws RuleValidationException 当 failFast=true 且存在不合法规则时抛出
     */
    public List<ValidationResult> validateAll(List<MaskingRule> rules) {
        List<ValidationResult> results = rules.stream()
            .map(this::validate)
            .collect(Collectors.toList());

        if (failFast && results.stream().anyMatch(r -> !r.isValid())) {
            throw new RuleValidationException("Rule validation failed, refusing to start", results);
        }

        return results;
    }

    /**
     * 检测正则是否含嵌套量词（ReDoS 高风险）。
     *
     * <p>嵌套量词指相邻两个量词直接相连（如 {@code .*.*}、{@code .+.+} 等），
     * 会导致回溯复杂度爆炸（例如 {@code "a" * 30 + "!"} 类的输入）。
     *
     * @param pattern 正则字符串
     * @return true 表示存在嵌套量词
     */
    private boolean hasNestedQuantifiers(String pattern) {
        return pattern.contains(".*.*") || pattern.contains(".+.+")
            || pattern.contains(".*.+") || pattern.contains(".+.*");
    }

    /**
     * 规则校验异常 —— failFast=true 时抛出，阻止应用启动。
     *
     * <p>通过 {@link #getResults} 可拿到每条规则的详细校验结果，
     * 用于运维定位失败规则。
     */
    public static class RuleValidationException extends RuntimeException {
        /** 所有规则的校验结果 */
        private final List<ValidationResult> results;

        /**
         * 构造异常。
         *
         * @param message 异常消息
         * @param results 校验结果列表
         */
        public RuleValidationException(String message, List<ValidationResult> results) {
            super(message);
            this.results = results;
        }

        /**
         * 获取所有规则的校验结果。
         *
         * @return 校验结果列表
         */
        public List<ValidationResult> getResults() { return results; }
    }
}