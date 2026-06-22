package com.example.anonymization.api.model;

import java.util.Collections;
import java.util.List;

/**
 * 规则校验结果 —— {@link com.example.anonymization.core.domain.RuleValidator}
 * 对单条规则校验后的输出。
 *
 * <p>使用场景：启动期校验所有规则，决定是否 fail-fast 抛异常阻止启动；
 * 也可在管理控制台展示校验报告。
 *
 * @author log-anonymization
 */
public final class ValidationResult {

    /** 被校验规则的 ID（可能为 null，对应未指定 ruleId 的批量校验场景） */
    private final String ruleId;
    /** 是否通过校验（true = 无错误） */
    private final boolean valid;
    /** 错误信息列表（语法错误、配置缺失等） */
    private final List<String> errors;
    /** 警告信息列表（潜在风险，如 ReDoS 嵌套量词） */
    private final List<String> warnings;

    /**
     * 创建校验结果。
     *
     * @param ruleId   规则 ID
     * @param valid    是否通过
     * @param errors   错误列表（可为 null，自动转为空列表）
     * @param warnings 警告列表（可为 null，自动转为空列表）
     */
    public ValidationResult(String ruleId, boolean valid,
                            List<String> errors, List<String> warnings) {
        this.ruleId = ruleId;
        this.valid = valid;
        this.errors = errors != null ? Collections.unmodifiableList(errors) : Collections.emptyList();
        this.warnings = warnings != null ? Collections.unmodifiableList(warnings) : Collections.emptyList();
    }

    /**
     * 获取规则 ID。
     *
     * @return 规则 ID
     */
    public String getRuleId() { return ruleId; }

    /**
     * 是否通过校验。
     *
     * @return true 表示无错误
     */
    public boolean isValid() { return valid; }

    /**
     * 获取错误信息列表。
     *
     * @return 不可变错误列表
     */
    public List<String> getErrors() { return errors; }

    /**
     * 获取警告信息列表。
     *
     * @return 不可变警告列表
     */
    public List<String> getWarnings() { return warnings; }

    /**
     * 是否存在警告（用于 UI 高亮提示）。
     *
     * @return true 表示存在警告
     */
    public boolean hasWarnings() { return !warnings.isEmpty(); }
}