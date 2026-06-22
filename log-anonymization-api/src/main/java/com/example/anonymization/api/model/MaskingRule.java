package com.example.anonymization.api.model;

import com.example.anonymization.api.enums.DetectorType;
import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.enums.SensitiveDataType;

import java.util.Objects;

/**
 * 脱敏规则 —— 关联检测器（识别什么）与脱敏器（怎么处理）的最小业务单元。
 *
 * <p>使用场景：从配置文件（YAML/Properties）、配置中心（Nacos/Apollo）加载后，
 * 注入到 {@link com.example.anonymization.core.domain.ThreadSafeRuleManager}，
 * 在检测阶段被 {@link com.example.anonymization.core.domain.service.DefaultRuleMatchService}
 * 按 scope + priority 匹配并执行。
 *
 * <p>不可变：通过 Builder 构建，所有非空字段在构造时通过 {@link Objects#requireNonNull} 校验。
 *
 * @author log-anonymization
 */
public final class MaskingRule {

    private final String ruleId;
    private final String name;
    private final SensitiveDataType dataType;
    private final DetectorType detectorType;
    private final MaskerType maskerType;
    private final DetectorConfig detectorConfig;
    private final MaskerConfig maskerConfig;
    private final MaskingScope scope;
    private final int priority;
    private final boolean enabled;
    private final int version;

    /**
     * 私有构造器 —— 由 {@link Builder} 触发，对关键字段执行非空校验。
     *
     * @param builder 构建器
     * @throws NullPointerException 当 ruleId/name/dataType/detectorType/maskerType/config 任一为 null 时抛出
     */
    private MaskingRule(Builder builder) {
        this.ruleId = Objects.requireNonNull(builder.ruleId, "ruleId must not be null");
        this.name = Objects.requireNonNull(builder.name, "name must not be null");
        this.dataType = Objects.requireNonNull(builder.dataType, "dataType must not be null");
        this.detectorType = Objects.requireNonNull(builder.detectorType, "detectorType must not be null");
        this.maskerType = Objects.requireNonNull(builder.maskerType, "maskerType must not be null");
        this.detectorConfig = Objects.requireNonNull(builder.detectorConfig, "detectorConfig must not be null");
        this.maskerConfig = Objects.requireNonNull(builder.maskerConfig, "maskerConfig must not be null");
        this.scope = builder.scope != null ? builder.scope : MaskingScope.global();
        this.priority = builder.priority;
        this.enabled = builder.enabled;
        this.version = builder.version;
    }

    /**
     * 判断当前规则是否适用于给定的日志上下文。
     *
     * <p>判定条件：规则启用（{@code enabled=true}）<b>且</b> {@link MaskingScope#matches(LogContext)} 通过。
     *
     * @param context 日志上下文
     * @return true 表示规则适用
     */
    public boolean appliesTo(LogContext context) {
        return enabled && scope.matches(context);
    }

    /**
     * 按 priority 倒序比较（数值大的在前）。
     *
     * <p>用于 {@link com.example.anonymization.core.domain.ThreadSafeRuleManager#refreshRules}
     * 对规则列表排序，优先级高的规则先被匹配。
     *
     * @param other 另一条规则
     * @return {@code Integer.compare(other.priority, this.priority)}
     */
    public int comparePriority(MaskingRule other) {
        return Integer.compare(other.priority, this.priority);
    }

    /**
     * 获取规则 ID。
     *
     * @return 唯一规则标识
     */
    public String getRuleId() { return ruleId; }

    /**
     * 获取规则名称（可读，用于审计报表）。
     *
     * @return 规则名称
     */
    public String getName() { return name; }

    /**
     * 获取敏感数据类型。
     *
     * @return 数据类型
     */
    public SensitiveDataType getDataType() { return dataType; }

    /**
     * 获取检测器类型。
     *
     * @return 检测器类型
     */
    public DetectorType getDetectorType() { return detectorType; }

    /**
     * 获取脱敏器类型。
     *
     * @return 脱敏器类型
     */
    public MaskerType getMaskerType() { return maskerType; }

    /**
     * 获取检测器配置。
     *
     * @return 检测器配置
     */
    public DetectorConfig getDetectorConfig() { return detectorConfig; }

    /**
     * 获取脱敏器配置。
     *
     * @return 脱敏器配置
     */
    public MaskerConfig getMaskerConfig() { return maskerConfig; }

    /**
     * 获取规则作用域（默认全局）。
     *
     * @return 作用域
     */
    public MaskingScope getScope() { return scope; }

    /**
     * 获取优先级。
     *
     * @return 优先级数值，越大越优先
     */
    public int getPriority() { return priority; }

    /**
     * 是否启用。
     *
     * @return true 表示启用
     */
    public boolean isEnabled() { return enabled; }

    /**
     * 获取规则版本号（用于灰度/回滚）。
     *
     * @return 版本号
     */
    public int getVersion() { return version; }

    /**
     * 获取 Builder 入口。
     *
     * @return 新的 {@link Builder} 实例
     */
    public static Builder builder() { return new Builder(); }

    /**
     * {@link MaskingRule} 的流式构建器。
     */
    public static class Builder {
        private String ruleId;
        private String name;
        private SensitiveDataType dataType;
        private DetectorType detectorType;
        private MaskerType maskerType;
        private DetectorConfig detectorConfig;
        private MaskerConfig maskerConfig;
        private MaskingScope scope;
        private int priority = 0;
        private boolean enabled = true;
        private int version = 1;

        /**
         * 设置规则 ID（必填）。
         *
         * @param ruleId 规则 ID
         * @return 当前 Builder
         */
        public Builder ruleId(String ruleId) { this.ruleId = ruleId; return this; }

        /**
         * 设置规则名称（必填）。
         *
         * @param name 规则名称
         * @return 当前 Builder
         */
        public Builder name(String name) { this.name = name; return this; }

        /**
         * 设置敏感数据类型（必填）。
         *
         * @param dataType 数据类型
         * @return 当前 Builder
         */
        public Builder dataType(SensitiveDataType dataType) { this.dataType = dataType; return this; }

        /**
         * 同时设置检测器类型与配置。
         *
         * @param type   检测器类型
         * @param config 检测器配置
         * @return 当前 Builder
         */
        public Builder detector(DetectorType type, DetectorConfig config) {
            this.detectorType = type;
            this.detectorConfig = config;
            return this;
        }

        /**
         * 同时设置脱敏器类型与配置。
         *
         * @param type   脱敏器类型
         * @param config 脱敏器配置
         * @return 当前 Builder
         */
        public Builder masker(MaskerType type, MaskerConfig config) {
            this.maskerType = type;
            this.maskerConfig = config;
            return this;
        }

        /**
         * 设置规则作用域（默认全局）。
         *
         * @param scope 作用域
         * @return 当前 Builder
         */
        public Builder scope(MaskingScope scope) { this.scope = scope; return this; }

        /**
         * 设置优先级。
         *
         * @param priority 优先级
         * @return 当前 Builder
         */
        public Builder priority(int priority) { this.priority = priority; return this; }

        /**
         * 设置是否启用。
         *
         * @param enabled 是否启用
         * @return 当前 Builder
         */
        public Builder enabled(boolean enabled) { this.enabled = enabled; return this; }

        /**
         * 设置规则版本号。
         *
         * @param version 版本号
         * @return 当前 Builder
         */
        public Builder version(int version) { this.version = version; return this; }

        /**
         * 构建不可变的 {@link MaskingRule}。
         *
         * @return 规则实例
         * @throws NullPointerException 当必填字段缺失时由构造器抛出
         */
        public MaskingRule build() { return new MaskingRule(this); }
    }
}