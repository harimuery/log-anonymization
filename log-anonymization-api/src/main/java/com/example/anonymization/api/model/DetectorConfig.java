package com.example.anonymization.api.model;

import com.example.anonymization.api.enums.DetectorType;
import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.enums.SensitiveDataType;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * 检测器配置 —— 描述一个敏感数据检测器的具体参数（正则、关键词、字段名、是否启用二次校验等）。
 *
 * <p>使用场景：作为 {@link MaskingRule} 的子对象，由 core 模块中具体的
 * {@link com.example.anonymization.api.spi.SensitiveDataDetector} 实现读取并完成识别逻辑。
 *
 * <p>不可变：通过 Builder 构建，所有 List 字段在构造时封装为
 * {@link Collections#unmodifiableList}，避免外部篡改影响规则执行。
 *
 * @author log-anonymization
 */
public final class DetectorConfig {

    /** 正则模式列表（仅 {@link DetectorType#REGEX} 生效，传入 re2j 编译） */
    private final List<String> patterns;
    /** 关键词列表（用于 {@link DetectorType#KEYWORD} 或 BloomFilter 预筛） */
    private final List<String> keywords;
    /** 字段名列表（用于 {@link DetectorType#FIELD_NAME}，如 password/pan/cvv） */
    private final List<String> fieldNames;
    /** 上下文模式（如 {@code "cardNo=\\w+"})，用于识别带前缀的 KV 片段 */
    private final String contextPattern;
    /** 是否启用 Luhn 校验（银行卡号二次确认，避免误杀长数字串） */
    private final boolean enableLuhnCheck;
    /** 是否启用校验位算法（如身份证 18 位校验位） */
    private final boolean enableChecksum;

    /**
     * 私有构造器 —— 由 {@link Builder} 触发，确保不可变性。
     *
     * @param builder 构建器实例
     */
    private DetectorConfig(Builder builder) {
        this.patterns = builder.patterns != null
            ? Collections.unmodifiableList(builder.patterns) : Collections.emptyList();
        this.keywords = builder.keywords != null
            ? Collections.unmodifiableList(builder.keywords) : Collections.emptyList();
        this.fieldNames = builder.fieldNames != null
            ? Collections.unmodifiableList(builder.fieldNames) : Collections.emptyList();
        this.contextPattern = builder.contextPattern;
        this.enableLuhnCheck = builder.enableLuhnCheck;
        this.enableChecksum = builder.enableChecksum;
    }

    /**
     * 获取正则模式列表。
     *
     * @return 不可变列表，无配置时返回空列表
     */
    public List<String> getPatterns() { return patterns; }

    /**
     * 获取关键词列表。
     *
     * @return 不可变列表，无配置时返回空列表
     */
    public List<String> getKeywords() { return keywords; }

    /**
     * 获取字段名列表。
     *
     * @return 不可变列表，无配置时返回空列表
     */
    public List<String> getFieldNames() { return fieldNames; }

    /**
     * 获取上下文模式。
     *
     * @return 上下文模式字符串，可能为 null
     */
    public String getContextPattern() { return contextPattern; }

    /**
     * 是否启用 Luhn 校验。
     *
     * @return true 表示启用 Luhn 二次校验（银行卡场景推荐开启）
     */
    public boolean isEnableLuhnCheck() { return enableLuhnCheck; }

    /**
     * 是否启用校验位算法。
     *
     * @return true 表示启用（如身份证 18 位校验位）
     */
    public boolean isEnableChecksum() { return enableChecksum; }

    /**
     * 获取 Builder 入口。
     *
     * @return 新的 {@link Builder} 实例
     */
    public static Builder builder() { return new Builder(); }

    /**
     * {@link DetectorConfig} 的流式构建器。
     *
     * <p>使用示例：
     * <pre>{@code
     * DetectorConfig config = DetectorConfig.builder()
     *     .patterns(List.of("\\b\\d{16,19}\\b"))
     *     .enableLuhnCheck(true)
     *     .build();
     * }</pre>
     */
    public static class Builder {
        private List<String> patterns;
        private List<String> keywords;
        private List<String> fieldNames;
        private String contextPattern;
        private boolean enableLuhnCheck;
        private boolean enableChecksum;

        /**
         * 设置正则模式列表。
         *
         * @param patterns 模式列表
         * @return 当前 Builder
         */
        public Builder patterns(List<String> patterns) { this.patterns = patterns; return this; }

        /**
         * 设置关键词列表。
         *
         * @param keywords 关键词列表
         * @return 当前 Builder
         */
        public Builder keywords(List<String> keywords) { this.keywords = keywords; return this; }

        /**
         * 设置字段名列表。
         *
         * @param fieldNames 字段名列表
         * @return 当前 Builder
         */
        public Builder fieldNames(List<String> fieldNames) { this.fieldNames = fieldNames; return this; }

        /**
         * 设置上下文模式。
         *
         * @param contextPattern 上下文模式字符串
         * @return 当前 Builder
         */
        public Builder contextPattern(String contextPattern) { this.contextPattern = contextPattern; return this; }

        /**
         * 设置是否启用 Luhn 校验。
         *
         * @param enable true 启用
         * @return 当前 Builder
         */
        public Builder enableLuhnCheck(boolean enable) { this.enableLuhnCheck = enable; return this; }

        /**
         * 设置是否启用校验位算法。
         *
         * @param enable true 启用
         * @return 当前 Builder
         */
        public Builder enableChecksum(boolean enable) { this.enableChecksum = enable; return this; }

        /**
         * 构建不可变的 {@link DetectorConfig}。
         *
         * @return 配置实例
         */
        public DetectorConfig build() { return new DetectorConfig(this); }
    }
}