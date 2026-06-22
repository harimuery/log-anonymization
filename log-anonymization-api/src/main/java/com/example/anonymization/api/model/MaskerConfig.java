package com.example.anonymization.api.model;

import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.enums.SensitiveDataType;

import java.util.Collections;
import java.util.List;

/**
 * 脱敏器配置 —— 描述一个脱敏算法的具体参数（保留前后位数、掩码字符、哈希算法、盐、IP 段保留数等）。
 *
 * <p>使用场景：作为 {@link MaskingRule} 的子对象，由 core 模块中具体的
 * {@link com.example.anonymization.api.spi.SensitiveDataMasker} 实现读取并执行脱敏。
 *
 * @author log-anonymization
 */
public final class MaskerConfig {

    /** 保留前缀长度（{@link MaskerType#PARTIAL_MASK} 使用，如卡号保留前 6 位） */
    private final int keepPrefixLen;
    /** 保留后缀长度（{@link MaskerType#PARTIAL_MASK} 使用，如卡号保留后 4 位） */
    private final int keepSuffixLen;
    /** 掩码字符（默认 '*'，可配置为 '#' 或 'X' 等） */
    private final char maskChar;
    /** 算法名（{@link MaskerType#HASH} 使用，如 {@code "SHA-256"}） */
    private final String algorithm;
    /** 盐来源（如 {@code "kms://payment-salt"}，由 {@link com.example.anonymization.core.infrastructure.masker.HashMasker} 使用） */
    private final String saltSource;
    /** IP 保留段数（{@link MaskerType#GENERALIZE} 使用，如保留前两段 → {@code "10.1.*.*"}) */
    private final int ipSegmentsToKeep;
    /** 金额区间分桶（{@link MaskerType#GENERALIZE} 使用，如 {@code [1000, 5000, 10000]}） */
    private final List<Double> amountBuckets;
    /** 是否掩码邮箱域名（{@link MaskerType#PARTIAL_MASK} 配合 EMAIL 时使用） */
    private final boolean maskDomain;
    /** 数据类型（部分算法如 {@link com.example.anonymization.core.infrastructure.masker.FallbackMasker} 据此选择占位符） */
    private final SensitiveDataType dataType;

    /**
     * 私有构造器 —— 由 {@link Builder} 触发。
     *
     * @param builder 构建器
     */
    private MaskerConfig(Builder builder) {
        this.keepPrefixLen = builder.keepPrefixLen;
        this.keepSuffixLen = builder.keepSuffixLen;
        this.maskChar = builder.maskChar;
        this.algorithm = builder.algorithm;
        this.saltSource = builder.saltSource;
        this.ipSegmentsToKeep = builder.ipSegmentsToKeep;
        this.amountBuckets = builder.amountBuckets != null
            ? Collections.unmodifiableList(builder.amountBuckets) : Collections.emptyList();
        this.maskDomain = builder.maskDomain;
        this.dataType = builder.dataType;
    }

    /**
     * 获取保留前缀长度。
     *
     * @return 保留前缀字符数
     */
    public int getKeepPrefixLen() { return keepPrefixLen; }

    /**
     * 获取保留后缀长度。
     *
     * @return 保留后缀字符数
     */
    public int getKeepSuffixLen() { return keepSuffixLen; }

    /**
     * 获取掩码字符。
     *
     * @return 掩码字符，默认 '*'
     */
    public char getMaskChar() { return maskChar; }

    /**
     * 获取哈希算法名。
     *
     * @return 算法名（如 {@code "SHA-256"}），可能为 null
     */
    public String getAlgorithm() { return algorithm; }

    /**
     * 获取盐来源。
     *
     * @return 盐来源字符串，可能为 null
     */
    public String getSaltSource() { return saltSource; }

    /**
     * 获取 IP 保留段数。
     *
     * @return 保留段数（0~4）
     */
    public int getIpSegmentsToKeep() { return ipSegmentsToKeep; }

    /**
     * 获取金额区间分桶列表。
     *
     * @return 不可变分桶列表
     */
    public List<Double> getAmountBuckets() { return amountBuckets; }

    /**
     * 是否掩码邮箱域名。
     *
     * @return true 表示掩码
     */
    public boolean isMaskDomain() { return maskDomain; }

    /**
     * 获取数据类型。
     *
     * @return 数据类型，可能为 null
     */
    public SensitiveDataType getDataType() { return dataType; }

    /**
     * 获取 Builder 入口。
     *
     * @return 新的 {@link Builder} 实例
     */
    public static Builder builder() { return new Builder(); }

    /**
     * {@link MaskerConfig} 的流式构建器。
     */
    public static class Builder {
        private int keepPrefixLen;
        private int keepSuffixLen;
        private char maskChar = '*';
        private String algorithm;
        private String saltSource;
        private int ipSegmentsToKeep;
        private List<Double> amountBuckets;
        private boolean maskDomain;
        private SensitiveDataType dataType;

        /**
         * 设置保留前缀长度。
         *
         * @param len 前缀字符数
         * @return 当前 Builder
         */
        public Builder keepPrefixLen(int len) { this.keepPrefixLen = len; return this; }

        /**
         * 设置保留后缀长度。
         *
         * @param len 后缀字符数
         * @return 当前 Builder
         */
        public Builder keepSuffixLen(int len) { this.keepSuffixLen = len; return this; }

        /**
         * 设置掩码字符。
         *
         * @param c 掩码字符
         * @return 当前 Builder
         */
        public Builder maskChar(char c) { this.maskChar = c; return this; }

        /**
         * 设置哈希算法名。
         *
         * @param algorithm 算法名
         * @return 当前 Builder
         */
        public Builder algorithm(String algorithm) { this.algorithm = algorithm; return this; }

        /**
         * 设置盐来源。
         *
         * @param saltSource 盐来源
         * @return 当前 Builder
         */
        public Builder saltSource(String saltSource) { this.saltSource = saltSource; return this; }

        /**
         * 设置 IP 保留段数。
         *
         * @param segments 保留段数
         * @return 当前 Builder
         */
        public Builder ipSegmentsToKeep(int segments) { this.ipSegmentsToKeep = segments; return this; }

        /**
         * 设置金额区间分桶列表。
         *
         * @param buckets 分桶列表
         * @return 当前 Builder
         */
        public Builder amountBuckets(List<Double> buckets) { this.amountBuckets = buckets; return this; }

        /**
         * 设置是否掩码邮箱域名。
         *
         * @param mask true 掩码
         * @return 当前 Builder
         */
        public Builder maskDomain(boolean mask) { this.maskDomain = mask; return this; }

        /**
         * 设置数据类型。
         *
         * @param dataType 数据类型
         * @return 当前 Builder
         */
        public Builder dataType(SensitiveDataType dataType) { this.dataType = dataType; return this; }

        /**
         * 构建不可变的 {@link MaskerConfig}。
         *
         * @return 配置实例
         */
        public MaskerConfig build() { return new MaskerConfig(this); }
    }
}