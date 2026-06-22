package com.example.anonymization.api.enums;

/**
 * 检测器类型枚举 —— 定义识别敏感数据的不同检测算法分类。
 *
 * <p>使用场景：作为 {@link com.example.anonymization.api.model.MaskingRule} 的字段，
 * 决定检测阶段使用何种识别器：
 * <ul>
 *   <li>{@link #REGEX}：基于正则表达式的模式匹配（最常用，配合 re2j 引擎保证线性时间复杂度）</li>
 *   <li>{@link #KEYWORD}：基于关键词字典的精确匹配（Aho-Corasick 多模式算法）</li>
 *   <li>{@link #FIELD_NAME}：基于字段名识别（如 password=xxx 中的 password 字段）</li>
 *   <li>{@link #CUSTOM}：自定义检测器实现，由用户通过 SPI 注入</li>
 * </ul>
 *
 * @author log-anonymization
 */
public enum DetectorType {
    /** 基于正则表达式匹配（默认主路径，配合 re2j 保证线性复杂度与 ReDoS 防护） */
    REGEX,
    /** 基于关键词字典的精确匹配（Aho-Corasick 等多模式算法） */
    KEYWORD,
    /** 基于字段名识别（如 JSON/XML 中的 password、pan、cvv 等字段） */
    FIELD_NAME,
    /** 自定义检测器，由用户通过 {@link com.example.anonymization.api.spi.SensitiveDataDetector} SPI 扩展 */
    CUSTOM
}