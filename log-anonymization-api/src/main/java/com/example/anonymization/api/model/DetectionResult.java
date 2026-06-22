package com.example.anonymization.api.model;

import com.example.anonymization.api.enums.SensitiveDataType;

/**
 * 检测结果 —— 单次识别过程中命中的一个敏感数据片段。
 *
 * <p>使用场景：由 {@link com.example.anonymization.api.spi.SensitiveDataDetector} 生成，
 * 进入 {@link MaskingContext} 后由 {@link com.example.anonymization.core.application.pipeline.MaskingStage}
 * 按 startIndex/endIndex 在原文中替换为脱敏后的值。
 *
 * @param startIndex    命中片段在原日志消息中的起始下标（包含，{@code >= 0}）
 * @param endIndex      命中片段的结束下标（不包含，{@code > startIndex}）
 * @param dataType      命中的敏感数据类型
 * @param confidence    匹配置信度（{@code [0.0, 1.0]}，由具体检测器赋值，例如 Luhn 通过=1.0、未通过=0.0）
 * @param matchedValue  命中的原始值（仅在内部流水线传递，最终持久化前需脱敏）
 *
 * @author log-anonymization
 */
public record DetectionResult(
    int startIndex,
    int endIndex,
    SensitiveDataType dataType,
    double confidence,
    String matchedValue
) {
    /**
     * 紧凑构造器 —— 校验下标区间与置信度合法性，避免后续替换阶段抛 {@link IndexOutOfBoundsException}。
     *
     * @param startIndex   起始下标
     * @param endIndex     结束下标
     * @param dataType     敏感类型
     * @param confidence   置信度
     * @param matchedValue 命中值
     * @throws IllegalArgumentException 当下标非法或置信度不在 [0,1] 区间时抛出
     */
    public DetectionResult {
        if (startIndex < 0) throw new IllegalArgumentException("startIndex must be >= 0");
        if (endIndex <= startIndex) throw new IllegalArgumentException("endIndex must be > startIndex");
        if (confidence < 0 || confidence > 1.0) throw new IllegalArgumentException("confidence must be between 0 and 1");
    }

    /**
     * 计算命中片段的长度（{@code endIndex - startIndex}）。
     *
     * <p>用于 {@link com.example.anonymization.core.infrastructure.detector.ResultAggregator}
     * 在区间重叠时保留更长命中（避免短片段吞掉长片段）。
     *
     * @return 命中片段字符数
     */
    public int length() {
        return endIndex - startIndex;
    }
}