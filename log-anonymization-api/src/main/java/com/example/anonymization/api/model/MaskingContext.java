package com.example.anonymization.api.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 脱敏上下文 —— 在脱敏管道（Pipeline）各 Stage 之间传递的可变状态对象。
 *
 * <p>使用场景：作为
 * {@link com.example.anonymization.core.application.pipeline.PipelineStage#process(MaskingContext)}
 * 的入参，依次被 {@link com.example.anonymization.core.application.pipeline.BloomFilterStage}
 * → {@link com.example.anonymization.core.application.pipeline.DetectionStage}
 * → {@link com.example.anonymization.core.application.pipeline.MaskingStage}
 * → {@link com.example.anonymization.core.application.pipeline.AuditStage}
 * 读写，最终携带 {@link MaskingResult} 返回。
 *
 * <p>注意：因管道是单线程顺序执行（每条日志一个上下文对象），可变状态在单条流水线上
 * 不存在并发问题；但同一对象不可跨线程共享。
 *
 * @author log-anonymization
 */
public final class MaskingContext {

    /** 原始日志消息 */
    private final String message;
    /** 原始日志上下文（不可变） */
    private final LogContext logContext;
    /** 检测阶段写入的命中结果列表（{@link DetectionResult} 集合） */
    private List<DetectionResult> detections;
    /** 脱敏阶段写入的最终结果 */
    private MaskingResult result;

    /**
     * 创建脱敏上下文。
     *
     * @param message    原始日志消息
     * @param logContext 原始日志上下文
     */
    public MaskingContext(String message, LogContext logContext) {
        this.message = message;
        this.logContext = logContext;
        this.detections = Collections.emptyList();
    }

    /**
     * 获取原始消息。
     *
     * @return 原始消息文本
     */
    public String message() { return message; }

    /**
     * 获取原始日志上下文。
     *
     * @return {@link LogContext} 实例
     */
    public LogContext logContext() { return logContext; }

    /**
     * 获取检测结果列表。
     *
     * @return 不可变副本（{@link List#copyOf}），未设置时返回空列表
     */
    public List<DetectionResult> detections() { return detections; }

    /**
     * 获取脱敏结果。
     *
     * @return 结果实例，未设置时返回 null
     */
    public MaskingResult result() { return result; }

    /**
     * 设置检测结果列表（由 DetectionStage 调用）。
     *
     * @param detections 检测结果，传 null 时回退为空列表
     */
    public void setDetections(List<DetectionResult> detections) {
        this.detections = detections != null ? List.copyOf(detections) : Collections.emptyList();
    }

    /**
     * 设置脱敏结果（由 MaskingStage 调用）。
     *
     * @param result 脱敏结果
     */
    public void setResult(MaskingResult result) {
        this.result = result;
    }
}