package com.example.anonymization.api.event;

import java.time.Instant;

/**
 * 脱敏完成事件 —— 在一次脱敏管道执行完毕后发布，用于监控/审计/下游联动。
 *
 * <p>典型发布位置：{@link com.example.anonymization.core.application.pipeline.AuditStage#process}
 * 检测到结果被修改（{@code result.isChanged()} 为 true）时触发。
 *
 * <p>使用场景：消费方包括 Micrometer 指标（hits/errors 按 dataType 分桶统计）、
 * SIEM 同步器（按 risk level 路由告警）等。
 *
 * @param traceId    链路追踪 ID（取自 MDC 的 traceId），用于关联一次请求的完整日志
 * @param appName    应用名（用于多应用环境下的指标切分）
 * @param dataType   命中的敏感数据类型（如 BANK_CARD、PHONE），可为空
 * @param action     实际执行的脱敏动作，见 {@link com.example.anonymization.api.enums.MaskingAction}
 * @param success    是否成功（true = 正常脱敏；false = 降级或失败）
 * @param occurredAt 事件发生时间戳（若传入 null，紧凑构造器会回填为 {@link Instant#now()}）
 *
 * @author log-anonymization
 */
public record MaskingCompletedEvent(
    String traceId,
    String appName,
    String dataType,
    String action,
    boolean success,
    Instant occurredAt
) implements DomainEvent {
    /**
     * 紧凑构造器 —— 自动回填发生时间戳，避免下游消费方判空。
     *
     * @param traceId    链路追踪 ID
     * @param appName    应用名
     * @param dataType   命中的敏感数据类型
     * @param action     脱敏动作
     * @param success    是否成功
     * @param occurredAt 事件时间戳，为 null 时填充为当前时间
     */
    public MaskingCompletedEvent {
        if (occurredAt == null) occurredAt = Instant.now();
    }
}