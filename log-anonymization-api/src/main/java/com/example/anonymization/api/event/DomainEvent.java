package com.example.anonymization.api.event;

import java.time.Instant;

/**
 * 领域事件根接口 —— 抽象所有领域事件共有的"发生时间"属性。
 *
 * <p>使用 sealed interface 限制可扩展的具体事件类型（当前仅允许
 * {@link MaskingCompletedEvent} 和 {@link RuleRefreshedEvent}），
 * 便于编译期校验与模式匹配（Pattern Matching）。
 *
 * <p>使用场景：在脱敏管道（如 {@link com.example.anonymization.core.application.pipeline.AuditStage}）
 * 中触发事件，由 {@link DomainEventBus} 分发给订阅方（监控、审计、SIEM 同步等）。
 *
 * @author log-anonymization
 */
public sealed interface DomainEvent
    permits MaskingCompletedEvent, RuleRefreshedEvent {
    /**
     * 事件发生时间戳。
     *
     * <p>若发布方未显式传入时间，子事件 record 的紧凑构造器会回填为当前时间，
     * 保证事件一定有有效时间戳用于审计与排序。
     *
     * @return 事件发生时间（{@link Instant}），永远不为 null
     */
    Instant occurredAt();
}