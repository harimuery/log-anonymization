package com.example.anonymization.core.application.pipeline;

import com.example.anonymization.api.event.DomainEventBus;
import com.example.anonymization.api.event.MaskingCompletedEvent;
import com.example.anonymization.api.model.MaskingContext;
import com.example.anonymization.api.port.AuditPort;
import com.example.anonymization.api.port.MetricsPort;

/**
 * 审计 Stage —— 在脱敏完成后上报指标、发布事件（管道最后一站）。
 *
 * <p>使用场景：作为管道的收尾 Stage，串联 {@link MetricsPort} 与
 * {@link DomainEventBus}，为后续监控/SIEM 集成提供数据源。
 *
 * <p>短路条件：当 {@link com.example.anonymization.api.model.MaskingResult#isChanged()}
 * 为 false（如 BloomFilter 跳过、未命中检测）时，本 Stage 不会发布事件，避免无意义开销。
 *
 * @author log-anonymization
 */
public class AuditStage extends AbstractPipelineStage {

    /** 审计端口（异步批量写入） */
    private final AuditPort auditPort;
    /** 指标端口（命中计数） */
    private final MetricsPort metricsPort;
    /** 领域事件总线（发布 MaskingCompletedEvent） */
    private final DomainEventBus eventBus;

    /**
     * 构造审计 Stage。
     *
     * @param auditPort   审计端口
     * @param metricsPort 指标端口
     * @param eventBus    领域事件总线
     */
    public AuditStage(AuditPort auditPort, MetricsPort metricsPort, DomainEventBus eventBus) {
        this.auditPort = auditPort;
        this.metricsPort = metricsPort;
        this.eventBus = eventBus;
    }

    /**
     * 执行审计上报：
     * <ol>
     *   <li>无论如何都自增 {@code processed.total} 计数器（每条日志均被处理）</li>
     *   <li>仅当 result 非空且 changed=true 时，按 detections 自增 {@code hits.total}（按 dataType 分桶）</li>
     *   <li>构造并发布 {@link MaskingCompletedEvent}，便于下游消费（SIEM、监控等）</li>
     * </ol>
     *
     * <p>注意：traceId 取自 MDC；dataType 仅取第一条命中以避免事件过大。
     *
     * @param context 脱敏上下文
     */
    @Override
    public void process(MaskingContext context) {
        metricsPort.incrementProcessed();
        if (context.result() != null && context.result().isChanged()) {
            context.detections().forEach(detection -> {
                metricsPort.incrementHits(detection.dataType().name());
            });
            eventBus.publish(new MaskingCompletedEvent(
                context.logContext().getMdc().getOrDefault("traceId", ""),
                context.logContext().getAppName(),
                context.detections().isEmpty() ? "" : context.detections().get(0).dataType().name(),
                context.result().getAction().name(),
                !context.result().isDegraded(),
                null
            ));
        }
    }
}