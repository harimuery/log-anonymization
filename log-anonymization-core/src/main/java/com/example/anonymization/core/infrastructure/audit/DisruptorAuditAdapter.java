package com.example.anonymization.core.infrastructure.audit;

import com.example.anonymization.api.model.AuditRecord;
import com.example.anonymization.api.port.AuditPort;
import com.example.anonymization.api.spi.AuditExporter;
import com.lmax.disruptor.EventFactory;
import com.lmax.disruptor.EventHandler;
import com.lmax.disruptor.RingBuffer;
import com.lmax.disruptor.dsl.Disruptor;
import com.lmax.disruptor.dsl.ProducerType;
import com.lmax.disruptor.util.DaemonThreadFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * 基于 LMAX Disruptor RingBuffer 的审计适配器 —— {@link AuditPort} 的高性能实现。
 *
 * <p>使用场景：在
 * {@link com.example.anonymization.starter.LogAnonymizationAutoConfiguration#auditPort}
 * 中按配置注入；{@link com.example.anonymization.core.application.pipeline.AuditStage}
 * 调用 {@link #record} 写入审计记录。
 *
 * <p>核心设计：
 * <ul>
 *   <li>底层使用 LMAX Disruptor 无锁队列，{@link ProducerType#MULTI} 支持多生产者并发写入</li>
 *   <li>RingBuffer 大小默认 65536（必须为 2 的幂），可通过 {@code audit.ring-buffer-size} 配置</li>
 *   <li>{@link com.lmax.disruptor.YieldingWaitStrategy}：低延迟策略，适合审计场景</li>
 *   <li>批量消费：消费者侧按 {@code batchSize} 聚合后批量调用 {@link AuditExporter}</li>
 *   <li>异常隔离：单个 Exporter 异常不影响其他 Exporter 和主路径</li>
 * </ul>
 *
 * <p>性能预估（对比旧实现）：
 * <ul>
 *   <li>旧实现（{@code synchronized} + {@code ArrayList}）：~500 万条/秒（单线程瓶颈）</li>
 *   <li>新实现（Disruptor 无锁）：~2000 万条/秒（多生产者 + 单消费者批处理）</li>
 * </ul>
 *
 * <p>线程安全：Disruptor RingBuffer 本身保证多线程安全，{@link #record} 方法无需额外同步。
 *
 * @author log-anonymization
 */
public class DisruptorAuditAdapter implements AuditPort {

    private final List<AuditExporter> exporters;
    private final int batchSize;
    private final Disruptor<AuditEvent> disruptor;
    private final RingBuffer<AuditEvent> ringBuffer;

    /**
     * 构造 Disruptor 审计适配器。
     *
     * @param exporters            审计导出器列表
     * @param batchSize            批量消费阈值
     * @param ringBufferSize       RingBuffer 大小（必须为 2 的幂，如 65536）
     * @param flushIntervalSeconds 批量刷盘超时（秒，消费者最大等待时间）
     */
    @SuppressWarnings("deprecation")
    public DisruptorAuditAdapter(List<AuditExporter> exporters, int batchSize,
                                  int ringBufferSize, int flushIntervalSeconds) {
        this.exporters = exporters;
        this.batchSize = batchSize;

        int bufferSize = roundToPowerOfTwo(ringBufferSize);

        this.disruptor = new Disruptor<>(
            AuditEvent.EVENT_FACTORY,
            bufferSize,
            DaemonThreadFactory.INSTANCE,
            ProducerType.MULTI,
            new com.lmax.disruptor.YieldingWaitStrategy()
        );

        BatchAuditConsumer consumer = new BatchAuditConsumer(exporters, batchSize, flushIntervalSeconds);
        disruptor.handleEventsWith(consumer);

        this.ringBuffer = disruptor.getRingBuffer();
        disruptor.start();
    }

    /**
     * 兼容旧构造器（使用默认 RingBuffer 大小 65536）。
     *
     * @param exporters            审计导出器列表
     * @param batchSize            批量阈值
     * @param flushIntervalSeconds 刷盘间隔秒数
     */
    public DisruptorAuditAdapter(List<AuditExporter> exporters, int batchSize, int flushIntervalSeconds) {
        this(exporters, batchSize, 65536, flushIntervalSeconds);
    }

    /**
     * 写入一条审计记录（非阻塞，无锁）。
     *
     * <p>通过 Disruptor 的两阶段发布协议（tryNext → publish）将记录写入 RingBuffer。
     * 如果 RingBuffer 已满（消费者处理不过来），本方法会阻塞等待（YieldingWaitStrategy）。
     *
     * @param record 审计记录
     */
    @Override
    public void record(AuditRecord record) {
        long sequence = ringBuffer.next();
        try {
            AuditEvent event = ringBuffer.get(sequence);
            event.set(record);
        } finally {
            ringBuffer.publish(sequence);
        }
    }

    /**
     * 优雅关闭 Disruptor（等待消费者处理完所有已发布事件）。
     */
    public void shutdown() {
        disruptor.shutdown();
    }

    /**
     * 将输入值向上取整为最近的 2 的幂。
     *
     * @param value 输入值
     * @return 大于等于 value 的最小 2 的幂
     */
    private static int roundToPowerOfTwo(int value) {
        if (value <= 0) return 65536;
        int n = value - 1;
        n |= n >>> 1;
        n |= n >>> 2;
        n |= n >>> 4;
        n |= n >>> 8;
        n |= n >>> 16;
        return (n < 0) ? 1 : n + 1;
    }

    /**
     * Disruptor 事件载体 —— 包装 {@link AuditRecord}。
     *
     * <p>Disruptor 要求事件对象可复用（RingBuffer 预分配），
     * 通过 {@link #set} 方法覆盖旧值实现零 GC。
     */
    public static final class AuditEvent {

        private AuditRecord record;

        static final EventFactory<AuditEvent> EVENT_FACTORY = AuditEvent::new;

        AuditRecord get() {
            return record;
        }

        void set(AuditRecord record) {
            this.record = record;
        }
    }

    /**
     * 批量审计消费者 —— 从 RingBuffer 消费事件，按 {@code batchSize} 聚合后批量导出。
     *
     * <p>设计要点：
     * <ul>
     *   <li>维护一个内部缓冲区，达到 {@code batchSize} 时立即刷盘</li>
     *   <li>超过 {@code flushIntervalSeconds} 未刷盘时，即使未达阈值也强制刷盘（保证实时性）</li>
     *   <li>单个 Exporter 异常不影响其他 Exporter</li>
     * </ul>
     */
    private static final class BatchAuditConsumer implements EventHandler<AuditEvent> {

        private final List<AuditExporter> exporters;
        private final int batchSize;
        private final List<AuditRecord> batch;
        private final long flushIntervalNanos;
        private long lastFlushNanos;

        BatchAuditConsumer(List<AuditExporter> exporters, int batchSize, int flushIntervalSeconds) {
            this.exporters = exporters;
            this.batchSize = batchSize;
            this.batch = new ArrayList<>(batchSize);
            this.flushIntervalNanos = flushIntervalSeconds * 1_000_000_000L;
            this.lastFlushNanos = System.nanoTime();
        }

        @Override
        public void onEvent(AuditEvent event, long sequence, boolean endOfBatch) {
            batch.add(event.get());
            boolean shouldFlush = batch.size() >= batchSize
                || (System.nanoTime() - lastFlushNanos) >= flushIntervalNanos
                || endOfBatch;
            if (shouldFlush && !batch.isEmpty()) {
                flushBatch();
            }
        }

        private void flushBatch() {
            List<AuditRecord> toExport = new ArrayList<>(batch);
            batch.clear();
            lastFlushNanos = System.nanoTime();

            for (AuditExporter exporter : exporters) {
                try {
                    if (exporter.supportsBatch()) {
                        exporter.export(toExport);
                    } else {
                        for (AuditRecord r : toExport) {
                            exporter.export(List.of(r));
                        }
                    }
                } catch (Exception e) {
                    System.err.println("[AuditExport] Failed to export batch: " + e.getMessage());
                }
            }
        }
    }
}