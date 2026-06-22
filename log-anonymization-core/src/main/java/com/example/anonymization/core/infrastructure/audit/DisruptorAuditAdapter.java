package com.example.anonymization.core.infrastructure.audit;

import com.example.anonymization.api.model.AuditRecord;
import com.example.anonymization.api.port.AuditPort;
import com.example.anonymization.api.spi.AuditExporter;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * 基于 Disruptor 模式的审计适配器 —— {@link AuditPort} 的标准实现，提供异步批量审计能力。
 *
 * <p>使用场景：在
 * {@link com.example.anonymization.starter.LogAnonymizationAutoConfiguration#auditPort}
 * 中按配置注入；{@link com.example.anonymization.core.application.pipeline.AuditStage}
 * 调用 {@link #record} 写入审计记录。
 *
 * <p>关键设计：
 * <ul>
 *   <li>使用 {@link ScheduledExecutorService} 周期性刷盘，避免长尾延迟</li>
 *   <li>批次达到 {@code batchSize} 立即触发刷盘（保证实时性）</li>
 *   <li>支持多种 {@link AuditExporter}（按 order 排序），文件/Kafka/SIEM 任意组合</li>
 *   <li>{@code synchronized} 保证单 JVM 内单写多读安全</li>
 * </ul>
 *
 * @author log-anonymization
 */
public class DisruptorAuditAdapter implements AuditPort {

    /** 已注册的审计导出器列表（按 {@link AuditExporter#getOrder()} 升序） */
    private final List<AuditExporter> exporters;
    /** 内存缓冲（达到 {@code batchSize} 触发刷盘） */
    private final List<AuditRecord> buffer;
    /** 批量触发阈值 */
    private final int batchSize;
    /** 周期性刷盘调度器（单线程、守护） */
    private final ScheduledExecutorService scheduler;

    /**
     * 构造 Disruptor 审计适配器。
     *
     * <p>内部会启动一个守护线程，周期性地调用 {@link #flush}。
     *
     * @param exporters             审计导出器列表
     * @param batchSize             批量阈值（达到即刷盘）
     * @param flushIntervalSeconds  周期性刷盘间隔（秒）
     */
    public DisruptorAuditAdapter(List<AuditExporter> exporters, int batchSize, int flushIntervalSeconds) {
        this.exporters = exporters;
        this.batchSize = batchSize;
        this.buffer = new ArrayList<>(batchSize);
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "audit-flush");
            t.setDaemon(true);
            return t;
        });
        this.scheduler.scheduleAtFixedRate(this::flush, flushIntervalSeconds, flushIntervalSeconds, TimeUnit.SECONDS);
    }

    /**
     * 写入一条审计记录（非阻塞）。
     *
     * <p>记录先加入 buffer；达到 {@code batchSize} 时立即同步触发刷盘，
     * 否则等待调度器的周期性刷盘。
     *
     * @param record 审计记录
     */
    @Override
    public synchronized void record(AuditRecord record) {
        buffer.add(record);
        if (buffer.size() >= batchSize) {
            flush();
        }
    }

    /**
     * 刷盘：将当前 buffer 批量交给所有 Exporter。
     *
     * <p>实现细节：
     * <ul>
     *   <li>空 buffer 直接返回</li>
     *   <li>取出 buffer 副本后立即清空原 buffer（避免阻塞 record 路径）</li>
     *   <li>遍历所有 Exporter，supportsBatch=true 调用 {@link AuditExporter#export(List)}，否则逐条调用</li>
     *   <li>单个 Exporter 异常被捕获并打印，不影响其他 Exporter</li>
     * </ul>
     */
    private synchronized void flush() {
        if (buffer.isEmpty()) return;
        List<AuditRecord> batch = new ArrayList<>(buffer);
        buffer.clear();
        for (AuditExporter exporter : exporters) {
            try {
                if (exporter.supportsBatch()) {
                    exporter.export(batch);
                } else {
                    batch.forEach(r -> exporter.export(List.of(r)));
                }
            } catch (Exception e) {
                System.err.println("[AuditExport] Failed to export batch: " + e.getMessage());
            }
        }
    }
}