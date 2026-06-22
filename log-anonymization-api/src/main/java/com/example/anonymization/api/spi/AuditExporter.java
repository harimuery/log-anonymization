package com.example.anonymization.api.spi;

import com.example.anonymization.api.model.AuditRecord;

import java.util.List;

/**
 * 审计导出器 SPI —— 抽象审计记录的最终落地方式（文件、Kafka、SIEM 等）。
 *
 * <p>使用场景：业务方按需实现该接口（如 {@code KafkaAuditExporter}、
 * {@code FileAuditExporter}），并以 Spring Bean 形式注入到
 * {@link com.example.anonymization.core.infrastructure.audit.DisruptorAuditAdapter}。
 *
 * <p>多个 Exporter 通过 {@link Comparable} 排序：{@link #getOrder()} 数值越小越先执行。
 *
 * @author log-anonymization
 */
public interface AuditExporter extends Comparable<AuditExporter> {

    /**
     * 批量导出一条审计记录列表。
     *
     * <p>实现应保证：
     * <ul>
     *   <li>内部异常隔离，单条失败不影响其它记录</li>
     *   <li>幂等性：重复写入同一批记录不产生副作用（便于重试）</li>
     *   <li>超时控制，避免阻塞 Disruptor 消费线程</li>
     * </ul>
     *
     * @param records 待导出的审计记录列表
     */
    void export(List<AuditRecord> records);

    /**
     * 是否支持批量导出（用于 {@link com.example.anonymization.core.infrastructure.audit.DisruptorAuditAdapter}
     * 选择 export 或逐条调用）。
     *
     * @return true 表示支持批量
     */
    boolean supportsBatch();

    /**
     * 获取 Exporter 顺序（数值越小越先执行，默认 0）。
     *
     * <p>典型场景：文件 Exporter（order=0）在 Kafka Exporter（order=10）之前执行，
     * 保证本地审计日志一定先于远端传输落地。
     *
     * @return 顺序值
     */
    default int getOrder() { return 0; }

    /**
     * 按 {@link #getOrder()} 升序比较。
     *
     * @param other 另一 Exporter
     * @return 排序结果
     */
    @Override
    default int compareTo(AuditExporter other) {
        return Integer.compare(this.getOrder(), other.getOrder());
    }
}