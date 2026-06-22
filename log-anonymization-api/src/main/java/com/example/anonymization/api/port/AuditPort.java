package com.example.anonymization.api.port;

import com.example.anonymization.api.model.AuditRecord;

/**
 * 审计端口 —— 抽象审计记录的写入入口，解耦审计生产者与具体实现（Disruptor、Kafka 等）。
 *
 * <p>使用场景：
 * <ul>
 *   <li>{@link com.example.anonymization.core.application.pipeline.AuditStage}
 *       在检测/脱敏后调用 {@link #record} 写入一条审计记录</li>
 *   <li>核心实现为 {@link com.example.anonymization.core.infrastructure.audit.DisruptorAuditAdapter}
 *       （基于 LMAX Disruptor 的异步批量刷盘）</li>
 *   <li>合规审计要求所有敏感操作有完整审计链路，本端口是核心契约</li>
 * </ul>
 *
 * @author log-anonymization
 */
public interface AuditPort {
    /**
     * 记录一条审计事件。
     *
     * <p>实现必须保证：
     * <ul>
     *   <li>非阻塞（推荐异步队列，落盘与生产者解耦）</li>
     *   <li>异常隔离（写入失败不影响业务日志输出）</li>
     *   <li>顺序保证（同一 traceId 的事件保持顺序）</li>
     * </ul>
     *
     * @param record 审计记录，不可为 null
     */
    void record(AuditRecord record);
}