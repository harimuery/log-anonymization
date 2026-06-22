package com.example.anonymization.api.model;

import java.time.Instant;

/**
 * 审计记录 —— 一条脱敏行为的可追溯、不可篡改的记录单元。
 *
 * <p>使用场景：由 {@link com.example.anonymization.core.application.pipeline.AuditStage}
 * 或外部审计消费者写入 {@link com.example.anonymization.api.port.AuditPort}，
 * 最终由 {@link com.example.anonymization.core.infrastructure.audit.DisruptorAuditAdapter}
 * 异步批量推送至审计专用 Appender / SIEM。
 *
 * <p><b>合规约束</b>：根据 PCI DSS 与个人信息保护法要求，审计日志自身不得包含敏感明文，
 * 所有 value 字段（如 matchedValue）应已在写入前被脱敏或哈希。
 *
 * @param traceId      链路追踪 ID（与日志关联）
 * @param appName      应用名
 * @param ruleId       命中的规则 ID（如 {@code "RULE-BANK_CARD-001"}）
 * @param ruleName     规则的可读名称（用于审计报表展示）
 * @param dataType     命中的敏感数据类型
 * @param action       实际脱敏动作
 * @param hitCount     本次命中的敏感数据条数（单条日志中可能多次命中同类型）
 * @param success      是否成功
 * @param errorMessage 错误信息（成功时为 null，便于审计对账失败原因）
 * @param timestamp    记录时间戳（紧凑构造器回填当前时间）
 *
 * @author log-anonymization
 */
public record AuditRecord(
    String traceId,
    String appName,
    String ruleId,
    String ruleName,
    String dataType,
    String action,
    int hitCount,
    boolean success,
    String errorMessage,
    Instant timestamp
) {
    /**
     * 紧凑构造器 —— 自动回填时间戳。
     *
     * @param traceId      链路追踪 ID
     * @param appName      应用名
     * @param ruleId       规则 ID
     * @param ruleName     规则名
     * @param dataType     敏感类型
     * @param action       脱敏动作
     * @param hitCount     命中条数
     * @param success      是否成功
     * @param errorMessage 错误信息
     * @param timestamp    时间戳
     */
    public AuditRecord {
        if (timestamp == null) timestamp = Instant.now();
    }
}