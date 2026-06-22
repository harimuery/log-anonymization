package com.example.anonymization.api.event;

import java.time.Instant;

/**
 * 规则刷新事件 —— 当脱敏规则从配置中心（Nacos/Apollo）或本地文件动态加载后发布。
 *
 * <p>典型发布位置：{@link com.example.anonymization.core.domain.ThreadSafeRuleManager#refreshRules}
 * 被 {@link com.example.anonymization.core.infrastructure.config.LocalFileRuleLoadAdapter}
 * 或其他 {@link com.example.anonymization.api.spi.MaskingRuleLoader} 的变更回调触发时。
 *
 * <p>使用场景：消费方（如审计系统、规则预览面板）可感知规则变更，
 * 配合规则版本号（{@code version}）实现灰度发布与回滚能力。
 *
 * @param ruleCount  本次生效的规则条数（仅统计已启用的）
 * @param version    规则版本号（单调递增，用于审计追溯与冲突检测）
 * @param occurredAt 事件发生时间戳（为 null 时回填为当前时间）
 *
 * @author log-anonymization
 */
public record RuleRefreshedEvent(
    int ruleCount,
    int version,
    Instant occurredAt
) implements DomainEvent {
    /**
     * 紧凑构造器 —— 回填发生时间戳，避免下游判空。
     *
     * @param ruleCount  生效规则条数
     * @param version    规则版本号
     * @param occurredAt 事件时间戳
     */
    public RuleRefreshedEvent {
        if (occurredAt == null) occurredAt = Instant.now();
    }
}