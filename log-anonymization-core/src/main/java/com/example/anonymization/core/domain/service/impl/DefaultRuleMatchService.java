package com.example.anonymization.core.domain.service.impl;

import com.example.anonymization.api.model.DetectionResult;
import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.model.MaskingRule;
import com.example.anonymization.core.domain.ThreadSafeRuleManager;
import com.example.anonymization.core.domain.service.RuleMatchService;

import java.util.List;
import java.util.Optional;

/**
 * 默认规则匹配服务 —— {@link RuleMatchService} 的标准实现，基于无锁规则快照完成匹配查询。
 *
 * <p>使用场景：由 Spring 容器自动注入到 {@link com.example.anonymization.core.application.pipeline.DetectionStage}
 * 与 {@link com.example.anonymization.core.domain.service.impl.DefaultSensitiveDataMaskingService}。
 *
 * @author log-anonymization
 */
public class DefaultRuleMatchService implements RuleMatchService {

    /** 线程安全规则管理器（提供最新规则快照） */
    private final ThreadSafeRuleManager ruleManager;

    /**
     * 构造默认规则匹配服务。
     *
     * @param ruleManager 规则管理器实例
     */
    public DefaultRuleMatchService(ThreadSafeRuleManager ruleManager) {
        this.ruleManager = ruleManager;
    }

    /**
     * 查找适用于给定上下文的规则列表。
     *
     * <p>直接读取 {@link ThreadSafeRuleManager#getCurrentRules}（无锁快照），按
     * {@link MaskingRule#appliesTo} 过滤。
     *
     * @param context 日志上下文
     * @return 适用规则列表（可能为空）
     */
    @Override
    public List<MaskingRule> findApplicableRules(LogContext context) {
        return ruleManager.getCurrentRules().stream()
            .filter(rule -> rule.appliesTo(context))
            .toList();
    }

    /**
     * 根据检测结果的 dataType 查找首个匹配的规则。
     *
     * <p>实现返回找到的第一条匹配的规则；若同一数据类型注册多条规则，
     * 调用方应通过 {@link #findApplicableRules} 自行去重。
     *
     * @param detection 检测结果
     * @return 命中规则的 Optional 包装
     */
    @Override
    public Optional<MaskingRule> findRuleForDetection(DetectionResult detection) {
        return ruleManager.getCurrentRules().stream()
            .filter(rule -> rule.getDataType() == detection.dataType())
            .findFirst();
    }
}