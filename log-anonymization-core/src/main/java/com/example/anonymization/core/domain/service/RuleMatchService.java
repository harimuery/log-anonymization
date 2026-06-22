package com.example.anonymization.core.domain.service;

import com.example.anonymization.api.model.MaskingRule;
import com.example.anonymization.api.model.LogContext;

import java.util.List;
import java.util.Optional;

/**
 * 规则匹配服务 —— 提供"按上下文找规则"与"按命中找规则"两个核心查询能力。
 *
 * <p>使用场景：在 {@link com.example.anonymization.core.application.pipeline.DetectionStage}
 * 中通过 {@link #findApplicableRules} 拿到与日志匹配的规则列表，
 * 在 {@link com.example.anonymization.core.domain.service.DefaultSensitiveDataMaskingService}
 * 中通过 {@link #findRuleForDetection} 为单个命中片段找到对应脱敏规则。
 *
 * @author log-anonymization
 */
public interface RuleMatchService {
    /**
     * 查找适用于给定日志上下文的所有规则。
     *
     * <p>实现需结合 {@link com.example.anonymization.core.domain.ThreadSafeRuleManager}
     * 中的最新规则列表与 {@link com.example.anonymization.api.model.MaskingRule#appliesTo} 判断。
     *
     * @param context 日志上下文
     * @return 适用规则列表（空列表表示无匹配）
     */
    List<MaskingRule> findApplicableRules(LogContext context);

    /**
     * 根据检测结果查找对应的脱敏规则（按 dataType 匹配）。
     *
     * @param detection 检测结果（含 dataType）
     * @return 命中规则的 Optional 包装（空表示未配置对应类型规则）
     */
    Optional<MaskingRule> findRuleForDetection(com.example.anonymization.api.model.DetectionResult detection);
}