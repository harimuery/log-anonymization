package com.example.anonymization.core.domain.service.impl;

import com.example.anonymization.api.model.DetectionResult;
import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.model.MaskingRule;
import com.example.anonymization.api.spi.SensitiveDataDetector;
import com.example.anonymization.core.domain.DetectorRegistry;
import com.example.anonymization.core.domain.ThreadSafeRuleManager;
import com.example.anonymization.core.domain.service.RuleMatchService;
import com.example.anonymization.core.domain.service.SensitiveDataDetectionService;

import java.util.ArrayList;
import java.util.List;

/**
 * 默认敏感数据检测服务 —— {@link SensitiveDataDetectionService} 的标准实现，
 * 编排"匹配规则 → 取出检测器 → 执行检测 → 汇总结果"的完整流程。
 *
 * <p>使用场景：在 {@link com.example.anonymization.core.application.pipeline.DetectionStage}
 * 中作为 {@code detectionService} 被调用。
 *
 * @author log-anonymization
 */
public class DefaultSensitiveDataDetectionService implements SensitiveDataDetectionService {

    /** 检测器注册表（按数据类型查找） */
    private final DetectorRegistry detectorRegistry;
    /** 线程安全规则管理器（虽然内部主要通过 ruleMatchService 取规则，但保留以备扩展） */
    private final ThreadSafeRuleManager ruleManager;
    /** 规则匹配服务 */
    private final RuleMatchService ruleMatchService;

    /**
     * 构造默认检测服务。
     *
     * @param detectorRegistry 检测器注册表
     * @param ruleManager      规则管理器
     * @param ruleMatchService 规则匹配服务
     */
    public DefaultSensitiveDataDetectionService(DetectorRegistry detectorRegistry,
                                                  ThreadSafeRuleManager ruleManager,
                                                  RuleMatchService ruleMatchService) {
        this.detectorRegistry = detectorRegistry;
        this.ruleManager = ruleManager;
        this.ruleMatchService = ruleMatchService;
    }

    /**
     * 执行检测：
     * <ol>
     *   <li>通过 {@link RuleMatchService#findApplicableRules} 获取与上下文匹配的规则</li>
     *   <li>遍历每条规则，从 {@link DetectorRegistry} 取出对应类型的检测器（可选）</li>
     *   <li>执行 {@link SensitiveDataDetector#detect} 并汇总所有命中片段</li>
     * </ol>
     *
     * <p>若某条规则未注册对应检测器（{@code Optional.empty()}），该规则被静默跳过。
     *
     * @param context 日志上下文
     * @return 所有命中片段的合并列表
     */
    @Override
    public List<DetectionResult> detect(LogContext context) {
        List<MaskingRule> applicableRules = ruleMatchService.findApplicableRules(context);
        List<DetectionResult> allResults = new ArrayList<>();

        for (MaskingRule rule : applicableRules) {
            detectorRegistry.getDetector(rule.getDataType()).ifPresent(detector -> {
                List<DetectionResult> results = detector.detect(context);
                allResults.addAll(results);
            });
        }

        return allResults;
    }
}