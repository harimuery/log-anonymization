package com.example.anonymization.core.domain.service.impl;

import com.example.anonymization.api.model.DetectionResult;
import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.model.MaskerConfig;
import com.example.anonymization.api.model.MaskingResult;
import com.example.anonymization.api.model.MaskingRule;
import com.example.anonymization.api.spi.SensitiveDataMasker;
import com.example.anonymization.core.domain.MaskerRegistry;
import com.example.anonymization.core.domain.ThreadSafeRuleManager;
import com.example.anonymization.core.domain.service.RuleMatchService;
import com.example.anonymization.core.domain.service.SensitiveDataMaskingService;
import com.example.anonymization.core.infrastructure.masker.MaskerFactory;

import java.util.Comparator;
import java.util.List;

/**
 * 默认敏感数据脱敏服务 —— {@link SensitiveDataMaskingService} 的标准实现，
 * 在原文中按检测结果执行替换，生成脱敏后的完整字符串。
 *
 * <p>使用场景：在 {@link com.example.anonymization.core.application.pipeline.MaskingStage}
 * 中作为 {@code maskingService} 被调用。
 *
 * <p>关键设计：采用<b>逆序替换</b>策略（按 {@code startIndex} 倒序遍历），
 * 避免字符串下标因前缀长度变化而错位（如 {@code "12345" → "12***45"} 不会影响后续片段位置）。
 *
 * @author log-anonymization
 */
public class DefaultSensitiveDataMaskingService implements SensitiveDataMaskingService {

    /** 脱敏器工厂（按算法类型查找具体实现） */
    private final MaskerFactory maskerFactory;
    /** 线程安全规则管理器（保留扩展点） */
    private final ThreadSafeRuleManager ruleManager;
    /** 规则匹配服务（按检测结果找规则） */
    private final RuleMatchService ruleMatchService;

    /**
     * 构造默认脱敏服务。
     *
     * @param maskerFactory   脱敏器工厂
     * @param ruleManager     规则管理器
     * @param ruleMatchService 规则匹配服务
     */
    public DefaultSensitiveDataMaskingService(MaskerFactory maskerFactory,
                                                ThreadSafeRuleManager ruleManager,
                                                RuleMatchService ruleMatchService) {
        this.maskerFactory = maskerFactory;
        this.ruleManager = ruleManager;
        this.ruleMatchService = ruleMatchService;
    }

    /**
     * 执行脱敏替换：
     * <ol>
     *   <li>无命中片段 → 返回 {@link MaskingResult#unchanged} 短路审计</li>
     *   <li>按 {@code startIndex} 倒序排序（关键：避免下标错位）</li>
     *   <li>对每个命中片段：
     *     <ul>
     *       <li>调用 {@link RuleMatchService#findRuleForDetection} 找规则</li>
     *       <li>从 {@link MaskerFactory} 拿到对应脱敏器</li>
     *       <li>对原文片段执行脱敏，替换到 {@link StringBuilder}</li>
     *     </ul>
     *   </li>
     *   <li>返回 {@link MaskingResult#masked}</li>
     * </ol>
     *
     * @param message    原始消息文本
     * @param detections 检测命中片段列表
     * @return 脱敏结果
     */
    @Override
    public MaskingResult mask(String message, List<DetectionResult> detections) {
        if (detections == null || detections.isEmpty()) {
            return MaskingResult.unchanged(message);
        }

        List<DetectionResult> sorted = detections.stream()
            .sorted(Comparator.comparingInt(DetectionResult::startIndex).reversed())
            .toList();

        StringBuilder sb = new StringBuilder(message);
        for (DetectionResult detection : sorted) {
            ruleMatchService.findRuleForDetection(detection).ifPresent(rule -> {
                SensitiveDataMasker masker = maskerFactory.create(rule.getMaskerType());
                String original = sb.substring(detection.startIndex(), detection.endIndex());
                MaskingResult result = masker.mask(original, rule.getMaskerConfig());
                sb.replace(detection.startIndex(), detection.endIndex(), result.getMasked());
            });
        }

        return MaskingResult.masked(message, sb.toString());
    }
}