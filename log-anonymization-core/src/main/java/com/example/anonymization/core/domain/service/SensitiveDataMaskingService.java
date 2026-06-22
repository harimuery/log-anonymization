package com.example.anonymization.core.domain.service;

import com.example.anonymization.api.model.DetectionResult;
import com.example.anonymization.api.model.MaskingResult;

import java.util.List;

/**
 * 敏感数据脱敏服务 —— 领域服务接口，根据检测结果在原文中执行替换。
 *
 * <p>使用场景：{@link com.example.anonymization.core.application.pipeline.MaskingStage}
 * 调用本服务将检测片段替换为脱敏后字符串。
 *
 * @author log-anonymization
 */
public interface SensitiveDataMaskingService {
    /**
     * 执行脱敏替换。
     *
     * <p>实现需保证：
     * <ul>
     *   <li>多个命中片段时按正确顺序替换（一般采用逆序替换避免下标偏移）</li>
     *   <li>区间重叠时合理合并（由 {@link com.example.anonymization.core.infrastructure.detector.ResultAggregator} 保证）</li>
     *   <li>无命中时返回 {@link MaskingResult#unchanged}（短路审计）</li>
     * </ul>
     *
     * @param message   原始消息文本
     * @param detections 检测命中片段列表
     * @return 脱敏结果（{@link MaskingResult}）
     */
    MaskingResult mask(String message, List<DetectionResult> detections);
}