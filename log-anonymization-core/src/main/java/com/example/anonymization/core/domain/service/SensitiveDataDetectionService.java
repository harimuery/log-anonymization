package com.example.anonymization.core.domain.service;

import com.example.anonymization.api.model.DetectionResult;
import com.example.anonymization.api.model.LogContext;

import java.util.List;

/**
 * 敏感数据检测服务 —— 领域服务接口，编排检测器与规则匹配逻辑，对外暴露统一检测入口。
 *
 * <p>使用场景：{@link com.example.anonymization.core.application.pipeline.DetectionStage}
 * 在管道中调用本服务的 {@link #detect} 完成实际识别。
 *
 * @author log-anonymization
 */
public interface SensitiveDataDetectionService {
    /**
     * 检测日志上下文中包含的所有敏感数据片段。
     *
     * <p>典型实现：
     * <ol>
     *   <li>通过 {@link RuleMatchService#findApplicableRules} 获取当前上下文适用的规则</li>
     *   <li>遍历每条规则，通过 {@link com.example.anonymization.core.domain.DetectorRegistry}
     *       获取对应类型的检测器并执行 {@link com.example.anonymization.api.spi.SensitiveDataDetector#detect}</li>
     *   <li>汇总所有命中片段返回</li>
     * </ol>
     *
     * @param context 日志上下文
     * @return 所有命中片段列表（空列表表示未发现敏感数据）
     */
    List<DetectionResult> detect(LogContext context);
}