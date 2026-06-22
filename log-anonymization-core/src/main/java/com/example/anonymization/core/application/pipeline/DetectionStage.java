package com.example.anonymization.core.application.pipeline;

import com.example.anonymization.api.model.DetectionResult;
import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.model.MaskingContext;
import com.example.anonymization.core.domain.service.SensitiveDataDetectionService;

import java.util.List;

/**
 * 检测 Stage —— 调用 {@link SensitiveDataDetectionService} 识别消息中的敏感数据片段。
 *
 * <p>使用场景：在管道中处于第二位（{@link BloomFilterStage} 之后），
 * 输出 {@link DetectionResult} 列表写入 {@link MaskingContext#setDetections}，
 * 供 {@link MaskingStage} 消费。
 *
 * @author log-anonymization
 */
public class DetectionStage extends AbstractPipelineStage {

    /** 敏感数据检测服务（领域服务的应用层代理） */
    private final SensitiveDataDetectionService detectionService;

    /**
     * 构造检测 Stage。
     *
     * @param detectionService 检测服务实例
     */
    public DetectionStage(SensitiveDataDetectionService detectionService) {
        this.detectionService = detectionService;
    }

    /**
     * 执行检测：
     * <ol>
     *   <li>调用 {@link SensitiveDataDetectionService#detect} 拿到所有命中</li>
     *   <li>写入 {@link MaskingContext#setDetections}</li>
     *   <li>若未命中，写入 {@code MaskingResult.unchanged} 短路</li>
     *   <li>命中则调用 {@link #processNext} 进入 MaskingStage</li>
     * </ol>
     *
     * @param context 脱敏上下文
     */
    @Override
    public void process(MaskingContext context) {
        List<DetectionResult> detections = detectionService.detect(context.logContext());
        context.setDetections(detections);
        if (detections.isEmpty()) {
            context.setResult(com.example.anonymization.api.model.MaskingResult.unchanged(context.message()));
            return;
        }
        processNext(context);
    }
}