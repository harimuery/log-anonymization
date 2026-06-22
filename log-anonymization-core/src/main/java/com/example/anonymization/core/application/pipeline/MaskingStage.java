package com.example.anonymization.core.application.pipeline;

import com.example.anonymization.api.model.MaskingContext;
import com.example.anonymization.api.model.MaskingResult;
import com.example.anonymization.core.domain.service.SensitiveDataMaskingService;

/**
 * 脱敏 Stage —— 调用 {@link SensitiveDataMaskingService} 执行真正的替换逻辑。
 *
 * <p>使用场景：在管道中处于第三位（{@link DetectionStage} 之后），
 * 根据检测结果将原文中的敏感片段替换为脱敏后的字符串。
 *
 * @author log-anonymization
 */
public class MaskingStage extends AbstractPipelineStage {

    /** 敏感数据脱敏服务 */
    private final SensitiveDataMaskingService maskingService;

    /**
     * 构造脱敏 Stage。
     *
     * @param maskingService 脱敏服务实例
     */
    public MaskingStage(SensitiveDataMaskingService maskingService) {
        this.maskingService = maskingService;
    }

    /**
     * 执行脱敏：
     * <ol>
     *   <li>从 context 取出 detections（由 {@link DetectionStage} 写入）</li>
     *   <li>调用 {@link SensitiveDataMaskingService#mask} 执行替换</li>
     *   <li>写入 {@link MaskingContext#setResult}</li>
     *   <li>调用 {@link #processNext} 进入 {@link AuditStage}</li>
     * </ol>
     *
     * @param context 脱敏上下文
     */
    @Override
    public void process(MaskingContext context) {
        MaskingResult result = maskingService.mask(context.message(), context.detections());
        context.setResult(result);
        processNext(context);
    }
}