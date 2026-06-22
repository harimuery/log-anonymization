package com.example.anonymization.core.application.pipeline;

import com.example.anonymization.api.model.MaskingContext;

/**
 * 管道阶段接口 —— 责任链（Chain of Responsibility）模式的标准抽象。
 *
 * <p>使用场景：脱敏管道由若干 Stage 串成责任链，每个 Stage 处理自己关心的职责
 * （如 {@link BloomFilterStage} 负责快速跳过、{@link DetectionStage} 负责识别、
 * {@link MaskingStage} 负责替换、{@link AuditStage} 负责审计）。
 *
 * <p>典型调用链：BloomFilter → Detection → Masking → Audit，
 * 每个 Stage 都可以决定是否调用 {@code processNext} 进入下一阶段，
 * 也可设置 {@link MaskingContext#setResult} 终止链路（如未命中检测时短路）。
 *
 * @author log-anonymization
 */
public interface PipelineStage {
    /**
     * 执行本阶段的处理逻辑。
     *
     * <p>实现约定：
     * <ul>
     *   <li>无修改时无需继续后续 Stage（可短路）</li>
     *   <li>修改 {@link MaskingContext} 时应使用其 setter，保证不可变性约束</li>
     *   <li>异常不应直接抛出，应降级或转为结果对象，避免污染业务日志</li>
     * </ul>
     *
     * @param context 脱敏上下文（在各 Stage 间共享状态）
     */
    void process(MaskingContext context);
}