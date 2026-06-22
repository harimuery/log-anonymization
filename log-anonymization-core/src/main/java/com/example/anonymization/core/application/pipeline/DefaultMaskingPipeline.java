package com.example.anonymization.core.application.pipeline;

import com.example.anonymization.api.model.MaskingContext;
import com.example.anonymization.api.model.MaskingResult;

import java.util.List;

/**
 * 默认脱敏管道 —— 按顺序链接并执行一组 Stage 的编排器。
 *
 * <p>使用场景：在 {@link com.example.anonymization.core.application.MaskingApplicationService}
 * 中作为依赖被注入；典型阶段顺序：BloomFilter → Detection → Masking → Audit。
 *
 * @author log-anonymization
 */
public class DefaultMaskingPipeline {

    /** 链头 Stage（入口） */
    private final PipelineStage head;

    /**
     * 构造管道并链接所有 Stage。
     *
     * <p>阶段链接通过循环调用 {@code ((AbstractPipelineStage) stages.get(i)).setNext(stages.get(i+1))} 完成，
     * 形成一条单向责任链。
     *
     * @param stages 阶段列表（按执行顺序），不能为空
     * @throws IllegalArgumentException 当 stages 为 null 或空时抛出
     */
    public DefaultMaskingPipeline(List<PipelineStage> stages) {
        if (stages == null || stages.isEmpty()) {
            throw new IllegalArgumentException("Pipeline stages must not be empty");
        }
        for (int i = 0; i < stages.size() - 1; i++) {
            ((AbstractPipelineStage) stages.get(i)).setNext(stages.get(i + 1));
        }
        this.head = stages.get(0);
    }

    /**
     * 同步执行完整管道。
     *
     * <p>调用链头开始处理，依次触发后续 Stage，最终从 {@link MaskingContext#result()} 读取结果。
     *
     * @param context 脱敏上下文（会被各 Stage 修改并最终携带 MaskingResult）
     * @return 脱敏结果（来自 context.result()）
     */
    public MaskingResult execute(MaskingContext context) {
        head.process(context);
        return context.result();
    }
}