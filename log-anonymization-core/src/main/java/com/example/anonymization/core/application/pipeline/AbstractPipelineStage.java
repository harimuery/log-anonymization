package com.example.anonymization.core.application.pipeline;

import com.example.anonymization.api.model.MaskingContext;

/**
 * 管道阶段抽象基类 —— 提供后继 Stage 的引用与向下游传递的 {@code processNext} 能力。
 *
 * <p>使用场景：所有内置 Stage（BloomFilter/Detection/Masking/Audit）继承本类，
 * 由 {@link DefaultMaskingPipeline} 在构造时通过 {@link #setNext} 链接成链。
 *
 * <p>设计意图：避免每个 Stage 重复维护 {@code next} 字段与判空逻辑。
 *
 * @author log-anonymization
 */
public abstract class AbstractPipelineStage implements PipelineStage {

    /** 后继 Stage 引用（在 {@link DefaultMaskingPipeline} 构造时通过 {@link #setNext} 注入） */
    private PipelineStage next;

    /**
     * 注入后继 Stage（由 {@link DefaultMaskingPipeline} 在构造时调用）。
     *
     * @param next 后继 Stage 实例
     */
    public void setNext(PipelineStage next) {
        this.next = next;
    }

    /**
     * 触发后继 Stage 执行（供子类在自身逻辑完成后调用）。
     *
     * <p>若 {@link #setNext} 未注入（即当前是链尾），则本方法为 no-op，不会抛 NPE。
     *
     * @param context 脱敏上下文
     */
    protected void processNext(MaskingContext context) {
        if (next != null) {
            next.process(context);
        }
    }
}