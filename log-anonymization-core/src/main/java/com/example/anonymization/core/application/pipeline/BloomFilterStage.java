package com.example.anonymization.core.application.pipeline;

import com.example.anonymization.api.model.MaskingContext;
import com.example.anonymization.core.infrastructure.filter.SensitiveDataBloomFilter;

/**
 * BloomFilter 预筛 Stage —— 通过布隆过滤器快速跳过不含敏感关键词的消息，避免昂贵正则开销。
 *
 * <p>使用场景：作为管道的第一站（{@link DefaultMaskingPipeline} 中 stages[0]）。
 * 据线上统计可屏蔽 80% 以上的"无敏感数据"日志，对 TPS 提升显著。
 *
 * <p>短路逻辑：当 BloomFilter 判断不含任何敏感关键词/字段名时，
 * 直接在 context 上写入 {@code MaskingResult.unchanged(...)} 终止管道，
 * 跳过后续 Detection/Masking/Audit Stage。
 *
 * @author log-anonymization
 */
public class BloomFilterStage extends AbstractPipelineStage {

    /** 敏感数据布隆过滤器（{@link SensitiveDataBloomFilter} 单例，规则刷新时重建） */
    private final SensitiveDataBloomFilter bloomFilter;

    /**
     * 构造 BloomFilter 预筛 Stage。
     *
     * @param bloomFilter 布隆过滤器实例
     */
    public BloomFilterStage(SensitiveDataBloomFilter bloomFilter) {
        this.bloomFilter = bloomFilter;
    }

    /**
     * 执行 BloomFilter 预筛：
     * <ol>
     *   <li>调用 {@link SensitiveDataBloomFilter#mightContainSensitiveData} 判断是否可能包含敏感数据</li>
     *   <li>若判断为 false，写入 {@code MaskingResult.unchanged} 并 return（短路）</li>
     *   <li>否则调用 {@link #processNext} 进入后续 Stage</li>
     * </ol>
     *
     * @param context 脱敏上下文
     */
    @Override
    public void process(MaskingContext context) {
        if (!bloomFilter.mightContainSensitiveData(context.message())) {
            context.setResult(com.example.anonymization.api.model.MaskingResult.unchanged(context.message()));
            return;
        }
        processNext(context);
    }
}