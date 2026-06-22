package com.example.anonymization.core.infrastructure.filter;

import com.example.anonymization.api.model.MaskingRule;
import com.google.common.hash.BloomFilter;
import com.google.common.hash.Funnels;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * 敏感数据布隆过滤器（Sensitive Data Bloom Filter）。
 *
 * <p>属于基础设施层（infrastructure/filter），是一个快速"是否可能存在敏感数据"的预筛组件，
 * 主要用于 Pipeline 中的 {@link com.example.anonymization.core.application.pipeline.BloomFilterStage}，
 * 在进入正则匹配前先做一轮快速判断，命中失败直接跳过（避免对长文本做昂贵的 re2j 匹配）。
 *
 * <p>核心特性：
 * <ul>
 *   <li>底层为 Guava {@link BloomFilter}，容量 10000、误判率 1%；</li>
 *   <li>将规则中所有 {@code keywords} 与 {@code fieldNames} 放入过滤器；</li>
 *   <li>{@link #mightContainSensitiveData(String)} 对文本按空白/分隔符分词后逐个查询；</li>
 *   <li>重建（{@link #rebuild}）时通过 {@code volatile} 写替换，整体过程无锁。</li>
 * </ul>
 *
 * <p>注意：布隆过滤器存在约 1% 的误判率（即"明明没有却返回有"），
 * 业务上这意味着"最多多跑一次正则"，不会漏检真正的敏感数据。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class SensitiveDataBloomFilter {

    /**
     * 内部布隆过滤器实例。
     * 使用 {@code volatile} 保证多线程下"重建后立即可见"（无需加锁）。
     */
    private volatile BloomFilter<String> filter;

    /**
     * 构造默认布隆过滤器：容量 10000、误判率 1%。
     *
     * <p>实际生产建议在 {@link #rebuild} 后基于真实规则数量重新计算容量。
     */
    public SensitiveDataBloomFilter() {
        this.filter = BloomFilter.create(
            Funnels.stringFunnel(StandardCharsets.UTF_8), 10000, 0.01
        );
    }

    /**
     * 基于最新规则集合重建布隆过滤器。
     *
     * <p>容量策略：取 {@code max(10000, rules.size() * 10)} 作为期望插入数，
     * 防止规则数量增长后误判率飙升。
     * 将每条规则的 {@code keywords} 和 {@code fieldNames} 加入过滤器。
     *
     * <p>重建过程无锁：通过 {@code volatile} 写实现"整体替换"，旧过滤器仍可被并发线程使用直至其方法返回。
     *
     * @param rules 最新规则列表（通常来自 {@link com.example.anonymization.core.domain.ThreadSafeRuleManager}）
     */
    public void rebuild(List<MaskingRule> rules) {
        int expectedInsertions = Math.max(10000, rules.size() * 10);
        BloomFilter<String> newFilter = BloomFilter.create(
            Funnels.stringFunnel(StandardCharsets.UTF_8), expectedInsertions, 0.01
        );
        rules.forEach(rule -> {
            rule.getDetectorConfig().getKeywords().forEach(newFilter::put);
            rule.getDetectorConfig().getFieldNames().forEach(newFilter::put);
        });
        this.filter = newFilter;
    }

    /**
     * 判断给定的日志消息是否"可能"包含敏感数据。
     *
     * <p>算法：按空白/常见分隔符（{@code ,;:=(){}[]"' }）分词，对每个 token 查询布隆过滤器。
     * 任一 token 命中即返回 {@code true}；全部 miss 才返回 {@code false}。
     *
     * @param message 待检测的日志消息
     * @return {@code true} 表示"可能包含敏感数据"（建议继续走正则检测）；{@code false} 表示"几乎不可能包含"（可安全跳过）
     */
    public boolean mightContainSensitiveData(String message) {
        if (message == null || message.isEmpty()) return false;
        BloomFilter<String> current = this.filter;
        String[] tokens = message.split("[\\s,;:=\\{\\}\\[\\]\\(\\)\"']+");
        for (String token : tokens) {
            if (current.mightContain(token)) {
                return true;
            }
        }
        return false;
    }
}