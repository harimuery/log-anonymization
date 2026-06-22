package com.example.anonymization.core.domain;

import com.example.anonymization.api.model.MaskingRule;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.Comparator;

/**
 * 线程安全规则管理器 —— 基于 {@link AtomicReference} 提供无锁的规则列表原子替换。
 *
 * <p>使用场景：被
 * {@link com.example.anonymization.core.domain.service.DefaultRuleMatchService}
 * 通过 {@link #getCurrentRules} 读取最新规则，
 * 由 {@link com.example.anonymization.core.infrastructure.config.LocalFileRuleLoadAdapter}
 * 或其它 {@link com.example.anonymization.api.spi.MaskingRuleLoader} 在配置变更时回调
 * {@link #refreshRules} 完成热更新。
 *
 * <p>线程安全：通过 {@link AtomicReference} 的 volatile 语义保证多线程可见性，
 * 配合不可变 List 实现零拷贝快照读取。
 *
 * @author log-anonymization
 */
public class ThreadSafeRuleManager {

    /** 规则引用（volatile 语义保证多线程可见性） */
    private final AtomicReference<List<MaskingRule>> rulesRef =
        new AtomicReference<>(Collections.emptyList());

    /**
     * 刷新规则（原子替换）。
     *
     * <p>流程：
     * <ol>
     *   <li>过滤掉 {@code enabled=false} 的规则</li>
     *   <li>按 priority 降序排序（数值大的在前）</li>
     *   <li>封装为不可变 List 后通过 {@link AtomicReference#set} 原子替换</li>
     * </ol>
     *
     * <p>并发安全保证：{@link AtomicReference#set} 提供 happens-before 语义，
     * 其它线程通过 {@link #getCurrentRules} 立即看到新规则。
     *
     * @param newRules 新规则列表（包含启用与禁用两种状态，内部会过滤）
     */
    public void refreshRules(List<MaskingRule> newRules) {
        List<MaskingRule> sortedRules = newRules.stream()
            .filter(MaskingRule::isEnabled)
            .sorted(Comparator.comparingInt(MaskingRule::getPriority).reversed())
            .toList();
        rulesRef.set(Collections.unmodifiableList(sortedRules));
    }

    /**
     * 获取当前生效的规则列表（按优先级降序，不可变）。
     *
     * <p>无锁读取，性能极高，适合在热路径（每条日志的检测阶段）反复调用。
     *
     * @return 不可变规则列表（空列表而非 null）
     */
    public List<MaskingRule> getCurrentRules() {
        return rulesRef.get();
    }
}