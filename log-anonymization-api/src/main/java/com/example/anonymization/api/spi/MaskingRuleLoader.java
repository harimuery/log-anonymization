package com.example.anonymization.api.spi;

import com.example.anonymization.api.model.MaskingRule;

import java.util.List;
import java.util.function.Consumer;

/**
 * 规则加载器 SPI —— 抽象脱敏规则的来源（YAML、JSON、Nacos、Apollo、数据库等）。
 *
 * <p>使用场景：
 * <ul>
 *   <li>实现该接口加载规则列表（{@link #loadRules}）</li>
 *   <li>当远端配置变更时，主动通知所有已注册监听器（{@link #addChangeListener}）</li>
 * </ul>
 *
 * <p>核心实现：{@link com.example.anonymization.core.infrastructure.config.LocalFileRuleLoadAdapter}。
 *
 * @author log-anonymization
 */
public interface MaskingRuleLoader extends Comparable<MaskingRuleLoader> {

    /**
     * 同步加载当前生效的规则列表。
     *
     * <p>实现需保证：
     * <ul>
     *   <li>原子性：返回的列表是某个时间点的完整快照</li>
     *   <li>幂等性：重复调用结果一致（除非规则确实发生变化）</li>
     * </ul>
     *
     * @return 当前生效的脱敏规则列表
     */
    List<MaskingRule> loadRules();

    /**
     * 注册规则变更监听器。
     *
     * <p>实现需在规则文件/配置中心变更时主动回调所有监听器，
     * 由 {@link com.example.anonymization.core.domain.ThreadSafeRuleManager}
     * 完成无锁原子替换。
     *
     * @param listener 监听器，接收新的规则列表
     */
    void addChangeListener(Consumer<List<MaskingRule>> listener);

    /**
     * 获取规则来源标识（用于日志/审计，如 {@code "LOCAL_FILE"}、{@code "NACOS_PAYMENT"}）。
     *
     * @return 来源标识字符串
     */
    String getSource();

    /**
     * 获取加载器顺序（数值越小越先执行，默认 0）。
     *
     * <p>多 Loader 场景：用于确定规则合并的优先级顺序。
     *
     * @return 顺序值
     */
    default int getOrder() { return 0; }

    /**
     * 按 {@link #getOrder()} 升序比较。
     *
     * @param other 另一加载器
     * @return 排序结果
     */
    @Override
    default int compareTo(MaskingRuleLoader other) {
        return Integer.compare(this.getOrder(), other.getOrder());
    }
}