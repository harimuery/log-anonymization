package com.example.anonymization.core.infrastructure.config;

import com.example.anonymization.api.model.MaskingRule;
import com.example.anonymization.api.port.RuleLoadPort;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * 本地文件规则加载适配器 —— {@link RuleLoadPort} 的简化实现。
 *
 * <p>使用场景：作为骨架实现存在，业务方通常会被基于 Nacos/Apollo 的实现替换。
 * 当前实现仅保留接口契约与监听器注册能力，{@link #loadRules} 返回空列表。
 *
 * <p>后续演进：可重写 {@link #loadRules} 解析 YAML/Properties 文件，
 * 并在文件变更（{@code WatchService}）时主动回调监听器，实现规则热更新。
 *
 * @author log-anonymization
 */
public class LocalFileRuleLoadAdapter implements RuleLoadPort {

    /** 规则文件路径（classpath: 或 file:） */
    private final String filePath;
    /** 规则变更监听器列表（按注册顺序执行） */
    private final List<Consumer<List<MaskingRule>>> listeners = new ArrayList<>();

    /**
     * 构造本地文件规则加载器。
     *
     * @param filePath 规则文件路径
     */
    public LocalFileRuleLoadAdapter(String filePath) {
        this.filePath = filePath;
    }

    /**
     * 同步加载规则列表。
     *
     * <p>当前骨架实现返回空列表；业务方需重写此方法以解析实际规则文件。
     *
     * @return 规则列表（当前为空）
     */
    @Override
    public List<MaskingRule> loadRules() {
        return List.of();
    }

    /**
     * 注册规则变更监听器。
     *
     * <p>当文件/配置中心变更时，回调所有监听器，
     * 由 {@link com.example.anonymization.core.domain.ThreadSafeRuleManager}
     * 完成原子替换。
     *
     * @param listener 变更监听器
     */
    @Override
    public void onRuleChange(Consumer<List<MaskingRule>> listener) {
        listeners.add(listener);
    }
}