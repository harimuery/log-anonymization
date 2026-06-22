package com.example.anonymization.api.port;

import com.example.anonymization.api.model.MaskingRule;

import java.util.List;
import java.util.function.Consumer;

/**
 * 规则加载端口 —— 抽象脱敏规则的来源（本地文件、Nacos、Apollo、DB 等）与变更通知。
 *
 * <p>使用场景：
 * <ul>
 *   <li>启动期通过 {@link #loadRules} 加载首批规则</li>
 *   <li>运行期通过 {@link #onRuleChange} 注册回调，实现配置热更新（无需重启服务）</li>
 * </ul>
 *
 * <p>实现包括 {@link com.example.anonymization.core.infrastructure.config.LocalFileRuleLoadAdapter}，
 * 业务方可实现基于 Nacos/Apollo 的版本。
 *
 * @author log-anonymization
 */
public interface RuleLoadPort {
    /**
     * 同步加载当前生效的规则列表。
     *
     * <p>注意：调用方应缓存或周期性加载，避免每次请求都触发磁盘/网络 IO。
     *
     * @return 当前生效的脱敏规则列表
     */
    List<MaskingRule> loadRules();

    /**
     * 注册规则变更监听器。
     *
     * <p>当配置中心或文件变更时，实现需主动回调所有已注册的 listener，
     * 由 {@link com.example.anonymization.core.domain.ThreadSafeRuleManager#refreshRules}
     * 完成原子替换。
     *
     * @param listener 变更监听器，接收新的规则列表
     */
    void onRuleChange(Consumer<List<MaskingRule>> listener);
}