package com.example.anonymization.core.infrastructure.config;

import com.alibaba.nacos.api.NacosFactory;
import com.alibaba.nacos.api.config.ConfigService;
import com.alibaba.nacos.api.config.listener.Listener;
import com.alibaba.nacos.api.exception.NacosException;
import com.example.anonymization.api.model.MaskingRule;
import com.example.anonymization.api.port.RuleLoadPort;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.Executor;
import java.util.function.Consumer;

/**
 * Nacos 配置中心规则加载适配器 —— {@link RuleLoadPort} 的 Nacos 实现。
 *
 * <p>属于基础设施层（infrastructure/config），实现从 Nacos 配置中心加载脱敏规则，
 * 并通过 Nacos Listener 机制实现规则动态刷新（Observer 模式）。
 *
 * <p>设计要点：
 * <ul>
 *   <li>启动时通过 {@link ConfigService#getConfig} 同步拉取初始规则；</li>
 *   <li>注册 {@link Listener} 监听配置变更，变更时回调所有已注册的 {@code Consumer}；</li>
 *   <li>YAML 解析委托给 {@link YamlRuleParser}，与 {@link LocalFileRuleLoadAdapter} 共享解析逻辑；</li>
 *   <li>ConfigService 实例在构造时创建并缓存，整个生命周期复用。</li>
 * </ul>
 *
 * <p>动态刷新时序：
 * <pre>
 *   Nacos Server 推送配置变更
 *     → Listener.receiveConfigInfo
 *       → YamlRuleParser.parse
 *         → 逐个回调 Consumer<List<MaskingRule>>
 *           → ThreadSafeRuleManager.refreshRules（原子替换）
 *             → SensitiveDataBloomFilter.rebuild
 * </pre>
 *
 * @author log-anonymization
 * @since 1.0.0
 */
public class NacosRuleLoadAdapter implements RuleLoadPort {

    private final String serverAddr;
    private final String dataId;
    private final String group;
    private final ConfigService configService;
    private final YamlRuleParser yamlRuleParser;
    private final List<Consumer<List<MaskingRule>>> listeners = new ArrayList<>();

    /**
     * 构造 Nacos 规则加载器。
     *
     * @param serverAddr Nacos 服务器地址（host:port）
     * @param dataId     配置 Data ID
     * @param group      配置 Group
     */
    public NacosRuleLoadAdapter(String serverAddr, String dataId, String group) {
        this.serverAddr = serverAddr;
        this.dataId = dataId;
        this.group = group;
        this.yamlRuleParser = new YamlRuleParser();
        this.configService = createConfigService();
    }

    /**
     * 从 Nacos 同步加载规则列表。
     *
     * <p>首次调用时获取配置内容并解析为 {@link MaskingRule} 列表。
     * 若 Nacos 不可用或配置不存在，返回空列表（不抛异常，保证启动不阻塞）。
     *
     * @return 规则列表
     */
    @Override
    public List<MaskingRule> loadRules() {
        try {
            String content = configService.getConfig(dataId, group, 5000);
            if (content == null || content.isBlank()) {
                return List.of();
            }
            return yamlRuleParser.parse(content);
        } catch (NacosException e) {
            return List.of();
        }
    }

    /**
     * 注册规则变更监听器。
     *
     * <p>当 Nacos 推送配置变更时，自动解析新配置并回调所有监听器。
     * 监听器通常为 {@link com.example.anonymization.core.domain.ThreadSafeRuleManager#refreshRules}。
     *
     * @param listener 变更监听器
     */
    @Override
    public void onRuleChange(Consumer<List<MaskingRule>> listener) {
        listeners.add(listener);
        if (listeners.size() == 1) {
            registerNacosListener();
        }
    }

    /**
     * 注册 Nacos 配置变更监听器（仅注册一次）。
     *
     * <p>使用 Nacos 的 {@link ConfigService#addListener} 注册异步监听器，
     * 配置变更时在 Nacos 回调线程中解析并通知。
     */
    private void registerNacosListener() {
        try {
            configService.addListener(dataId, group, new Listener() {
                @Override
                public Executor getExecutor() {
                    return null;
                }

                @Override
                public void receiveConfigInfo(String configInfo) {
                    if (configInfo == null || configInfo.isBlank()) {
                        return;
                    }
                    List<MaskingRule> newRules = yamlRuleParser.parse(configInfo);
                    for (Consumer<List<MaskingRule>> listener : listeners) {
                        listener.accept(newRules);
                    }
                }
            });
        } catch (NacosException e) {
            throw new RuntimeException("注册 Nacos 配置监听器失败: " + e.getMessage(), e);
        }
    }

    /**
     * 创建 Nacos ConfigService 实例。
     *
     * @return ConfigService 实例
     */
    private ConfigService createConfigService() {
        try {
            Properties properties = new Properties();
            properties.put("serverAddr", serverAddr);
            return NacosFactory.createConfigService(properties);
        } catch (NacosException e) {
            throw new RuntimeException("创建 Nacos ConfigService 失败: " + e.getMessage(), e);
        }
    }
}