package com.example.anonymization.core.domain;

import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.spi.SensitiveDataMasker;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 脱敏器注册表 —— 以 {@link MaskerType} 为键管理所有 {@link SensitiveDataMasker} 实例。
 *
 * <p>使用场景：应用启动时由 Spring 容器构造（详见
 * {@link com.example.anonymization.starter.LogAnonymizationAutoConfiguration#maskerRegistry}），
 * 通过 {@link #getMasker} 按算法类型查找具体脱敏器。
 *
 * <p>线程安全：使用 {@link ConcurrentHashMap} 实现无锁并发。
 *
 * @author log-anonymization
 */
public class MaskerRegistry {

    /** 算法类型 → 脱敏器映射 */
    private final Map<MaskerType, SensitiveDataMasker> maskerMap = new ConcurrentHashMap<>();

    /**
     * 构造注册表（一次性注入所有脱敏器）。
     *
     * @param maskers 脱敏器列表
     */
    public MaskerRegistry(List<SensitiveDataMasker> maskers) {
        maskers.forEach(m -> maskerMap.put(m.getMaskerType(), m));
    }

    /**
     * 按算法类型获取脱敏器。
     *
     * @param type 算法类型
     * @return 脱敏器的 Optional 包装
     */
    public Optional<SensitiveDataMasker> getMasker(MaskerType type) {
        return Optional.ofNullable(maskerMap.get(type));
    }

    /**
     * 运行期注册脱敏器（用于热加载自定义算法）。
     *
     * @param masker 脱敏器实例
     */
    public void register(SensitiveDataMasker masker) {
        maskerMap.put(masker.getMaskerType(), masker);
    }

    /**
     * 判断指定算法类型是否已注册。
     *
     * @param type 算法类型
     * @return true 表示已注册
     */
    public boolean hasMasker(MaskerType type) {
        return maskerMap.containsKey(type);
    }

    /**
     * 获取所有已注册脱敏器。
     *
     * @return 不可变副本列表
     */
    public List<SensitiveDataMasker> getAllMaskers() {
        return List.copyOf(maskerMap.values());
    }
}