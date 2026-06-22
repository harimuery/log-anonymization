package com.example.anonymization.core.domain;

import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.spi.SensitiveDataDetector;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 检测器注册表 —— 以 {@link SensitiveDataType} 为键管理所有 {@link SensitiveDataDetector} 实例。
 *
 * <p>使用场景：应用启动时由 Spring 容器构造并注入所有 {@link SensitiveDataDetector} Bean，
 * 通过 {@link #getDetector} 按数据类型查找具体检测器，
 * 由 {@link com.example.anonymization.core.domain.service.DefaultSensitiveDataDetectionService}
 * 调用。
 *
 * <p>线程安全：内部使用 {@link ConcurrentHashMap}，支持运行期通过 {@link #register} 动态注册。
 *
 * @author log-anonymization
 */
public class DetectorRegistry {

    /** 类型 → 检测器映射（同类型后注册的会覆盖先注册的） */
    private final Map<SensitiveDataType, SensitiveDataDetector> detectorMap = new ConcurrentHashMap<>();

    /**
     * 构造注册表（一次性注入所有检测器）。
     *
     * <p>注册时通过 {@link SensitiveDataDetector#getSupportedType()} 作为 key。
     * 同一类型多个实现只会保留最后一个（后者覆盖）。
     *
     * @param detectors 检测器列表
     */
    public DetectorRegistry(List<SensitiveDataDetector> detectors) {
        detectors.forEach(d -> detectorMap.put(d.getSupportedType(), d));
    }

    /**
     * 按数据类型获取检测器。
     *
     * @param type 敏感数据类型
     * @return 检测器的 Optional 包装（未注册时为空，绝不返回 null）
     */
    public Optional<SensitiveDataDetector> getDetector(SensitiveDataType type) {
        return Optional.ofNullable(detectorMap.get(type));
    }

    /**
     * 运行期注册检测器（用于热加载自定义检测器）。
     *
     * @param detector 检测器实例
     */
    public void register(SensitiveDataDetector detector) {
        detectorMap.put(detector.getSupportedType(), detector);
    }

    /**
     * 判断指定类型是否已注册检测器。
     *
     * @param type 敏感数据类型
     * @return true 表示已注册
     */
    public boolean hasDetector(SensitiveDataType type) {
        return detectorMap.containsKey(type);
    }

    /**
     * 获取所有已注册检测器。
     *
     * @return 不可变副本列表
     */
    public List<SensitiveDataDetector> getAllDetectors() {
        return List.copyOf(detectorMap.values());
    }
}