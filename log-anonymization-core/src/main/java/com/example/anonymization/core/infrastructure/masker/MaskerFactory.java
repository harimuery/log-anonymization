package com.example.anonymization.core.infrastructure.masker;

import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.spi.SensitiveDataMasker;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * 打码器工厂（Masker Factory）。
 *
 * <p>属于基础设施层（infrastructure/masker），是打码器的注册中心与工厂入口，
 * 以 {@link MaskerType} 为 Key 维护 {@link SensitiveDataMasker} 映射，
 * 上游 {@code SensitiveDataMaskingService} 通过 {@link #create} 按类型获取具体打码器。
 *
 * <p>使用示例：
 * <pre>
 *   MaskerFactory factory = new MaskerFactory(List.of(
 *       new PartialMaskMasker(),
 *       new FullMaskMasker(),
 *       new HashMasker("salt")
 *   ));
 *   SensitiveDataMasker masker = factory.create(MaskerType.PARTIAL_MASK);
 *   MaskingResult result = masker.mask("6222021234567890", config);
 * </pre>
 *
 * @author java-architect
 * @since 1.0.0
 */
public class MaskerFactory {

    /**
     * {@link MaskerType} → {@link SensitiveDataMasker} 映射表。
     * 使用 {@link EnumMap} 保证枚举键访问为 O(1)，且迭代顺序稳定。
     */
    private final Map<MaskerType, SensitiveDataMasker> registry = new EnumMap<>(MaskerType.class);

    /**
     * 构造打码器工厂。
     *
     * <p>同类型重复传入时，后者覆盖前者（业务上不应出现此场景）。
     *
     * @param maskers 全部打码器列表，不可为 {@code null}；每个打码器的 {@link SensitiveDataMasker#getMaskerType()} 必须唯一
     */
    public MaskerFactory(List<SensitiveDataMasker> maskers) {
        maskers.forEach(m -> registry.put(m.getMaskerType(), m));
    }

    /**
     * 按类型获取打码器。
     *
     * @param type 打码器类型（{@link MaskerType}）
     * @return 已注册的打码器
     * @throws IllegalArgumentException 当指定类型未注册时抛出（典型场景：配置中引用了未实现的类型）
     */
    public SensitiveDataMasker create(MaskerType type) {
        SensitiveDataMasker masker = registry.get(type);
        if (masker == null) {
            throw new IllegalArgumentException("No masker implementation found for: " + type);
        }
        return masker;
    }
}