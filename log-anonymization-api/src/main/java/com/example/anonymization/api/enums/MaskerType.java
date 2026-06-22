package com.example.anonymization.api.enums;

/**
 * 脱敏算法类型枚举 —— 定义可插拔的脱敏策略分类。
 *
 * <p>每种类型对应 {@code core.infrastructure.masker} 包下的具体实现类，
 * 通过 {@link com.example.anonymization.core.infrastructure.masker.MaskerFactory}
 * 按类型获取执行器。
 *
 * <p>使用场景：在 {@link com.example.anonymization.api.model.MaskingRule}
 * 中声明一条规则应采用哪种脱敏算法。
 *
 * @author log-anonymization
 */
public enum MaskerType {
    /** 部分遮盖（保留首尾 N 位，中间用 * 填充，常用于手机号、身份证号） */
    PARTIAL_MASK,
    /** 完全遮盖（全部替换为 *，用于不需要识别的场景） */
    FULL_MASK,
    /** 直接丢弃（PCI DSS 要求 CVV 等敏感认证数据完全不可留存） */
    DISCARD,
    /** 不可逆哈希（SHA-256 + 盐，用于密码等需脱敏但可关联的场景） */
    HASH,
    /** 泛化（如 IP 段保留、金额区间化） */
    GENERALIZE,
    /** 降级占位（脱敏组件异常时使用，避免输出原始明文） */
    FALLBACK,
    /** 自定义脱敏器，由用户通过 {@link com.example.anonymization.api.spi.SensitiveDataMasker} SPI 扩展 */
    CUSTOM
}