package com.example.anonymization.api.spi;

import com.example.anonymization.api.model.MaskerConfig;
import com.example.anonymization.api.model.MaskingResult;
import com.example.anonymization.api.enums.MaskerType;

/**
 * 敏感数据脱敏器 SPI —— 抽象对单个敏感数据值执行脱敏变换的算法实现。
 *
 * <p>使用场景：业务方按需实现该接口（继承
 * {@link com.example.anonymization.core.infrastructure.masker.AbstractMasker}
 * 可复用输入校验与标准结果封装），并通过
 * {@link com.example.anonymization.core.infrastructure.masker.MaskerFactory} 注册。
 *
 * <p>注意：本 SPI 一次只处理单个字符串值（如卡号），不负责在原文中定位/替换；
 * 定位由检测器完成，替换由 {@link com.example.anonymization.core.domain.service.DefaultSensitiveDataMaskingService}
 * 统一调度。
 *
 * @author log-anonymization
 */
public interface SensitiveDataMasker extends Comparable<SensitiveDataMasker> {

    /**
     * 执行脱敏：将原始字符串按配置变换为脱敏后字符串。
     *
     * <p>实现必须遵守的安全铁律（PCI DSS/个人信息保护法）：
     * <ul>
     *   <li>任何异常情况均不允许直接返回原始明文</li>
     *   <li>不可逆算法（如 SHA-256）应使用盐防止彩虹表攻击</li>
     *   <li>对于 CVV 等禁存数据应返回空字符串而非占位符</li>
     * </ul>
     *
     * @param original 待脱敏的原始字符串（如银行卡号、手机号）
     * @param config   脱敏算法配置（保留位数、掩码字符、盐源等）
     * @return 脱敏结果（包含原始值、脱敏值、动作标记、降级标记）
     */
    MaskingResult mask(String original, MaskerConfig config);

    /**
     * 获取本脱敏器对应的算法类型（用于工厂查找）。
     *
     * @return 算法类型枚举值
     */
    MaskerType getMaskerType();

    /**
     * 是否可逆脱敏（如 AES-256-GCM 是可逆的，SHA-256 是不可逆的）。
     *
     * <p>仅在需要"还原"原始值进行故障排查或合规审计时使用可逆算法。
     *
     * @return true 表示可逆
     */
    boolean isReversible();

    /**
     * 获取执行顺序（数值越小越先执行，默认 0）。
     *
     * @return 顺序值
     */
    default int getOrder() { return 0; }

    /**
     * 按 {@link #getOrder()} 升序比较。
     *
     * @param other 另一脱敏器
     * @return 排序结果
     */
    @Override
    default int compareTo(SensitiveDataMasker other) {
        return Integer.compare(this.getOrder(), other.getOrder());
    }
}