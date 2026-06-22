package com.example.anonymization.core.infrastructure.masker;

import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.model.MaskerConfig;
import com.example.anonymization.api.model.MaskingResult;
import com.example.anonymization.api.spi.SensitiveDataMasker;

import java.util.Map;

/**
 * 降级打码器（Fallback Masker）。
 *
 * <p>属于基础设施层（infrastructure/masker），提供两类降级打码：
 * <ul>
 *   <li>按数据类型给出固定占位符（如银行卡 → {@code ****DEGRADED****}），用于熔断或异常时的最终兜底；</li>
 *   <li>提供 {@link #fallbackMask} 工具方法，由 {@link ResilientMaskingEngine} 在熔断时调用。</li>
 * </ul>
 *
 * <p>与 {@link DiscardMasker} 的差异：本类保留了一定的"类型可识别性"，便于排障人员判断"这里本来是哪种敏感字段"。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class FallbackMasker implements SensitiveDataMasker {

    private static final Map<SensitiveDataType, String> FALLBACK_MAP = Map.of(
        SensitiveDataType.BANK_CARD, "****DEGRADED****",
        SensitiveDataType.ID_CARD, "***ID_DEGRADED***",
        SensitiveDataType.PHONE, "***PHONE_DEGRADED***",
        SensitiveDataType.EMAIL, "***EMAIL_DEGRADED***",
        SensitiveDataType.NAME, "**NAME_DEGRADED**",
        SensitiveDataType.PASSWORD, "********",
        SensitiveDataType.CVV, "",
        SensitiveDataType.IP_ADDRESS, "***.***.***.***"
    );

    /**
     * 通用打码入口：依据 {@link MaskerConfig#getDataType()} 查表返回占位符，未命中默认 {@code ***MASKED***}。
     *
     * @param original 原始字符串（不使用）
     * @param config   打码配置，必须包含 {@code dataType}
     * @return {@link MaskingResult#degraded}（{@code isDegraded=true}）
     */
    @Override
    public MaskingResult mask(String original, MaskerConfig config) {
        SensitiveDataType type = config.getDataType();
        String fallback = FALLBACK_MAP.getOrDefault(type, "***MASKED***");
        return MaskingResult.degraded(original, fallback);
    }

    /**
     * 熔断降级专用入口：由 {@link ResilientMaskingEngine} 在下游异常或熔断打开时调用，
     * 直接将整条消息标记为降级（不区分具体数据类型）。
     *
     * @param message  原始消息
     * @param context  日志上下文（不使用，预留扩展点）
     * @return {@link MaskingResult#degraded}，{@code masked = "***DEGRADED***"}
     */
    public MaskingResult fallbackMask(String message, com.example.anonymization.api.model.LogContext context) {
        return MaskingResult.degraded(message, "***DEGRADED***");
    }

    /**
     * 当前打码器类型。
     *
     * @return {@link MaskerType#FALLBACK}
     */
    @Override
    public MaskerType getMaskerType() { return MaskerType.FALLBACK; }

    /**
     * 是否可逆。
     *
     * @return {@code false} 永远不可逆
     */
    @Override
    public boolean isReversible() { return false; }
}