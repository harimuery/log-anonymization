package com.example.anonymization.core.infrastructure.masker;

import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.model.MaskerConfig;

/**
 * 全量打码器（Full Mask Masker）。
 *
 * <p>属于基础设施层（infrastructure/masker），将整段字符串替换为同样长度的 {@link MaskerConfig#getMaskChar()}。
 * 适用场景：
 * <ul>
 *   <li>用户昵称、地址等"保留格式没意义"的字段；</li>
 *   <li>对脱敏强度要求极高，不允许泄漏"原始长度"以外的任何信息（本打码器仅保留长度，{@link PartialMaskMasker} 会保留首尾）。</li>
 * </ul>
 *
 * <p>不可逆（{@code isReversible = false}）。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class FullMaskMasker extends AbstractMasker {

    /**
     * 实际打码逻辑：生成 {@code maskChar.repeat(original.length())}。
     *
     * @param original 原始字符串
     * @param config   打码配置，使用 {@link MaskerConfig#getMaskChar()}
     * @return 等长全掩码字符串
     */
    @Override
    protected String doMask(String original, MaskerConfig config) {
        return String.valueOf(config.getMaskChar()).repeat(original.length());
    }

    /**
     * 当前打码器类型。
     *
     * @return {@link MaskerType#FULL_MASK}
     */
    @Override
    public MaskerType getMaskerType() { return MaskerType.FULL_MASK; }

    /**
     * 是否可逆。
     *
     * @return {@code false}
     */
    @Override
    public boolean isReversible() { return false; }
}