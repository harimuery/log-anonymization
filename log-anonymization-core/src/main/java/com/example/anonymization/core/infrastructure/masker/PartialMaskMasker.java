package com.example.anonymization.core.infrastructure.masker;

import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.model.MaskerConfig;

/**
 * 部分打码器（Partial Mask Masker）。
 *
 * <p>属于基础设施层（infrastructure/masker），保留字符串的首 {@code keepPrefixLen} 字符与尾 {@code keepSuffixLen} 字符，
 * 中间替换为 {@link MaskerConfig#getMaskChar()}。
 * 这是支付/金融行业最常见的脱敏策略，如：
 * <ul>
 *   <li>银行卡：{@code 6222 **** **** 1234}（前 4 + 后 4）；</li>
 *   <li>手机号：{@code 138 **** 1234}（前 3 + 后 4）；</li>
 *   <li>身份证：{@code 110 ************ 0023}（前 3 + 后 4）。</li>
 * </ul>
 *
 * <p>边界处理：当 {@code prefix + suffix >= length} 时退化为 {@link FullMaskMasker} 行为（全掩码）。
 *
 * <p>不可逆（{@code isReversible = false}）。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class PartialMaskMasker extends AbstractMasker {

    /**
     * 实际打码逻辑：{@code original[0..prefix] + maskChar.repeat(maskLen) + original[length-suffix..length]}。
     *
     * @param original 原始字符串
     * @param config   打码配置，使用 {@link MaskerConfig#getKeepPrefixLen()} / {@link MaskerConfig#getKeepSuffixLen()} / {@link MaskerConfig#getMaskChar()}
     * @return 部分掩码字符串；{@code prefix + suffix >= length} 时退化为全掩码
     */
    @Override
    protected String doMask(String original, MaskerConfig config) {
        int prefix = config.getKeepPrefixLen();
        int suffix = config.getKeepSuffixLen();
        char maskChar = config.getMaskChar();
        int maskLen = original.length() - prefix - suffix;
        if (maskLen <= 0) {
            return String.valueOf(maskChar).repeat(original.length());
        }
        return original.substring(0, prefix)
            + String.valueOf(maskChar).repeat(maskLen)
            + original.substring(original.length() - suffix);
    }

    /**
     * 当前打码器类型。
     *
     * @return {@link MaskerType#PARTIAL_MASK}
     */
    @Override
    public MaskerType getMaskerType() { return MaskerType.PARTIAL_MASK; }

    /**
     * 是否可逆。
     *
     * @return {@code false}
     */
    @Override
    public boolean isReversible() { return false; }
}