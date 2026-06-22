package com.example.anonymization.core.infrastructure.masker;

import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.model.MaskerConfig;
import com.example.anonymization.api.model.MaskingResult;

/**
 * 丢弃型打码器（Discard Masker）。
 *
 * <p>属于基础设施层（infrastructure/masker），将敏感数据替换为空字符串（即"在日志中直接抹除"）。
 * 适用场景：
 * <ul>
 *   <li>极高敏感度字段（CVV、密码原文） —— 任何保留都可能泄漏；</li>
 *   <li>合规要求"不可逆脱敏 + 不可保留特征"的字段。</li>
 * </ul>
 *
 * <p>注意：本打码器不可逆（{@code isReversible = false}），下游无法还原原始值。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class DiscardMasker extends AbstractMasker {

    /**
     * 实际打码逻辑：永远返回空字符串。
     *
     * @param original 原始字符串（{@link AbstractMasker} 已保证非空）
     * @param config   打码配置（本类不使用）
     * @return 固定空字符串 {@code ""}
     */
    @Override
    protected String doMask(String original, MaskerConfig config) {
        return "";
    }

    /**
     * 当前打码器类型。
     *
     * @return {@link MaskerType#DISCARD}
     */
    @Override
    public MaskerType getMaskerType() { return MaskerType.DISCARD; }

    /**
     * 是否可逆。
     *
     * @return {@code false} 永远不可逆
     */
    @Override
    public boolean isReversible() { return false; }
}