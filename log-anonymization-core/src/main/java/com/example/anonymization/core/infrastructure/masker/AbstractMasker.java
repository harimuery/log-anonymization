package com.example.anonymization.core.infrastructure.masker;

import com.example.anonymization.api.model.MaskerConfig;
import com.example.anonymization.api.model.MaskingResult;
import com.example.anonymization.api.spi.SensitiveDataMasker;

/**
 * 抽象打码器（Abstract Masker）。
 *
 * <p>属于基础设施层（infrastructure/masker），是所有 {@link SensitiveDataMasker} 实现的模板基类，
 * 提供统一的"前置校验 + 模板方法 + 结果包装"骨架：
 * <ul>
 *   <li>{@link #mask(String, MaskerConfig)} 是 final 流程：空值短路、配置校验、调用 {@link #doMask}、包装 {@link MaskingResult}；</li>
 *   <li>{@link #doMask(String, MaskerConfig)} 是子类必须实现的"实际打码逻辑"；</li>
 *   <li>{@link #validateConfig(MaskerConfig)} 是可选的"配置合法性校验"钩子（默认空实现）。</li>
 * </ul>
 *
 * <p>设计意图：所有打码器的对外行为完全一致（返回 {@link MaskingResult}），
 * 上游 {@code MaskerRegistry} 可无差别路由，子类只需关注"把字符串变成脱敏字符串"。
 *
 * @author java-architect
 * @since 1.0.0
 */
public abstract class AbstractMasker implements SensitiveDataMasker {

    /**
     * 模板方法：对原始字符串执行打码并包装为 {@link MaskingResult}。
     *
     * <p>流程：
     * <ol>
     *   <li>空值短路：{@code original == null || original.isEmpty()} → 返回"未变化"结果；</li>
     *   <li>调用 {@link #validateConfig} 校验配置（子类可重写抛出 {@code IllegalArgumentException}）；</li>
     *   <li>调用 {@link #doMask} 执行实际打码；</li>
     *   <li>用 {@link MaskingResult#masked(String, String)} 包装（{@code isChanged = (original != masked)}）。</li>
     * </ol>
     *
     * @param original 原始字符串
     * @param config   打码配置
     * @return {@link MaskingResult}（{@code isChanged=true} 表示确实发生了打码）
     */
    @Override
    public MaskingResult mask(String original, MaskerConfig config) {
        if (original == null || original.isEmpty()) {
            return MaskingResult.masked(original, original);
        }
        validateConfig(config);
        String masked = doMask(original, config);
        return MaskingResult.masked(original, masked);
    }

    /**
     * 子类实现的实际打码逻辑。
     *
     * @param original 原始字符串（{@link #mask} 已保证非空）
     * @param config   打码配置
     * @return 脱敏后的字符串
     */
    protected abstract String doMask(String original, MaskerConfig config);

    /**
     * 配置合法性校验钩子（默认空实现）。
     *
     * <p>子类可重写该方法检查 {@code keepPrefixLen >= 0}、{@code algorithm != null} 等不变量；
     * 若不合法应抛出 {@code IllegalArgumentException}，由 {@link #mask} 透传给上层。
     *
     * @param config 待校验的打码配置
     */
    protected void validateConfig(MaskerConfig config) {}
}