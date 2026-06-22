package com.example.anonymization.api.model;

import com.example.anonymization.api.enums.MaskingAction;

/**
 * 脱敏结果 —— 一条日志经过脱敏管道处理后的最终输出。
 *
 * <p>使用场景：由 {@link com.example.anonymization.core.application.pipeline.MaskingStage}
 * 写入到 {@link MaskingContext}，并通过 {@link com.example.anonymization.api.port.MaskingPort#process}
 * 返回给日志框架的 Converter，最终替换日志输出。
 *
 * <p>不可变：通过静态工厂方法构造（如 {@link #masked}、{@link #degraded}、{@link #unchanged}、{@link #failed}），
 * 杜绝运行期修改导致的状态不一致问题。
 *
 * @author log-anonymization
 */
public final class MaskingResult {

    /** 原始消息（保留用于审计对比） */
    private final String original;
    /** 脱敏后消息（最终输出到日志文件） */
    private final String masked;
    /** 是否发生修改（false = 跳过，未触发规则） */
    private final boolean changed;
    /** 实际脱敏动作 */
    private final MaskingAction action;
    /** 是否处于降级状态（true = 输出的是占位符，需告警） */
    private final boolean degraded;

    /**
     * 私有构造器 —— 仅供静态工厂调用。
     *
     * @param original 原始消息
     * @param masked   脱敏后消息
     * @param changed  是否修改
     * @param action   脱敏动作
     * @param degraded 是否降级
     */
    private MaskingResult(String original, String masked, boolean changed,
                          MaskingAction action, boolean degraded) {
        this.original = original;
        this.masked = masked;
        this.changed = changed;
        this.action = action;
        this.degraded = degraded;
    }

    /**
     * 创建"未修改"结果 —— 当 BloomFilter 预筛或检测器未命中时返回。
     *
     * <p>该结果会被 {@link com.example.anonymization.core.application.pipeline.AuditStage}
     * 跳过，避免无意义的审计记录。
     *
     * @param message 原始消息（保持原样输出）
     * @return 标记为 SKIPPED 的不可变结果
     */
    public static MaskingResult unchanged(String message) {
        return new MaskingResult(message, message, false, MaskingAction.SKIPPED, false);
    }

    /**
     * 创建"已脱敏"结果 —— 正常命中规则并完成脱敏时返回。
     *
     * @param original 原始消息
     * @param masked   脱敏后消息
     * @return 标记为 MASKED 的不可变结果
     */
    public static MaskingResult masked(String original, String masked) {
        return new MaskingResult(original, masked, true, MaskingAction.MASKED, false);
    }

    /**
     * 创建"降级"结果 —— 熔断器开启或算法异常时输出占位符，避免明文泄露。
     *
     * @param original 原始消息（保留用于审计）
     * @param fallback 占位符字符串
     * @return 标记为 DEGRADED 的不可变结果
     */
    public static MaskingResult degraded(String original, String fallback) {
        return new MaskingResult(original, fallback, true, MaskingAction.DEGRADED, true);
    }

    /**
     * 创建"失败"结果 —— 脱敏失败且未触发降级，最终输出原值。
     *
     * @param original 原始消息
     * @return 标记为 FAILED 的不可变结果
     */
    public static MaskingResult failed(String original) {
        return new MaskingResult(original, original, false, MaskingAction.FAILED, false);
    }

    /**
     * 获取原始消息。
     *
     * @return 原始消息
     */
    public String getOriginal() { return original; }

    /**
     * 获取脱敏后消息（最终输出）。
     *
     * @return 脱敏后消息
     */
    public String getMasked() { return masked; }

    /**
     * 是否发生修改。
     *
     * @return true 表示输出与原始不同
     */
    public boolean isChanged() { return changed; }

    /**
     * 获取脱敏动作。
     *
     * @return {@link MaskingAction} 枚举值
     */
    public MaskingAction getAction() { return action; }

    /**
     * 是否处于降级状态。
     *
     * @return true 表示输出的是降级占位符
     */
    public boolean isDegraded() { return degraded; }
}