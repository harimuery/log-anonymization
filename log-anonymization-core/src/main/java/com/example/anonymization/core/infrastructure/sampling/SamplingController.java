package com.example.anonymization.core.infrastructure.sampling;

import com.example.anonymization.api.enums.RiskLevel;

import java.util.concurrent.ThreadLocalRandom;

/**
 * 采样控制器（Sampling Controller）。
 *
 * <p>属于基础设施层（infrastructure/sampling），根据风险等级决定是否对当前日志执行脱敏，
 * 实现"高风险必脱敏、低风险按概率采样"的弹性策略，以在峰值流量时降低 CPU 占用。
 *
 * <p>策略规则：
 * <ul>
 *   <li>{@link RiskLevel#CRITICAL} 与 {@link RiskLevel#HIGH}：{@code 100%} 执行脱敏（不参与采样）；</li>
 *   <li>{@link RiskLevel#MEDIUM} / {@link RiskLevel#LOW}：按当前 {@code samplingRate} 概率执行；</li>
 *   <li>随机数使用 {@link ThreadLocalRandom}，避免高并发下 {@code Random} 的 CAS 热点。</li>
 * </ul>
 *
 * <p>线程安全：{@code samplingRate} 使用 {@code volatile} 修饰，配置变更对所有线程立即可见。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class SamplingController {

    /**
     * 采样率（{@code [0.0, 1.0]}），{@code 1.0} 表示 100% 执行脱敏，{@code 0.0} 表示全部跳过。
     * 使用 {@code volatile} 保证多线程可见性，无需加锁。
     */
    private volatile double samplingRate = 1.0;

    /**
     * 判定"当前日志是否需要执行脱敏"。
     *
     * @param riskLevel 当前日志的风险等级（由规则或上下文决定）
     * @return {@code true} 表示执行脱敏；{@code false} 表示跳过（命中采样）
     */
    public boolean shouldMask(RiskLevel riskLevel) {
        if (riskLevel == RiskLevel.CRITICAL || riskLevel == RiskLevel.HIGH) {
            return true;
        }
        return ThreadLocalRandom.current().nextDouble() < samplingRate;
    }

    /**
     * 设置采样率（支持运行时动态调整）。
     *
     * <p>自动将入参截断到 {@code [0.0, 1.0]} 区间，防止运维误传 {@code 2.0} / {@code -1.0} 等异常值。
     *
     * @param rate 新的采样率，{@code 0.0} 表示全量跳过，{@code 1.0} 表示全量脱敏
     */
    public void setSamplingRate(double rate) {
        this.samplingRate = Math.max(0.0, Math.min(1.0, rate));
    }

    /**
     * 获取当前采样率（用于指标暴露或运维查询）。
     *
     * @return 当前采样率
     */
    public double getSamplingRate() {
        return samplingRate;
    }
}