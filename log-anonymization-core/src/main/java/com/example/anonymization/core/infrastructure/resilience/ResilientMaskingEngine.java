package com.example.anonymization.core.infrastructure.resilience;

import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.model.MaskingResult;
import com.example.anonymization.api.port.MaskingPort;
import com.example.anonymization.core.infrastructure.masker.FallbackMasker;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;

/**
 * 弹性脱敏引擎（Resilient Masking Engine）。
 *
 * <p>属于基础设施层（infrastructure/resilience），是一个面向失败的脱敏引擎装饰器，
 * 通过 Resilience4j 熔断器包装下游 {@link MaskingPort} 实现，
 * 在下游故障率超阈值时快速失败并降级到 {@link FallbackMasker}，保护日志主链路不被拖垮。
 *
 * <p>典型调用链：
 * <pre>
 *   Logback/Log4j2 Appender
 *     → ResilientMaskingEngine#process（熔断保护）
 *       → delegate.process（实际脱敏） — 异常时 fallback
 *     → 返回 MaskingResult
 * </pre>
 *
 * <p>熔断配置（默认，由 {@link com.example.anonymization.starter.LogAnonymizationAutoConfiguration} 提供）：
 * <ul>
 *   <li>失败率阈值：{@code 50%}；</li>
 *   <li>慢调用阈值：{@code 10ms}；</li>
 *   <li>滑动窗口大小：{@code 100} 次调用；</li>
 *   <li>Open 状态等待时间：{@code 30s}。</li>
 * </ul>
 *
 * <p>线程安全：实例本身无状态（仅持有 3 个 final 引用），可并发调用。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class ResilientMaskingEngine implements MaskingPort {

    /**
     * 被装饰的实际脱敏引擎（如 {@link com.example.anonymization.core.application.MaskingApplicationService}）。
     */
    private final MaskingPort delegate;

    /**
     * Resilience4j 熔断器实例；由 {@code LogAnonymizationAutoConfiguration} 注入。
     */
    private final CircuitBreaker circuitBreaker;

    /**
     * 降级兜底打码器；当熔断打开或下游异常时使用，避免日志明文泄漏。
     */
    private final FallbackMasker fallbackMasker;

    /**
     * 构造弹性脱敏引擎。
     *
     * @param delegate       实际脱敏引擎，不可为 {@code null}
     * @param circuitBreaker 熔断器，不可为 {@code null}
     * @param fallbackMasker 降级打码器，不可为 {@code null}
     */
    public ResilientMaskingEngine(MaskingPort delegate,
                                  CircuitBreaker circuitBreaker,
                                  FallbackMasker fallbackMasker) {
        this.delegate = delegate;
        this.circuitBreaker = circuitBreaker;
        this.fallbackMasker = fallbackMasker;
    }

    /**
     * 在熔断器保护下执行脱敏。
     *
     * <p>异常路径：
     * <ul>
     *   <li>下游 {@code delegate.process} 抛出异常 → 调用 {@link FallbackMasker#fallbackMask} 返回降级结果；</li>
     *   <li>熔断器处于 Open 状态 → {@link CircuitBreaker#executeSupplier} 抛出 {@code CallNotPermittedException}，
     *       由全局异常处理器（若有）兜底。</li>
     * </ul>
     *
     * @param message 原始日志消息
     * @param context 日志上下文
     * @return 脱敏结果；正常路径为 {@code delegate.process} 结果，降级路径为 {@code fallbackMask} 结果
     */
    @Override
    public MaskingResult process(String message, LogContext context) {
        return circuitBreaker.executeSupplier(() -> {
            try {
                return delegate.process(message, context);
            } catch (Exception e) {
                return fallbackMasker.fallbackMask(message, context);
            }
        });
    }
}