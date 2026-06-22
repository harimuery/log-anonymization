package com.example.anonymization.logback;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.filter.Filter;
import ch.qos.logback.core.spi.FilterReply;
import com.example.anonymization.api.port.MaskingPort;

/**
 * 日志脱敏 Turbo 过滤器（Logback Turbo Filter）。
 *
 * <p>属于 logback 集成模块，继承自 {@code ch.qos.logback.classic.turbo.TurboFilter}，
 * 是 Logback 体系中"在事件创建阶段就介入"的过滤器。
 * 当前实现为占位符/扩展点 —— 实际脱敏放在下游的 Converter 中完成，
 * 本类保留 {@link #decide} 钩子供后续实现"按 logger/level 动态开关脱敏"。
 *
 * <p>典型配置（{@code logback-spring.xml}）：
 * <pre>
 *   &lt;turboFilter class="com.example.anonymization.logback.AnonymizationTurboFilter"&gt;
 *     &lt;Enabled&gt;true&lt;/Enabled&gt;
 *   &lt;/turboFilter&gt;
 * </pre>
 *
 * @author java-architect
 * @since 1.0.0
 */
public class AnonymizationTurboFilter extends ch.qos.logback.classic.turbo.TurboFilter {

    /**
     * 脱敏端口引用。当前未在 {@link #decide} 中调用，预留给后续扩展。
     * 使用 {@code volatile} 保证运行时注入可见性。
     */
    private volatile MaskingPort maskingPort;

    /**
     * 全局开关。可通过 {@code <Enabled>} 配置或运行时 {@link #setEnabled(boolean)} 调整。
     */
    private volatile boolean enabled = true;

    /**
     * Turbo Filter 决策方法。
     *
     * <p>当前实现：始终返回 {@link FilterReply#NEUTRAL}（不过滤），但保留扩展点：
     * 若需要在事件创建阶段拦截，可在此处调用 {@link #maskingPort} 提前脱敏并修改 event。
     *
     * @param marker  SLF4J Marker
     * @param logger  Logback Logger
     * @param level   日志级别
     * @param format  格式字符串
     * @param params  格式化参数
     * @param t       异常
     * @return 始终 {@link FilterReply#NEUTRAL}
     */
    @Override
    public FilterReply decide(org.slf4j.Marker marker, ch.qos.logback.classic.Logger logger,
                               ch.qos.logback.classic.Level level, String format,
                               Object[] params, Throwable t) {
        if (!enabled || maskingPort == null) {
            return FilterReply.NEUTRAL;
        }
        return FilterReply.NEUTRAL;
    }

    /**
     * 注入脱敏端口。
     *
     * @param maskingPort 脱敏端口
     */
    public void setMaskingPort(MaskingPort maskingPort) {
        this.maskingPort = maskingPort;
    }

    /**
     * 动态开启/关闭脱敏（默认 {@code true}）。
     *
     * <p>运行时关闭后，已创建的事件仍会被 Converter 处理 —— 本方法影响的是 {@link #decide} 决策。
     *
     * @param enabled {@code true} 开启；{@code false} 关闭
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}