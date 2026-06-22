package com.example.anonymization.logback;

import ch.qos.logback.classic.pattern.MessageConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;
import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.model.MaskingResult;
import com.example.anonymization.api.port.MaskingPort;

/**
 * 日志消息脱敏转换器（Logback Converter）。
 *
 * <p>属于 logback 集成模块，继承自 Logback 内置的 {@link MessageConverter}，
 * 用于在日志格式化为字符串之前对日志主体消息执行脱敏。
 * 是整个 SDK 在 Logback 体系中的"主入口"。
 *
 * <p>典型配置（{@code logback-spring.xml}）：
 * <pre>
 *   &lt;conversionRule conversionWord="maskedMsg"
 *                   converterClass="com.example.anonymization.logback.AnonymizationMessageConverter"/&gt;
 *   &lt;pattern&gt;%d{HH:mm:ss.SSS} [%thread] %-5level %logger - %maskedMsg%n&lt;/pattern&gt;
 * </pre>
 *
 * <p>依赖：由 Spring 通过 {@link #setMaskingPort(MaskingPort)} 注入脱敏端口；
 * 未注入或消息为空时直接走父类默认行为。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class AnonymizationMessageConverter extends MessageConverter {

    /**
     * 脱敏端口。由 Spring 容器注入。
     */
    private MaskingPort maskingPort;

    /**
     * 转换日志事件为字符串。
     *
     * <p>流程：{@code super.convert} 获取原始消息 → 构造 {@link LogContext} →
     * {@link MaskingPort#process} 脱敏 → 返回 masked 字符串。
     *
     * @param event Logback 日志事件
     * @return 脱敏后的日志主体
     */
    @Override
    public String convert(ILoggingEvent event) {
        String message = super.convert(event);
        if (maskingPort == null || message == null || message.isEmpty()) {
            return message;
        }
        LogContext context = buildLogContext(event);
        MaskingResult result = maskingPort.process(message, context);
        return result.getMasked();
    }

    /**
     * Spring 容器注入入口。
     *
     * @param maskingPort 脱敏端口；传 {@code null} 走无脱敏路径
     */
    public void setMaskingPort(MaskingPort maskingPort) {
        this.maskingPort = maskingPort;
    }

    /**
     * 从 Logback 事件构造 {@link LogContext}，供下游 Pipeline 使用。
     *
     * <p>携带信息：message、loggerName、threadName、MDC PropertyMap（保留以支持按 logger 维度差异化规则）。
     *
     * @param event Logback 日志事件
     * @return 构建好的日志上下文
     */
    private LogContext buildLogContext(ILoggingEvent event) {
        return LogContext.builder()
            .message(event.getFormattedMessage())
            .loggerName(event.getLoggerName())
            .threadName(event.getThreadName())
            .mdc(event.getMDCPropertyMap())
            .build();
    }
}