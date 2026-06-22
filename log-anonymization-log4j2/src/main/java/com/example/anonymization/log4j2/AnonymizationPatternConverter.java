package com.example.anonymization.log4j2;

import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.model.MaskingResult;
import com.example.anonymization.api.port.MaskingPort;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.pattern.LogEventPatternConverter;

/**
 * 日志消息脱敏 Pattern Converter（Log4j2）。
 *
 * <p>属于 log4j2 集成模块，继承自 Log4j2 的 {@link LogEventPatternConverter}，
 * 以 {@code MaskedMessage} 转换字注册（{@code %maskedMsg}），在日志格式化为字符串前对主体消息执行脱敏。
 * 是整个 SDK 在 Log4j2 体系中的"主入口"。
 *
 * <p>典型配置（{@code log4j2.xml}）：
 * <pre>
 *   &lt;Configuration packages="com.example.anonymization.log4j2"&gt;
 *     &lt;Appenders&gt;
 *       &lt;Console name="Console" target="SYSTEM_OUT"&gt;
 *         &lt;PatternLayout pattern="%d{HH:mm:ss.SSS} [%t] %-5level %logger - %maskedMsg%n"/&gt;
 *       &lt;/Console&gt;
 *     &lt;/Appenders&gt;
 *   &lt;/Configuration&gt;
 * </pre>
 *
 * <p>插件机制：通过 {@link Plugin} 注解注册为 {@code "Converter"} 类别的插件，
 * Log4j2 启动时扫描 {@code META-INF} 下的 {@code Log4j2Plugins.dat} 发现本类。
 *
 * @author java-architect
 * @since 1.0.0
 */
@Plugin(name = "MaskedMessage", category = "Converter")
public class AnonymizationPatternConverter extends LogEventPatternConverter {

    /**
     * 全局单例。Log4j2 插件机制要求 {@code newInstance} 返回单例；
     * 真正的 {@link MaskingPort} 由 Spring 容器运行时注入（通过 {@link #setMaskingPort}）。
     */
    private static final AnonymizationPatternConverter INSTANCE =
        new AnonymizationPatternConverter(null);

    /**
     * 脱敏端口。由 Spring 容器运行时注入。
     * 使用 {@code volatile} 保证在 Log4j2 已运行后注入的可见性。
     */
    private volatile MaskingPort maskingPort;

    /**
     * Log4j2 插件构造器（Plugin 框架反射调用）。
     *
     * @param maskingPort 脱敏端口（插件初始化时通常为 {@code null}，由 Spring 后续注入）
     */
    private AnonymizationPatternConverter(MaskingPort maskingPort) {
        super("MaskedMessage", "maskedMsg");
        this.maskingPort = maskingPort;
    }

    /**
     * Log4j2 插件工厂方法：被框架反射调用以创建转换器实例。
     *
     * @param options 配置文件中的属性数组（本插件忽略）
     * @return {@link #INSTANCE} 单例
     */
    public static AnonymizationPatternConverter newInstance(String[] options) {
        return INSTANCE;
    }

    /**
     * 格式化日志事件：将原始消息脱敏后追加到输出缓冲区。
     *
     * <p>流程：{@code event.getMessage().getFormattedMessage()} 获取消息 →
     * 构造 {@link LogContext} → {@link MaskingPort#process} 脱敏 → 追加到 {@code toAppendTo}。
     *
     * @param event       Log4j2 日志事件
     * @param toAppendTo  输出缓冲区（PatternLayout 提供）
     */
    @Override
    public void format(LogEvent event, StringBuilder toAppendTo) {
        String message = event.getMessage().getFormattedMessage();
        if (maskingPort == null || message == null) {
            toAppendTo.append(message != null ? message : "");
            return;
        }
        LogContext context = LogContext.builder()
            .message(message)
            .loggerName(event.getLoggerName())
            .threadName(event.getThreadName())
            .build();
        MaskingResult result = maskingPort.process(message, context);
        toAppendTo.append(result.getMasked());
    }

    /**
     * Spring 容器注入入口。
     *
     * <p>Log4j2 插件在 Spring 启动前就会被创建并被多个线程使用，
     * 因此注入时必须使用 {@code volatile} 写，保证其他线程能立即看到新值。
     *
     * @param maskingPort 脱敏端口；传 {@code null} 时 {@link #format} 走无脱敏路径
     */
    public void setMaskingPort(MaskingPort maskingPort) {
        this.maskingPort = maskingPort;
    }
}