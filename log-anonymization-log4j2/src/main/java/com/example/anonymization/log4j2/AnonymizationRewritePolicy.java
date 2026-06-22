package com.example.anonymization.log4j2;

import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.model.MaskingResult;
import com.example.anonymization.api.port.MaskingPort;
import com.example.anonymization.core.infrastructure.exception.ExceptionSanitizer;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.rewrite.RewritePolicy;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.config.plugins.PluginElement;
import org.apache.logging.log4j.core.impl.Log4jLogEvent;
import org.apache.logging.log4j.message.SimpleMessage;

/**
 * 日志重写策略（Log4j2 Rewrite Policy）。
 *
 * <p>属于 log4j2 集成模块，实现 {@link RewritePolicy} 接口，
 * 是 Log4j2 体系中"在事件落入 Appender 之前改写事件内容"的扩展点。
 * 与 {@link AnonymizationPatternConverter} 的差异：
 * <ul>
 *   <li>Converter 在"格式化字符串"阶段介入；</li>
 *   <li>Rewrite Policy 在"事件对象"阶段介入，可同时改写 {@code message} 与 {@code thrown}，更彻底。</li>
 * </ul>
 *
 * <p>典型配置（{@code log4j2.xml}）：
 * <pre>
 *   &lt;Rewrite name="AnonymizationRewrite"&gt;
 *     &lt;AnonymizationRewritePolicy/&gt;
 *     &lt;AppenderRef ref="Console"/&gt;
 *   &lt;/Rewrite&gt;
 * </pre>
 *
 * <p>插件机制：通过 {@link Plugin} 注解注册为 {@code Core} 类别的 {@code rewritePolicy} 元素。
 *
 * @author java-architect
 * @since 1.0.0
 */
@Plugin(name = "AnonymizationRewritePolicy", category = "Core", elementType = "rewritePolicy", printObject = true)
public class AnonymizationRewritePolicy implements RewritePolicy {

    /**
     * 脱敏端口。由 Spring 容器运行时注入。
     */
    private volatile MaskingPort maskingPort;

    /**
     * 异常脱敏器。由 Spring 容器运行时注入。
     */
    private volatile ExceptionSanitizer exceptionSanitizer;

    /**
     * 无参构造器（Log4j2 插件框架要求）。
     */
    public AnonymizationRewritePolicy() {}

    /**
     * 带依赖的构造器（供测试或非 Spring 环境直接 new）。
     *
     * @param maskingPort        脱敏端口
     * @param exceptionSanitizer 异常脱敏器
     */
    public AnonymizationRewritePolicy(MaskingPort maskingPort, ExceptionSanitizer exceptionSanitizer) {
        this.maskingPort = maskingPort;
        this.exceptionSanitizer = exceptionSanitizer;
    }

    /**
     * 重写日志事件：替换消息与异常为脱敏版本，返回新事件对象。
     *
     * <p>未注入 {@link #maskingPort} 时直接返回原事件（不做任何修改），
     * 保证 Log4j2 默认行为不被破坏。
     *
     * @param source 原始日志事件
     * @return 改写后的新事件（消息已脱敏、异常已脱敏）
     */
    @Override
    public LogEvent rewrite(LogEvent source) {
        if (maskingPort == null) {
            return source;
        }

        String message = source.getMessage().getFormattedMessage();
        LogContext context = LogContext.builder()
            .message(message)
            .loggerName(source.getLoggerName())
            .threadName(source.getThreadName())
            .build();
        MaskingResult result = maskingPort.process(message, context);

        Log4jLogEvent.Builder builder = new Log4jLogEvent.Builder(source)
            .setMessage(new SimpleMessage(result.getMasked()));

        if (exceptionSanitizer != null && source.getThrown() != null) {
            Throwable sanitized = exceptionSanitizer.sanitize(source.getThrown());
            builder.setThrown(sanitized);
        }

        return builder.build();
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
     * 注入异常脱敏器。
     *
     * @param exceptionSanitizer 异常脱敏器
     */
    public void setExceptionSanitizer(ExceptionSanitizer exceptionSanitizer) {
        this.exceptionSanitizer = exceptionSanitizer;
    }
}