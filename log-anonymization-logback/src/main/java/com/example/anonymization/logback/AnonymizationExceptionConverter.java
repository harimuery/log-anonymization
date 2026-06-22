package com.example.anonymization.logback;

import ch.qos.logback.classic.pattern.ThrowableProxyConverter;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.classic.spi.ILoggingEvent;
import com.example.anonymization.core.infrastructure.exception.ExceptionSanitizer;

/**
 * 异常信息脱敏转换器（Logback Converter）。
 *
 * <p>属于 logback 集成模块，继承自 Logback 内置的 {@link ThrowableProxyConverter}，
 * 用于在日志格式化为字符串之前对异常信息执行脱敏。
 * 核心场景：业务异常堆栈中常常打印 SQL、HTTP 请求体等敏感数据，传统 Logback 会原样输出，
 * 本类通过 {@link ExceptionSanitizer} 对每条异常的 {@code message} 进行脱敏。
 *
 * <p>典型配置（{@code logback-spring.xml}）：
 * <pre>
 *   &lt;conversionRule conversionWord="maskedEx"
 *                   converterClass="com.example.anonymization.logback.AnonymizationExceptionConverter"/&gt;
 *   &lt;encoder&gt;
 *     &lt;pattern&gt;%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %maskedEx%n&lt;/pattern&gt;
 *   &lt;/encoder&gt;
 * </pre>
 *
 * <p>依赖：必须由 Spring 通过 {@link #setExceptionSanitizer(ExceptionSanitizer)} 注入 {@link ExceptionSanitizer}；
 * 未注入时退化为 Logback 默认行为（即原样输出）。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class AnonymizationExceptionConverter extends ThrowableProxyConverter {

    /**
     * 异常脱敏器。由 Spring 容器注入。
     * 使用 {@code null} 表示走父类默认实现（{@code super.convert}）。
     */
    private ExceptionSanitizer exceptionSanitizer;

    /**
     * 转换异常事件为字符串。
     *
     * <p>流程：
     * <ol>
     *   <li>{@link #setExceptionSanitizer} 未注入 → 走父类默认行为；</li>
     *   <li>无 throwableProxy → 返回空串；</li>
     *   <li>{@link #convertToThrowable} 重建异常实例 → {@link ExceptionSanitizer#sanitize} 脱敏 → 输出。</li>
     * </ol>
     *
     * @param event Logback 日志事件
     * @return 脱敏后的异常字符串
     */
    @Override
    public String convert(ILoggingEvent event) {
        if (exceptionSanitizer == null) {
            return super.convert(event);
        }
        IThrowableProxy throwableProxy = event.getThrowableProxy();
        if (throwableProxy == null) {
            return "";
        }
        Throwable throwable = convertToThrowable(throwableProxy);
        if (throwable != null) {
            Throwable sanitized = exceptionSanitizer.sanitize(throwable);
            return sanitized.toString();
        }
        return super.convert(event);
    }

    /**
     * Spring 容器注入入口。
     *
     * @param exceptionSanitizer 异常脱敏器；传 {@code null} 可回退到父类默认实现
     */
    public void setExceptionSanitizer(ExceptionSanitizer exceptionSanitizer) {
        this.exceptionSanitizer = exceptionSanitizer;
    }

    /**
     * 将 {@link IThrowableProxy} 还原为 {@link Throwable} 实例。
     *
     * <p>优先尝试按 {@code proxy.getClassName()} 加载真实类（保留异常类型）；
     * 加载失败时退化为 {@link RuntimeException}，避免日志链路因 ClassNotFound 中断。
     *
     * @param proxy Logback 异常代理对象
     * @return 还原后的异常实例
     */
    private Throwable convertToThrowable(IThrowableProxy proxy) {
        try {
            Class<?> clazz = Class.forName(proxy.getClassName());
            return new RuntimeException(proxy.getMessage());
        } catch (ClassNotFoundException e) {
            return new RuntimeException(proxy.getClassName() + ": " + proxy.getMessage());
        }
    }
}