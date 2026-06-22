package com.example.anonymization.test;

import com.example.anonymization.api.model.LogContext;

/**
 * {@link LogContext} 测试工厂（Test Factory）。
 *
 * <p>属于 test 模块，提供一系列静态方法快速构造测试用的 {@link LogContext} 实例，
 * 避免在每个测试用例中重复编写 {@code LogContext.builder()...build()} 链式调用。
 *
 * <p>典型用法：
 * <pre>
 *   LogContext ctx = LogContextTestFactory.simpleMessage("user card=6222021234567890");
 *   MaskingResult result = maskingEngine.process("user card=6222021234567890", ctx);
 * </pre>
 *
 * <p>所有方法返回的 {@link LogContext} 都设置了：
 * <ul>
 *   <li>{@code loggerName = "com.example.TestLogger"}；</li>
 *   <li>{@code threadName = "main"}；</li>
 *   <li>其余字段由对应方法填充。</li>
 * </ul>
 *
 * @author java-architect
 * @since 1.0.0
 */
public final class LogContextTestFactory {

    /**
     * 私有构造器，工具类不允许实例化。
     */
    private LogContextTestFactory() {}

    /**
     * 构造仅含消息的简单 {@link LogContext}。
     *
     * @param message 日志主体消息
     * @return 构建好的 {@link LogContext}
     */
    public static LogContext simpleMessage(String message) {
        return LogContext.builder()
            .message(message)
            .loggerName("com.example.TestLogger")
            .threadName("main")
            .build();
    }

    /**
     * 构造含单个 MDC 键值的 {@link LogContext}。
     *
     * @param message 日志主体消息
     * @param key     MDC 键
     * @param value   MDC 值
     * @return 构建好的 {@link LogContext}（MDC 中仅含 {@code key=value} 一项）
     */
    public static LogContext withMdc(String message, String key, String value) {
        return LogContext.builder()
            .message(message)
            .loggerName("com.example.TestLogger")
            .threadName("main")
            .mdc(java.util.Map.of(key, value))
            .build();
    }

    /**
     * 构造带应用名的 {@link LogContext}（适用于多租户场景）。
     *
     * @param message 日志主体消息
     * @param appName 应用名（用于按 appName 维度差异化规则）
     * @return 构建好的 {@link LogContext}
     */
    public static LogContext withAppName(String message, String appName) {
        return LogContext.builder()
            .message(message)
            .appName(appName)
            .loggerName("com.example.TestLogger")
            .threadName("main")
            .build();
    }
}