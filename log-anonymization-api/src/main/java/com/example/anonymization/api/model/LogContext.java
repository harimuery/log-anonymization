package com.example.anonymization.api.model;

import java.util.Collections;
import java.util.Map;

/**
 * 日志上下文 —— 描述一条日志事件的所有上下文信息，作为检测/脱敏的输入参数。
 *
 * <p>使用场景：
 * <ul>
 *   <li>由 Logback/Log4j2 Converter 在日志输出前构建并传入
 *       {@link com.example.anonymization.api.port.MaskingPort#process}</li>
 *   <li>{@link com.example.anonymization.api.spi.SensitiveDataDetector}
 *       通过此对象读取 message/MDC/loggerName 等决定是否识别、采用哪条规则</li>
 *   <li>{@link com.example.anonymization.api.model.MaskingScope#matches(LogContext)}
 *       用于规则的 scope 匹配判断</li>
 * </ul>
 *
 * <p>不可变：通过 Builder 构建，MDC 字段在构造时封装为不可变 Map。
 *
 * @author log-anonymization
 */
public final class LogContext {

    /** 原始日志消息文本（未格式化） */
    private final String message;
    /** 应用名（多应用环境下用于指标切分与规则 scope 匹配） */
    private final String appName;
    /** 日志器名（用于 scope/packagePatterns 匹配） */
    private final String loggerName;
    /** SLF4J Marker 名（可选，用于按 Marker 路由规则） */
    private final String markerName;
    /** 环境标识（如 dev/test/prod，用于按环境切换规则集） */
    private final String environment;
    /** 线程名（用于审计、问题定位） */
    private final String threadName;
    /** MDC 上下文（链路追踪、用户 ID 等元数据，不可变） */
    private final Map<String, String> mdc;

    /**
     * 私有构造器 —— 由 Builder 触发。
     *
     * @param builder 构建器
     */
    private LogContext(Builder builder) {
        this.message = builder.message;
        this.appName = builder.appName;
        this.loggerName = builder.loggerName;
        this.markerName = builder.markerName;
        this.environment = builder.environment;
        this.threadName = builder.threadName;
        this.mdc = builder.mdc != null
            ? Collections.unmodifiableMap(builder.mdc) : Collections.emptyMap();
    }

    /**
     * 获取原始日志消息。
     *
     * @return 消息文本
     */
    public String getMessage() { return message; }

    /**
     * 获取应用名。
     *
     * @return 应用名，可能为 null
     */
    public String getAppName() { return appName; }

    /**
     * 获取日志器名。
     *
     * @return 日志器全限定名
     */
    public String getLoggerName() { return loggerName; }

    /**
     * 获取 SLF4J Marker 名。
     *
     * @return Marker 名，可能为 null
     */
    public String getMarkerName() { return markerName; }

    /**
     * 获取环境标识。
     *
     * @return 环境标识，可能为 null
     */
    public String getEnvironment() { return environment; }

    /**
     * 获取线程名。
     *
     * @return 线程名，可能为 null
     */
    public String getThreadName() { return threadName; }

    /**
     * 获取 MDC 上下文。
     *
     * @return 不可变 MDC Map，无值时返回空 Map
     */
    public Map<String, String> getMdc() { return mdc; }

    /**
     * 获取 Builder 入口。
     *
     * @return 新的 {@link Builder} 实例
     */
    public static Builder builder() { return new Builder(); }

    /**
     * {@link LogContext} 的流式构建器。
     */
    public static class Builder {
        private String message;
        private String appName;
        private String loggerName;
        private String markerName;
        private String environment;
        private String threadName;
        private Map<String, String> mdc;

        /**
         * 设置原始消息文本。
         *
         * @param message 消息
         * @return 当前 Builder
         */
        public Builder message(String message) { this.message = message; return this; }

        /**
         * 设置应用名。
         *
         * @param appName 应用名
         * @return 当前 Builder
         */
        public Builder appName(String appName) { this.appName = appName; return this; }

        /**
         * 设置日志器名。
         *
         * @param loggerName 日志器名
         * @return 当前 Builder
         */
        public Builder loggerName(String loggerName) { this.loggerName = loggerName; return this; }

        /**
         * 设置 Marker 名。
         *
         * @param markerName Marker 名
         * @return 当前 Builder
         */
        public Builder markerName(String markerName) { this.markerName = markerName; return this; }

        /**
         * 设置环境标识。
         *
         * @param env 环境标识
         * @return 当前 Builder
         */
        public Builder environment(String env) { this.environment = env; return this; }

        /**
         * 设置线程名。
         *
         * @param threadName 线程名
         * @return 当前 Builder
         */
        public Builder threadName(String threadName) { this.threadName = threadName; return this; }

        /**
         * 设置 MDC 上下文（将被封装为不可变 Map）。
         *
         * @param mdc MDC Map
         * @return 当前 Builder
         */
        public Builder mdc(Map<String, String> mdc) { this.mdc = mdc; return this; }

        /**
         * 构建不可变的 {@link LogContext}。
         *
         * @return 上下文实例
         */
        public LogContext build() { return new LogContext(this); }
    }
}