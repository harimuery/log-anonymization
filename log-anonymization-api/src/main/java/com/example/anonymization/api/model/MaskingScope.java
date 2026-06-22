package com.example.anonymization.api.model;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * 脱敏规则作用域 —— 描述规则在哪些日志上下文中生效（应用、环境、日志器、Marker、包路径）。
 *
 * <p>使用场景：作为 {@link MaskingRule} 的子对象，用于实现"全局 → 应用 → 包/类 → Marker"
 * 的多层级覆盖机制。被 {@link MaskingRule#appliesTo(LogContext)} 调用。
 *
 * @author log-anonymization
 */
public final class MaskingScope {

    /** 应用名过滤（精确匹配） */
    private final String appName;
    /** 包路径模式列表（如 {@code "com.example.payment.*"}） */
    private final List<String> packagePatterns;
    /** 日志器名前缀（startsWith 匹配） */
    private final String loggerName;
    /** SLF4J Marker 名（精确匹配） */
    private final String markerName;
    /** 环境标识（精确匹配，如 dev/test/prod） */
    private final String environment;
    /** 是否全局生效（true 时其它字段均被忽略） */
    private final boolean global;

    /**
     * 私有构造器 —— 由 {@link Builder} 触发。
     *
     * @param builder 构建器
     */
    private MaskingScope(Builder builder) {
        this.appName = builder.appName;
        this.packagePatterns = builder.packagePatterns != null
            ? Collections.unmodifiableList(builder.packagePatterns) : Collections.emptyList();
        this.loggerName = builder.loggerName;
        this.markerName = builder.markerName;
        this.environment = builder.environment;
        this.global = builder.global;
    }

    /**
     * 判断规则作用域是否覆盖给定的日志上下文。
     *
     * <p>匹配逻辑（任一条件不满足即返回 false）：
     * <ol>
     *   <li>{@code global=true} → 直接返回 true</li>
     *   <li>{@code appName} 配置时，与上下文精确匹配</li>
     *   <li>{@code environment} 配置时，与上下文精确匹配</li>
     *   <li>{@code loggerName} 配置时，上下文 loggerName 必须以其为前缀</li>
     *   <li>{@code markerName} 配置时，与上下文精确匹配</li>
     *   <li>{@code packagePatterns} 非空时，至少有一个模式匹配上下文 loggerName</li>
     * </ol>
     *
     * @param context 日志上下文
     * @return true 表示规则在当前上下文生效
     */
    public boolean matches(LogContext context) {
        if (global) return true;
        if (appName != null && !appName.equals(context.getAppName())) return false;
        if (environment != null && !environment.equals(context.getEnvironment())) return false;
        if (loggerName != null && context.getLoggerName() != null
            && !context.getLoggerName().startsWith(loggerName)) return false;
        if (markerName != null && !markerName.equals(context.getMarkerName())) return false;
        if (!packagePatterns.isEmpty() && context.getLoggerName() != null) {
            boolean matchesAny = packagePatterns.stream()
                .anyMatch(pattern -> context.getLoggerName().startsWith(pattern.replace(".*", "")));
            if (!matchesAny) return false;
        }
        return true;
    }

    /**
     * 静态工厂：创建全局作用域（{@code global=true}）。
     *
     * @return 全局作用域实例
     */
    public static MaskingScope global() {
        return MaskingScope.builder().global(true).build();
    }

    /**
     * 获取应用名过滤条件。
     *
     * @return 应用名，可能为 null
     */
    public String getAppName() { return appName; }

    /**
     * 获取包路径模式列表。
     *
     * @return 不可变模式列表
     */
    public List<String> getPackagePatterns() { return packagePatterns; }

    /**
     * 获取日志器名前缀。
     *
     * @return 日志器名前缀，可能为 null
     */
    public String getLoggerName() { return loggerName; }

    /**
     * 获取 Marker 名过滤条件。
     *
     * @return Marker 名，可能为 null
     */
    public String getMarkerName() { return markerName; }

    /**
     * 获取环境过滤条件。
     *
     * @return 环境标识，可能为 null
     */
    public String getEnvironment() { return environment; }

    /**
     * 是否全局生效。
     *
     * @return true 表示全局生效
     */
    public boolean isGlobal() { return global; }

    /**
     * 获取 Builder 入口。
     *
     * @return 新的 {@link Builder} 实例
     */
    public static Builder builder() { return new Builder(); }

    /**
     * {@link MaskingScope} 的流式构建器。
     */
    public static class Builder {
        private String appName;
        private List<String> packagePatterns;
        private String loggerName;
        private String markerName;
        private String environment;
        private boolean global;

        /**
         * 设置应用名过滤。
         *
         * @param appName 应用名
         * @return 当前 Builder
         */
        public Builder appName(String appName) { this.appName = appName; return this; }

        /**
         * 设置包路径模式列表。
         *
         * @param patterns 模式列表
         * @return 当前 Builder
         */
        public Builder packagePatterns(List<String> patterns) { this.packagePatterns = patterns; return this; }

        /**
         * 设置日志器名前缀。
         *
         * @param loggerName 日志器名前缀
         * @return 当前 Builder
         */
        public Builder loggerName(String loggerName) { this.loggerName = loggerName; return this; }

        /**
         * 设置 Marker 名过滤。
         *
         * @param markerName Marker 名
         * @return 当前 Builder
         */
        public Builder markerName(String markerName) { this.markerName = markerName; return this; }

        /**
         * 设置环境过滤。
         *
         * @param env 环境标识
         * @return 当前 Builder
         */
        public Builder environment(String env) { this.environment = env; return this; }

        /**
         * 设置是否全局生效。
         *
         * @param global true 表示全局
         * @return 当前 Builder
         */
        public Builder global(boolean global) { this.global = global; return this; }

        /**
         * 构建不可变的 {@link MaskingScope}。
         *
         * @return 作用域实例
         */
        public MaskingScope build() { return new MaskingScope(this); }
    }
}