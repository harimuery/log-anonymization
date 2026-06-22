package com.example.anonymization.core.infrastructure.security;

import com.example.anonymization.api.model.LogContext;

/**
 * 安全内存管理器（Secure Memory Manager）。
 *
 * <p>属于基础设施层（infrastructure/security），基于 {@link ThreadLocal} 提供线程级
 * {@link LogContext} 的传递与生命周期管理，主要解决以下问题：
 * <ul>
 *   <li>跨方法调用传递上下文时，避免污染方法签名（无需每个方法都加 {@code LogContext} 参数）；</li>
 *   <li>线程复用（如 Tomcat 工作线程）时，防止旧线程上下文残留造成数据泄漏；</li>
 *   <li>提供"取并清除"的原子操作，避免业务忘记 {@code remove()} 导致 ThreadLocal 内存泄漏。</li>
 * </ul>
 *
 * <p>典型用法（伪代码）：
 * <pre>
 *   SecureMemoryManager.setContext(logContext);
 *   try {
 *     // ... 业务逻辑（无需传递 logContext）
 *   } finally {
 *     SecureMemoryManager.getAndClearContext();
 *   }
 * </pre>
 *
 * @author java-architect
 * @since 1.0.0
 */
public class SecureMemoryManager {

    /**
     * 线程级 {@link LogContext} 容器。
     * 使用 {@link ThreadLocal} 而非 {@code InheritableThreadLocal}，避免线程池场景下父子线程串味。
     */
    private static final ThreadLocal<LogContext> CONTEXT = new ThreadLocal<>();

    /**
     * 私有构造器，工具类不允许实例化。
     */
    private SecureMemoryManager() {}

    /**
     * 在当前线程设置上下文。
     *
     * <p>警告：务必在 {@code finally} 块中调用 {@link #getAndClearContext}，否则线程复用时
     * 旧上下文会泄漏到下一次业务调用。
     *
     * @param context 待绑定的日志上下文
     */
    public static void setContext(LogContext context) {
        CONTEXT.set(context);
    }

    /**
     * 取出当前线程上下文并清除。
     *
     * @return 之前 {@link #setContext} 设置的上下文；若未设置则返回 {@code null}
     */
    public static LogContext getAndClearContext() {
        LogContext ctx = CONTEXT.get();
        CONTEXT.remove();
        return ctx;
    }
}