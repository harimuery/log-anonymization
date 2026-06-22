package com.example.anonymization.api.port;

import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.model.MaskingResult;

/**
 * 脱敏端口 —— 抽象日志消息脱敏的主入口，是日志框架（Logback/Log4j2）与脱敏核心之间的契约。
 *
 * <p>使用场景：日志框架的 Converter/TurboFilter 在日志输出前调用 {@link #process}，
 * 返回脱敏后的结果用于替换原始消息。
 *
 * <p>典型实现：
 * <ul>
 *   <li>{@link com.example.anonymization.core.application.MaskingApplicationService}
 *       —— 实际执行管道的主实现</li>
 *   <li>{@link com.example.anonymization.core.infrastructure.resilience.ResilientMaskingEngine}
 *       —— 在主实现外层包装熔断器，提供降级保护</li>
 * </ul>
 *
 * @author log-anonymization
 */
public interface MaskingPort {
    /**
     * 对单条日志消息执行脱敏处理。
     *
     * <p>实现应满足非功能性约束：
     * <ul>
     *   <li>单条处理 P99 延迟 &lt; 5ms（见需求文档 4.1）</li>
     *   <li>异常时输出占位符（DEGRADED），绝不输出原始明文</li>
     *   <li>线程安全（无状态或只读状态）</li>
     * </ul>
     *
     * @param message 原始日志消息文本
     * @param context 日志上下文（含 loggerName/MDC/appName 等）
     * @return 脱敏结果（包含原始消息、脱敏后消息、动作标记、降级标记）
     */
    MaskingResult process(String message, LogContext context);
}