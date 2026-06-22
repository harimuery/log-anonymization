package com.example.anonymization.core.infrastructure.security;

import com.example.anonymization.api.model.LogContext;
import com.google.re2j.Pattern;

/**
 * 日志消息控制字符清理器（Log Message Sanitizer）。
 *
 * <p>属于基础设施层（infrastructure/security），是一个无状态的工具类，
 * 使用 re2j 一次性移除日志消息中所有 ASCII 控制字符（{@code 0x00-0x1F} 多数不可见字符 + {@code 0x7F} DEL），
 * 防止以下危害：
 * <ul>
 *   <li>终端 ANSI 转义注入（{@code \u001B[...m}）；</li>
 *   <li>日志文件解析异常（{@code \u0000} 截断 C-style 字符串）；</li>
 *   <li>日志采集器（Filebeat/Vector）解析失败导致数据丢失。</li>
 * </ul>
 *
 * <p>保留换行符（{@code \n} 即 {@code 0x0A}）与回车符（{@code \r} 即 {@code 0x0D}），
 * 其余 0x00-0x08、0x0B、0x0C、0x0E-0x1F 与 0x7F 均被剥离。
 *
 * <p>线程安全：纯函数实现，无共享状态，可并发调用。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class LogMessageSanitizer {

    /**
     * 预编译的控制字符正则（re2j 引擎，线性时间复杂度）。
     * 类初始化时一次性编译，所有实例共享，避免每次调用重新编译。
     */
    private static final Pattern CONTROL_CHARS =
        Pattern.compile("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]");

    /**
     * 私有构造器，工具类不允许实例化。
     */
    private LogMessageSanitizer() {}

    /**
     * 移除日志消息中的控制字符。
     *
     * @param message 原始日志消息
     * @return 清理控制字符后的消息；{@code null} 输入返回 {@code null}
     */
    public static String sanitize(String message) {
        if (message == null) return null;
        return CONTROL_CHARS.matcher(message).replaceAll("");
    }
}