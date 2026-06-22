package com.example.anonymization.core.infrastructure.exception;

import com.example.anonymization.api.port.MaskingPort;
import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.model.MaskingResult;

import java.util.IdentityHashMap;

/**
 * 异常信息脱敏器（Exception Sanitizer）。
 *
 * <p>属于基础设施层（infrastructure/exception），负责递归地对异常链（含 cause 与 suppressed）中的消息字符串进行脱敏。
 * 核心场景：当业务代码使用 SLF4J 的 {@code logger.error("...", e)} 输出异常栈时，
 * 异常的 {@code getMessage()} 中可能包含卡号、身份证号、手机号等敏感数据，
 * 本类将其转为一个新的"脱敏后异常"，供日志框架序列化输出。
 *
 * <p>关键设计：
 * <ul>
 *   <li>递归遍历 cause 与 suppressed 链，最深 {@value #MAX_CAUSE_DEPTH} 层防止循环引用；</li>
 *   <li>使用 {@link IdentityHashMap} 按"对象身份"而非 {@code equals} 检测循环依赖；</li>
 *   <li>仅修改 {@code getMessage()} 返回值，保留原始异常类型与栈轨迹，便于运维定位。</li>
 * </ul>
 *
 * <p>线程安全：实例本身无状态（仅持有一个 {@link MaskingPort} 引用），可并发调用。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class ExceptionSanitizer {

    /**
     * 脱敏引擎引用，递归过程中对每个 cause 的 message 调用其 {@code process} 方法。
     */
    private final MaskingPort maskingEngine;

    /**
     * 异常链最大递归深度。
     * 超过该深度认为存在循环依赖或链路过深，停止递归以避免栈溢出。
     */
    private static final int MAX_CAUSE_DEPTH = 10;

    /**
     * 构造异常脱敏器。
     *
     * @param maskingEngine 脱敏引擎（{@link MaskingPort}），不可为 {@code null}
     */
    public ExceptionSanitizer(MaskingPort maskingEngine) {
        this.maskingEngine = maskingEngine;
    }

    /**
     * 对给定异常执行脱敏，返回一个 {@code getMessage()} 已被替换的"脱敏后异常"。
     *
     * <p>不会修改原始异常实例；通过返回新的 {@link SanitizedThrowable} 包装实现。
     *
     * @param throwable 待脱敏的异常，不可为 {@code null}；传入 {@code null} 时返回 {@code null}
     * @return 脱敏后的新异常；原异常 message 为 {@code null} 时返回原异常本身
     */
    public Throwable sanitize(Throwable throwable) {
        return sanitizeRecursive(throwable, 0, new IdentityHashMap<>());
    }

    /**
     * 递归脱敏实现。
     *
     * @param t       当前处理的异常
     * @param depth   当前递归深度（{@code 0} 为顶层）
     * @param visited 已访问异常集合（{@link IdentityHashMap}，按对象身份比较），
     *                用于检测循环依赖（如 {@code A.cause = B; B.cause = A}）
     * @return 脱敏后的异常（{@link SanitizedThrowable} 包装）；满足终止条件时返回原异常
     */
    private Throwable sanitizeRecursive(Throwable t, int depth,
                                         IdentityHashMap<Throwable, Throwable> visited) {
        if (t == null || depth > MAX_CAUSE_DEPTH || visited.containsKey(t)) {
            return t;
        }
        visited.put(t, t);

        String originalMessage = t.getMessage();
        String sanitizedMessage = originalMessage;
        if (originalMessage != null) {
            LogContext ctx = LogContext.builder().message(originalMessage).build();
            MaskingResult result = maskingEngine.process(originalMessage, ctx);
            if (result.isChanged()) {
                sanitizedMessage = result.getMasked();
            }
        }

        Throwable sanitizedCause = sanitizeRecursive(t.getCause(), depth + 1, visited);

        Throwable[] suppressed = t.getSuppressed();
        Throwable[] sanitizedSuppressed = new Throwable[suppressed.length];
        for (int i = 0; i < suppressed.length; i++) {
            sanitizedSuppressed[i] = sanitizeRecursive(suppressed[i], depth + 1, visited);
        }

        return new SanitizedThrowable(t, sanitizedMessage, sanitizedCause, sanitizedSuppressed);
    }

    /**
     * 脱敏后异常的包装类型。
     *
     * <p>继承 {@link RuntimeException} 是为了能被 {@link Throwable#initCause(Throwable)} 等通用 API 正常处理；
     * 重写 {@link #getMessage()} 返回脱敏后的字符串，栈轨迹与原异常保持一致（便于运维定位问题）。
     */
    private static class SanitizedThrowable extends RuntimeException {
        /**
     * 原始异常引用，仅用于读取 stackTrace，不参与 {@code getMessage()} 输出。
     */
        private final Throwable original;
        /**
         * 已脱敏的异常消息字符串，供 {@link #getMessage()} 返回。
         */
        private final String sanitizedMessage;

        /**
         * 构造脱敏后异常。
         *
         * @param original         原始异常（提供 stackTrace）
         * @param sanitizedMessage 已脱敏的异常消息
         * @param cause            已脱敏的 cause（可能为 {@code null}）
         * @param suppressed       已脱敏的 suppressed 数组
         */
        SanitizedThrowable(Throwable original, String sanitizedMessage,
                          Throwable cause, Throwable[] suppressed) {
            super(sanitizedMessage, cause);
            this.original = original;
            this.sanitizedMessage = sanitizedMessage;
            for (Throwable s : suppressed) {
                addSuppressed(s);
            }
            setStackTrace(original.getStackTrace());
        }

        /**
         * 返回脱敏后的消息字符串。
         *
         * <p>重写该方法是本包装类的核心目的 —— 任何 SLF4J / Logback / Log4j2
         * 通过 {@code exception.getMessage()} 获取异常信息时，都会得到脱敏后的字符串，
         * 而原始栈轨迹保持不变。
         *
         * @return 脱敏后的消息
         */
        @Override
        public String getMessage() {
            return sanitizedMessage;
        }
    }
}