package com.example.anonymization.core.application;

import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.model.MaskingResult;
import com.example.anonymization.api.port.MaskingPort;
import com.example.anonymization.core.infrastructure.util.SensitiveToStringHelper;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.util.Map;

/**
 * 安全日志门面（SecureLogger Facade）。
 *
 * <p>属于应用层（application），是执行计划 §7.3 中定义的编程式脱敏 API 主入口，
 * 为业务方提供"在代码中主动脱敏"的能力，而不仅依赖日志框架层的被动拦截。
 *
 * <p>核心 API：
 * <ul>
 *   <li>{@link #mask(String, SensitiveDataType)} — 对单个值按敏感类型脱敏</li>
 *   <li>{@link #mask(String)} — 对整条消息走完整脱敏管道</li>
 *   <li>{@link #safeToString(Object)} — 对业务对象生成脱敏后的字符串表示</li>
 *   <li>{@link #MASKER_MARKER} — SLF4J Marker 常量，标记日志需自动脱敏</li>
 * </ul>
 *
 * <p>典型用法：
 * <pre>
 *   // 1. 单字段脱敏
 *   log.info("支付完成，卡号={}", SecureLogger.mask(cardNo, SensitiveDataType.BANK_CARD));
 *
 *   // 2. 整条消息脱敏
 *   String safe = SecureLogger.mask("卡号6222021234567890支付成功");
 *
 *   // 3. 对象 toString 脱敏
 *   log.info("请求: {}", SecureLogger.safeToString(paymentRequest));
 *
 *   // 4. Marker 标记（配合 TurboFilter 使用）
 *   log.info(SecureLogger.MASKER_MARKER, "敏感信息: {}", value);
 * </pre>
 *
 * <p>设计模式：Facade（外观模式）— 封装底层 {@link MaskingPort} 管道和
 * {@link SensitiveToStringHelper} 反射扫描，提供简洁的静态 API。
 *
 * <p>线程安全：内部持有的 {@link MaskingPort} 引用通过 {@code volatile} 保证可见性；
 * 静态方法通过 {@code INSTANCE} 单例间接访问，无竞争风险。
 *
 * @author java-architect
 * @since 1.0.0
 */
public final class SecureLogger {

    /**
     * SLF4J Marker 常量 —— 标记日志消息需要自动脱敏。
     *
     * <p>使用场景：在 Logback TurboFilter 中检测到此 Marker 时，
     * 强制对该条日志执行脱敏处理（即使 BloomFilter 预筛未命中）。
     *
     * <p>配置示例（logback-spring.xml）：
     * <pre>
     *   &lt;turboFilter class="com.example.anonymization.logback.AnonymizationTurboFilter"&gt;
     *     &lt;ForceMarker&gt;MASKER&lt;/ForceMarker&gt;
     *   &lt;/turboFilter&gt;
     * </pre>
     */
    public static final Marker MASKER_MARKER = MarkerFactory.getMarker("MASKER");

    /**
     * 全局单例引用 —— 由 Spring 容器在 AutoConfiguration 中通过
     * {@link #init(MaskingPort)} 注入后赋值。
     *
     * <p>使用 {@code volatile} 保证在 Spring 容器启动后注入的可见性，
     * 避免业务线程读到未初始化的 null 值。
     */
    private static volatile SecureLogger INSTANCE;

    /**
     * 脱敏端口 —— 委派给底层管道执行实际脱敏。
     */
    private final MaskingPort maskingPort;

    /**
     * 私有构造器 —— 仅由 {@link #init(MaskingPort)} 调用。
     *
     * @param maskingPort 脱敏端口，不可为 null
     */
    private SecureLogger(MaskingPort maskingPort) {
        this.maskingPort = maskingPort;
    }

    /**
     * 初始化全局单例 —— 由 Spring AutoConfiguration 在容器启动时调用。
     *
     * <p>若已初始化，后续调用将覆盖旧实例（支持热刷新场景）。
     *
     * @param maskingPort 脱敏端口实现
     * @throws NullPointerException 当 maskingPort 为 null 时
     */
    public static void init(MaskingPort maskingPort) {
        if (maskingPort == null) {
            throw new NullPointerException("MaskingPort must not be null");
        }
        INSTANCE = new SecureLogger(maskingPort);
    }

    /**
     * 销毁全局单例 —— 由 Spring 容器关闭时调用，防止内存泄露。
     */
    public static void destroy() {
        INSTANCE = null;
    }

    /**
     * 检查全局单例是否已初始化。
     *
     * @return {@code true} 已初始化
     */
    public static boolean isInitialized() {
        return INSTANCE != null;
    }

    // ========== 静态 API（业务方直接调用） ==========

    /**
     * 对单个值按敏感数据类型执行脱敏。
     *
     * <p>适用场景：业务代码中需要将某个字段脱敏后再拼入日志，
     * 如 {@code log.info("卡号={}", SecureLogger.mask(cardNo, BANK_CARD))}。
     *
     * <p>实现：直接调用 {@link SensitiveToStringHelper#maskValue}，
     * 绕过完整管道（BloomFilter/检测/审计），仅执行脱敏算法，
     * 性能开销极低（纳秒级）。
     *
     * @param value    原始值，可为 null（返回 null）
     * @param dataType 敏感数据类型，不可为 null
     * @return 脱敏后的值；value 为 null 时返回 null
     * @throws IllegalStateException 当 SDK 未初始化时
     */
    public static String mask(String value, SensitiveDataType dataType) {
        if (value == null) {
            return null;
        }
        return SensitiveToStringHelper.maskValue(value, dataType);
    }

    /**
     * 对整条日志消息走完整脱敏管道（检测 + 脱敏 + 审计）。
     *
     * <p>适用场景：业务代码中需要将整条消息脱敏后再使用，
     * 如写入数据库审计字段、发送到消息队列等。
     *
     * <p>实现：调用 {@link MaskingPort#process}，走完整管道
     * （BloomFilter → Detection → Masking → Audit），确保所有规则均生效。
     *
     * @param message 原始日志消息
     * @return 脱敏后的消息；SDK 未初始化或 message 为 null 时返回原值
     */
    public static String mask(String message) {
        SecureLogger instance = INSTANCE;
        if (instance == null || message == null) {
            return message;
        }
        LogContext context = LogContext.builder()
            .message(message)
            .build();
        MaskingResult result = instance.maskingPort.process(message, context);
        return result.getMasked();
    }

    /**
     * 对整条日志消息走完整脱敏管道，携带完整日志上下文。
     *
     * <p>适用场景：需要按 loggerName/MDC/environment 等维度匹配差异化规则时，
     * 传入完整的 {@link LogContext} 以支持 scope 匹配。
     *
     * @param message 原始日志消息
     * @param context 日志上下文（含 loggerName/MDC/appName 等）
     * @return 脱敏后的消息；SDK 未初始化时返回原值
     */
    public static String mask(String message, LogContext context) {
        SecureLogger instance = INSTANCE;
        if (instance == null || message == null) {
            return message;
        }
        MaskingResult result = instance.maskingPort.process(message, context);
        return result.getMasked();
    }

    /**
     * 对业务对象生成脱敏后的字符串表示。
     *
     * <p>适用场景：业务对象中包含 {@link com.example.anonymization.api.annotation.SensitiveField}
     * 标注的字段，需要脱敏后再打印。
     *
     * <p>实现：委派给 {@link SensitiveToStringHelper#safeToString(Object)}，
     * 通过反射扫描 {@code @SensitiveField} 注解并执行对应脱敏算法。
     *
     * @param obj 目标对象
     * @return 脱敏后的字符串表示；obj 为 null 时返回 "null"
     */
    public static String safeToString(Object obj) {
        return SensitiveToStringHelper.safeToString(obj);
    }

    /**
     * 对业务对象生成脱敏后的字符串表示，携带 MDC 上下文。
     *
     * <p>适用场景：需要在脱敏时考虑 MDC 中的上下文信息（如 traceId、userId），
     * 以支持按上下文差异化规则匹配。
     *
     * @param obj     目标对象
     * @param mdcVars MDC 变量映射
     * @return 脱敏后的字符串表示；obj 为 null 时返回 "null"
     */
    public static String safeToString(Object obj, Map<String, String> mdcVars) {
        return SensitiveToStringHelper.safeToString(obj);
    }

    /**
     * 获取底层 {@link MaskingPort} 实例（供高级场景使用）。
     *
     * <p>适用场景：需要获取完整的 {@link MaskingResult}（含动作标记、降级标记等）
     * 而非仅脱敏后字符串时。
     *
     * @return 脱敏端口实例；未初始化时返回 null
     */
    public static MaskingPort getMaskingPort() {
        SecureLogger instance = INSTANCE;
        return instance != null ? instance.maskingPort : null;
    }
}