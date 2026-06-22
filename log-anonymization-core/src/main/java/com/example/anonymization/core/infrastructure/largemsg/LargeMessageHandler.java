package com.example.anonymization.core.infrastructure.largemsg;

import com.example.anonymization.api.port.MaskingPort;
import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.model.MaskingResult;

/**
 * 大日志消息处理器（Large Message Handler）。
 *
 * <p>属于基础设施层（infrastructure/largemsg），专门处理超长日志消息（Stack trace、序列化 JSON、报表行等），
 * 避免对整段文本执行昂贵的正则匹配导致 OOM 或长尾延迟。
 *
 * <p>三级处理策略：
 * <ol>
 *   <li>消息长度 &le; {@value #MAX_SCAN_SIZE}：直接交给 {@link MaskingPort} 完整脱敏；</li>
 *   <li>{@value #MAX_SCAN_SIZE} &lt; 长度 &le; {@value #MAX_MESSAGE_SIZE}：仅扫描首尾各 4KB，中间原样保留（加标记）；</li>
 *   <li>长度 &gt; {@value #MAX_MESSAGE_SIZE}：同上策略，但中间部分替换为 {@code [TRUNCATED:N chars:NOT_SCANNED]}，
 *       防止输出日志文件本身被撑爆。</li>
 * </ol>
 *
 * <p>业务取舍：长消息"中间不扫描"是有意为之 —— 绝大多数敏感字段（卡号、姓名）
 * 出现在请求首部（{@code cardNo=...}）或堆栈顶端，业务可接受此漏检范围。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class LargeMessageHandler {

    /**
     * 单段扫描字节数：单段为 8KB 的一半即 4KB（首段 + 尾段 = 8KB 总扫描量）。
     */
    private static final int MAX_SCAN_SIZE = 8192;

    /**
     * 单条日志消息最大保留字节数：超过即视为超大消息，强制截断。
     */
    private static final int MAX_MESSAGE_SIZE = 65536;

    /**
     * 脱敏引擎引用，用于对首/尾片段执行实际脱敏。
     */
    private final MaskingPort engine;

    /**
     * 构造大消息处理器。
     *
     * @param engine 脱敏引擎，不可为 {@code null}
     */
    public LargeMessageHandler(MaskingPort engine) {
        this.engine = engine;
    }

    /**
     * 对给定日志消息执行"分级脱敏"。
     *
     * <p>处理流程参见类级 JavaDoc 中的三级策略。
     *
     * @param message 原始日志消息；{@code null} 直接返回 {@code null}
     * @return 脱敏后的消息（含可能的截断标记）
     */
    public String handle(String message) {
        if (message == null) return null;
        int length = message.length();

        if (length > MAX_MESSAGE_SIZE) {
            int halfScan = MAX_SCAN_SIZE / 2;
            String headScanned = processSegment(message.substring(0, halfScan));
            String tailScanned = processSegment(message.substring(length - halfScan));
            int truncatedLen = length - MAX_SCAN_SIZE;
            return headScanned
                + "\n...[TRUNCATED:" + truncatedLen + "chars:NOT_SCANNED]...\n"
                + tailScanned;
        }

        if (length > MAX_SCAN_SIZE) {
            int halfScan = MAX_SCAN_SIZE / 2;
            String headScanned = processSegment(message.substring(0, halfScan));
            String tailScanned = processSegment(message.substring(length - halfScan));
            return headScanned
                + message.substring(halfScan, length - halfScan)
                + " [LARGE_MSG_MIDDLE_UNSCANNED]"
                + tailScanned;
        }

        LogContext ctx = LogContext.builder().message(message).build();
        MaskingResult result = engine.process(message, ctx);
        return result.getMasked();
    }

    /**
     * 对单个片段执行脱敏（{@link #handle} 内部调用）。
     *
     * <p>每个片段分别构造 {@link LogContext} 并调用引擎，保证 mdc/logger 等元数据独立。
     *
     * @param segment 文本片段（长度 &le; {@value #MAX_SCAN_SIZE} / 2）
     * @return 脱敏后的片段
     */
    private String processSegment(String segment) {
        LogContext ctx = LogContext.builder().message(segment).build();
        MaskingResult result = engine.process(segment, ctx);
        return result.getMasked();
    }
}