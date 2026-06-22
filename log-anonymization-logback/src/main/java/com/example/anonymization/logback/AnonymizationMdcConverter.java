package com.example.anonymization.logback;

import ch.qos.logback.classic.pattern.ClassicConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;
import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.model.MaskingResult;
import com.example.anonymization.api.port.MaskingPort;

import java.util.Map;

/**
 * MDC 属性脱敏转换器（Logback Converter）。
 *
 * <p>属于 logback 集成模块，继承自 {@link ClassicConverter}，
 * 用于在日志格式化为字符串时对 MDC（Mapped Diagnostic Context）中的每个键值执行脱敏。
 * 核心场景：traceId、userId、realIp 等常常携带敏感字段（如身份证号、手机号），
 * 本类对 MDC 的每个 value 调用 {@link MaskingPort#process} 进行脱敏。
 *
 * <p>典型配置（{@code logback-spring.xml}）：
 * <pre>
 *   &lt;conversionRule conversionWord="maskedMdc"
 *                   converterClass="com.example.anonymization.logback.AnonymizationMdcConverter"/&gt;
 *   &lt;pattern&gt;%d{HH:mm:ss.SSS} [%thread] %-5level %logger - %maskedMdc%n&lt;/pattern&gt;
 * </pre>
 *
 * <p>依赖：由 Spring 通过 {@link #setMaskingPort(MaskingPort)} 注入脱敏端口；
 * 未注入时退化为仅做 {@code key=value} 格式化（不做脱敏）。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class AnonymizationMdcConverter extends ClassicConverter {

    /**
     * 脱敏端口。由 Spring 容器注入。
     */
    private MaskingPort maskingPort;

    /**
     * 转换 MDC 属性为字符串。
     *
     * <p>格式：{@code key1=maskedValue1 key2=maskedValue2 ...}。
     * 未注入 {@link #maskingPort} 时直接按 {@code key=value} 拼接（无脱敏）。
     *
     * @param event Logback 日志事件
     * @return 脱敏后的 MDC 字符串
     */
    @Override
    public String convert(ILoggingEvent event) {
        if (maskingPort == null) {
            return formatMdc(event.getMDCPropertyMap());
        }
        Map<String, String> mdcMap = event.getMDCPropertyMap();
        if (mdcMap == null || mdcMap.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : mdcMap.entrySet()) {
            if (sb.length() > 0) sb.append(" ");
            String value = entry.getValue();
            LogContext ctx = LogContext.builder().message(value).build();
            MaskingResult result = maskingPort.process(value, ctx);
            sb.append(entry.getKey()).append("=").append(result.getMasked());
        }
        return sb.toString();
    }

    /**
     * 将 MDC Map 格式化为 {@code key=value} 字符串（不做脱敏）。
     *
     * <p>仅在 {@link #maskingPort} 未注入时使用，是 Logback 默认行为的兼容路径。
     *
     * @param mdcMap MDC 属性映射表
     * @return 拼接后的字符串
     */
    private String formatMdc(Map<String, String> mdcMap) {
        if (mdcMap == null || mdcMap.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        mdcMap.forEach((k, v) -> {
            if (sb.length() > 0) sb.append(" ");
            sb.append(k).append("=").append(v);
        });
        return sb.toString();
    }

    /**
     * Spring 容器注入入口。
     *
     * @param maskingPort 脱敏端口；传 {@code null} 表示走无脱敏路径
     */
    public void setMaskingPort(MaskingPort maskingPort) {
        this.maskingPort = maskingPort;
    }
}