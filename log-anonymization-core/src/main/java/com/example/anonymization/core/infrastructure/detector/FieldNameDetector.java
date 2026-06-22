package com.example.anonymization.core.infrastructure.detector;

import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.model.DetectionResult;
import com.example.anonymization.api.model.DetectorConfig;
import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.spi.SensitiveDataDetector;

import java.util.ArrayList;
import java.util.List;

/**
 * 字段名定位型检测器（Field Name Detector）。
 *
 * <p>属于基础设施层（infrastructure/detector），基于"键值对"日志格式启发式实现，
 * 通过字段名（如 {@code password} / {@code cardNo} / {@code mobile}）定位后续值区间，
 * 适用于 JSON、Form 编码、KV 字符串等结构化或半结构化日志。
 *
 * <p>典型业务场景：
 * <ul>
 *   <li>日志格式为 {@code password=123456&mobile=13800138000}，需识别键后的整段值；</li>
 *   <li>日志格式为 {@code {"password":"123456","mobile":"13800138000"}}，需跳过引号包裹；</li>
 *   <li>作为正则检测器的补充：先用字段名粗筛，再用正则二次校验。</li>
 * </ul>
 *
 * <p>职责边界：
 * <ul>
 *   <li>不参与敏感数据的最终判定（无业务含义的字段名不会被加载）；</li>
 *   <li>区间起止由 {@link #findValueStart} / {@link #findValueEnd} 启发式确定，可能误报；</li>
 *   <li>置信度固定 0.9（低于正则 + 校验位 1.0），下游可结合其他证据综合判断。</li>
 * </ul>
 *
 * <p>性能：O(N * K)，N 为文本长度，K 为字段名数量；
 * 字段名匹配使用 {@link String#indexOf(String, int)} 避免正则回溯带来的 ReDoS 风险。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class FieldNameDetector implements SensitiveDataDetector {

    /**
     * 检测器配置，承载 {@code fieldNames} 黑名单/白名单（如 {@code [password, mobile, idCard]}）。
     * 由 Spring 在装配阶段注入，运行时不可变。
     */
    private final DetectorConfig config;

    /**
     * 构造字段名检测器。
     *
     * @param config 检测器配置，不可为 {@code null}，
     *               其中 {@link DetectorConfig#getFieldNames()} 提供需定位的字段名集合
     */
    public FieldNameDetector(DetectorConfig config) {
        this.config = config;
    }

    /**
     * 执行检测：对每个字段名在文本中查找所有出现位置，并截取其后的"值"区间。
     *
     * <p>实现要点：
     * <ul>
     *   <li>使用 {@link String#indexOf(String, int)} 循环定位全部出现位置；</li>
     *   <li>值起止由启发式规则（{@code = : " '} 分隔符 + 空白）确定；</li>
     *   <li>每个匹配以 {@link DetectionResult} 形式返回，置信度 0.9；</li>
     *   <li>区间无交集时多结果可同时存在，区间重叠时由 {@link ResultAggregator} 在外层合并。</li>
     * </ul>
     *
     * @param context 日志上下文，取 {@link LogContext#getMessage()} 作为待扫描文本
     * @return 检测结果列表（区间为文本中的绝对偏移量），无命中或 {@code fieldNames} 为空时返回空列表
     */
    @Override
    public List<DetectionResult> detect(LogContext context) {
        String text = context.getMessage();
        List<DetectionResult> results = new ArrayList<>();
        for (String fieldName : config.getFieldNames()) {
            int idx = text.indexOf(fieldName);
            while (idx >= 0) {
                int valueStart = findValueStart(text, idx + fieldName.length());
                int valueEnd = findValueEnd(text, valueStart);
                if (valueStart < valueEnd) {
                    String matched = text.substring(valueStart, valueEnd);
                    results.add(new DetectionResult(
                        valueStart, valueEnd, getSupportedType(), 0.9, matched
                    ));
                }
                idx = text.indexOf(fieldName, idx + 1);
            }
        }
        return results;
    }

    /**
     * 在字段名之后定位"值的起始位置"。
     *
     * <p>跳过以下字符：{@code =}、{@code :}、{@code "}、{@code '}、空白字符。
     * 适用于 {@code key=value}、{@code key:value}、{@code "key":"value"} 等多种格式。
     *
     * @param text    原始文本
     * @param fromIdx 字段名结束位置（{@code fromIdx} = 字段名起始 + 字段名长度）
     * @return 值的起始偏移量；若未找到非分隔符字符则返回 {@code text.length()}（兜底）
     */
    private int findValueStart(String text, int fromIdx) {
        for (int i = fromIdx; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '=' || c == ':' || c == '"' || c == '\'') continue;
            if (Character.isWhitespace(c)) continue;
            return i;
        }
        return text.length();
    }

    /**
     * 从值的起始位置向后扫描，遇到第一个终止字符时返回。
     *
     * <p>终止字符集：{@code ,}、{@code }}、{@code &}、空格、{@code "}、{@code '}。
     * 未命中终止字符时返回 {@code text.length()}（兜底）。
     *
     * @param text    原始文本
     * @param startIdx 值的起始位置（由 {@link #findValueStart} 给出）
     * @return 值的结束偏移量（半开区间，不包含终止符本身）
     */
    private int findValueEnd(String text, int startIdx) {
        for (int i = startIdx; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == ',' || c == '}' || c == '&' || c == ' ' || c == '"' || c == '\'') {
                return i;
            }
        }
        return text.length();
    }

    /**
     * 当前检测器声明所支持的敏感数据类型。
     *
     * <p>统一返回 {@link SensitiveDataType#CUSTOM}，因为"按字段名识别"覆盖多种数据类型，
     * 不绑定到具体一种（如 PHONE / BANK_CARD）。
     *
     * @return CUSTOM 标识
     */
    @Override
    public SensitiveDataType getSupportedType() { return SensitiveDataType.CUSTOM; }

    /**
     * 返回检测器唯一名称，用于日志/指标维度。
     *
     * @return 固定值 {@code "FIELD_NAME"}
     */
    @Override
    public String getDetectorName() { return "FIELD_NAME"; }
}