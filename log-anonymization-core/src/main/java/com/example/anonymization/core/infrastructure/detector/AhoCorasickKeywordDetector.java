package com.example.anonymization.core.infrastructure.detector;

import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.model.DetectionResult;
import com.example.anonymization.api.model.DetectorConfig;
import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.spi.SensitiveDataDetector;
import org.ahocorasick.trie.Emit;
import org.ahocorasick.trie.Trie;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Aho-Corasick 关键字检测器 —— 基于 AC 自动机的多模式精确关键字匹配。
 *
 * <p>属于基础设施层（infrastructure/detector），是执行计划 §5.2 中定义的"辅助引擎"，
 * 仅用于精确关键字匹配（如 {@code password}、{@code cardNo}、{@code apiKey} 等），
 * 与正则引擎（RE2J）解决不同层面的问题。
 *
 * <p>设计要点：
 * <ul>
 *   <li>AC 自动机在构造时一次性构建，运行时 O(n + m + z) 线性扫描；</li>
 *   <li>适用于"字段名 + 上下文关键字"组合匹配，如 {@code cardNo=622202...}；</li>
 *   <li>当 {@link DetectorConfig#getContextPattern()} 非空时，先定位关键字位置，
 *       再用上下文模式提取关键字后的值区间；</li>
 *   <li>当 contextPattern 为空时，仅返回关键字本身的位置（用于字段名匹配场景）。</li>
 * </ul>
 *
 * <p>性能：AC 自动机构建为 O(m)（m 为所有关键字长度之和），匹配为 O(n + z)
 * （n 为文本长度，z 为命中数），远优于逐个关键字 {@code indexOf} 的 O(n * k)。
 *
 * @author log-anonymization
 * @since 1.0.0
 */
public class AhoCorasickKeywordDetector implements SensitiveDataDetector {

    private final DetectorConfig config;
    private final Trie trie;
    private final com.google.re2j.Pattern contextRe2jPattern;

    /**
     * 构造 AC 关键字检测器。
     *
     * <p>在构造时一次性构建 AC 自动机（Trie），避免热路径构建开销。
     * 若配置了 contextPattern，则同时编译为 RE2J Pattern 用于值提取。
     *
     * @param config 检测器配置，keywords 列表不能为空
     */
    public AhoCorasickKeywordDetector(DetectorConfig config) {
        this.config = config;
        Trie trieBuilder = Trie.builder()
            .ignoreCase()
            .addKeywords(config.getKeywords())
            .build();
        this.trie = trieBuilder;

        if (config.getContextPattern() != null && !config.getContextPattern().isBlank()) {
            this.contextRe2jPattern = com.google.re2j.Pattern.compile(config.getContextPattern());
        } else {
            this.contextRe2jPattern = null;
        }
    }

    /**
     * 执行关键字检测。
     *
     * <p>检测流程：
     * <ol>
     *   <li>AC 自动机全文扫描，定位所有关键字出现位置；</li>
     *   <li>若配置了 contextPattern，在关键字附近区域用 RE2J 提取值区间；</li>
     *   <li>否则返回关键字位置本身作为检测结果。</li>
     * </ol>
     *
     * @param context 日志上下文
     * @return 检测结果列表
     */
    @Override
    public List<DetectionResult> detect(LogContext context) {
        String text = context.getMessage();
        if (text == null || text.isEmpty()) {
            return List.of();
        }

        Collection<Emit> emits = trie.parseText(text);
        if (emits.isEmpty()) {
            return List.of();
        }

        List<DetectionResult> results = new ArrayList<>();
        for (Emit emit : emits) {
            if (contextRe2jPattern != null) {
                results.addAll(detectWithContextPattern(text, emit));
            } else {
                results.add(new DetectionResult(
                    emit.getStart(), emit.getEnd() + 1,
                    getSupportedType(), 0.85,
                    text.substring(emit.getStart(), emit.getEnd() + 1)
                ));
            }
        }
        return results;
    }

    /**
     * 在关键字附近区域使用上下文模式提取值。
     *
     * <p>策略：从关键字结束位置开始，向后搜索 contextPattern 匹配，
     * 提取匹配到的值区间作为敏感数据位置。
     *
     * @param text  原始文本
     * @param emit  AC 自动机命中的关键字位置
     * @return 值区间的检测结果列表
     */
    private List<DetectionResult> detectWithContextPattern(String text, Emit emit) {
        List<DetectionResult> results = new ArrayList<>();
        int searchStart = emit.getEnd() + 1;
        if (searchStart >= text.length()) {
            return results;
        }

        String searchRegion = text.substring(searchStart);
        com.google.re2j.Matcher matcher = contextRe2jPattern.matcher(searchRegion);
        if (matcher.find()) {
            String matched = matcher.group();
            int valueStart = searchStart + matcher.start();
            int valueEnd = searchStart + matcher.end();
            results.add(new DetectionResult(
                valueStart, valueEnd,
                getSupportedType(), 0.9, matched
            ));
        }
        return results;
    }

    @Override
    public SensitiveDataType getSupportedType() {
        return SensitiveDataType.CUSTOM;
    }

    @Override
    public String getDetectorName() {
        return "KEYWORD_AC";
    }
}