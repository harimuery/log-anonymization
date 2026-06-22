package com.example.anonymization.core.infrastructure.filter;

import com.example.anonymization.api.model.DetectionResult;
import com.google.re2j.Pattern;

import java.util.ArrayList;
import java.util.List;

/**
 * 白名单过滤器 —— 从检测结果中排除已知非敏感数据匹配，降低误杀率。
 *
 * <p>使用场景：在 {@link com.example.anonymization.core.infrastructure.detector.CompositeDetector}
 * 或 {@link com.example.anonymization.core.infrastructure.detector.ResultAggregator} 之后调用，
 * 过滤掉 UUID、时间戳、流水号、版本号等常见格式的误匹配。
 *
 * <p>过滤策略：对每条 {@link DetectionResult}，提取其 {@code matchedValue}，
 * 依次匹配白名单正则；若任一正则完整匹配，则视为非敏感数据，从结果集中移除。
 *
 * <p>性能分析：
 * <ul>
 *   <li>白名单正则数量少（默认 4 条），且均为预编译 RE2J Pattern，单次匹配耗时 &lt; 1μs</li>
 *   <li>过滤操作在检测结果列表上执行，列表通常 &lt; 10 条，总开销可忽略</li>
 * </ul>
 *
 * <p>扩展性：支持通过构造器注入自定义白名单模式列表，
 * 业务方可添加自身系统的特定非敏感格式（如内部 traceId 格式）。
 *
 * <p>线程安全：白名单模式列表在构造时确定后不可变，{@link #filter} 方法无状态可并发调用。
 *
 * @author log-anonymization
 */
public class WhitelistFilter {

    /**
     * 白名单正则模式列表（不可变快照）。
     */
    private final List<Pattern> whitelistPatterns;

    /**
     * 构造默认白名单过滤器（使用 {@link DefaultWhitelistPatterns#DEFAULT_PATTERNS}）。
     */
    public WhitelistFilter() {
        this(DefaultWhitelistPatterns.DEFAULT_PATTERNS);
    }

    /**
     * 构造自定义白名单过滤器。
     *
     * @param patterns 白名单正则模式列表（构造后不可修改，调用方应自行防御性拷贝）
     */
    public WhitelistFilter(List<Pattern> patterns) {
        this.whitelistPatterns = List.copyOf(patterns);
    }

    /**
     * 过滤检测结果 —— 移除匹配白名单模式的非敏感数据。
     *
     * <p>算法：遍历每条 {@link DetectionResult}，提取 {@code matchedValue}，
     * 依次与白名单正则匹配；若任一正则完整匹配，则排除该结果。
     *
     * <p>时间复杂度：O(N × M)，其中 N 为检测结果数，M 为白名单模式数。
     * 实际场景中 N 通常 &lt; 10，M = 4，总开销 &lt; 10μs。
     *
     * @param results 原始检测结果列表
     * @return 过滤后的结果列表（可能为空列表，绝不返回 null）
     */
    public List<DetectionResult> filter(List<DetectionResult> results) {
        if (results == null || results.isEmpty()) return List.of();

        List<DetectionResult> filtered = new ArrayList<>(results.size());
        for (DetectionResult result : results) {
            if (!isWhitelisted(result.matchedValue())) {
                filtered.add(result);
            }
        }
        return filtered;
    }

    /**
     * 判断给定值是否匹配任一白名单模式。
     *
     * @param value 待判断的字符串
     * @return {@code true} 表示匹配白名单（应排除），{@code false} 表示不匹配（保留）
     */
    public boolean isWhitelisted(String value) {
        if (value == null || value.isEmpty()) return false;
        for (Pattern pattern : whitelistPatterns) {
            if (pattern.matcher(value).matches()) {
                return true;
            }
        }
        return false;
    }

    /**
     * 获取当前白名单模式数量（用于监控指标）。
     *
     * @return 模式数量
     */
    public int patternCount() {
        return whitelistPatterns.size();
    }
}