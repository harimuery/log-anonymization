package com.example.anonymization.core.infrastructure.detector;

import com.example.anonymization.api.model.DetectionResult;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * 检测结果聚合器（Result Aggregator）。
 *
 * <p>属于基础设施层（infrastructure/detector），是一个无状态的工具类，
 * 解决"多个检测器对同一文本命中区间相互重叠/嵌套"时的合并问题。
 *
 * <p>典型场景：
 * <ul>
 *   <li>银行卡正则检测器命中区间 {@code [10, 26)}（16 位卡号）；</li>
 *   <li>字段名检测器同时命中 {@code [4, 26)}（{@code cardNo=6222021234567890}）；</li>
 *   <li>两者重叠，必须合并为 {@code [4, 26)} 单一区间，避免下游 Masker 重复打码。</li>
 * </ul>
 *
 * <p>合并策略：扫描线算法 + 贪心扩展
 * <ol>
 *   <li>先按 {@code startIndex} 升序排序；</li>
 *   <li>顺序遍历，若下一结果与当前区间重叠或相邻（{@code start <= current.end}）则保留更长者；</li>
 *   <li>否则将当前区间推入结果集，开始新区间。</li>
 * </ol>
 *
 * <p>线程安全：纯函数实现，无共享状态，可并发调用。
 *
 * @author java-architect
 * @since 1.0.0
 */
public final class ResultAggregator {

    /**
     * 私有构造器，工具类不允许实例化。
     */
    private ResultAggregator() {}

    /**
     * 对检测结果列表执行合并去重，返回按 {@code startIndex} 升序、无区间重叠的新列表。
     *
     * <p>时间复杂度：O(N log N)，主要来自排序步骤。
     * <p>空间复杂度：O(N)，输出新列表（不可变）。
     *
     * @param results 多个检测器返回的原始结果（顺序不限、可重叠）
     * @return 合并后的结果列表（{@link List#copyOf} 不可变快照）；入参为 {@code null} 或空时返回空列表
     */
    public static List<DetectionResult> aggregate(List<DetectionResult> results) {
        if (results == null || results.isEmpty()) return List.of();

        List<DetectionResult> sorted = results.stream()
            .sorted(Comparator.comparingInt(DetectionResult::startIndex))
            .toList();

        List<DetectionResult> merged = new ArrayList<>();
        DetectionResult current = null;
        for (DetectionResult result : sorted) {
            if (current == null) {
                current = result;
            } else if (result.startIndex() <= current.endIndex()) {
                if (result.length() > current.length()) {
                    current = result;
                }
            } else {
                merged.add(current);
                current = result;
            }
        }
        if (current != null) {
            merged.add(current);
        }

        return List.copyOf(merged);
    }
}