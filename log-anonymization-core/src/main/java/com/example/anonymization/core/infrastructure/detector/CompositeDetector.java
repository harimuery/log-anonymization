package com.example.anonymization.core.infrastructure.detector;

import com.example.anonymization.api.model.DetectionResult;
import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.spi.SensitiveDataDetector;
import com.example.anonymization.core.infrastructure.filter.WhitelistFilter;

import java.util.ArrayList;
import java.util.List;

/**
 * 组合检测器（Composite Detector）。
 *
 * <p>属于基础设施层（infrastructure/detector），是对 {@link SensitiveDataDetector} 的组合实现。
 * 将多个子检测器组织成一个"复合检测器"，对外呈现为一个检测节点，
 * 主要解决以下业务场景：
 * <ul>
 *   <li>同一文本需同时跑多种检测策略（如：字段名定位 + 正则匹配 + 自定义启发式）；</li>
 *   <li>需要在某些上下文下动态注入额外检测器，而又不希望修改 Pipeline 主链路；</li>
 *   <li>希望检测阶段保持单一入口（{@code DetectorRegistry#getDetector(CUSTOM)}），
 *       由本类在内部完成"多检测器结果合并"。</li>
 * </ul>
 *
 * <p>职责边界：
 * <ul>
 *   <li>仅做"编排 + 合并"，不实现具体检测逻辑；</li>
 *   <li>合并策略委托给 {@link ResultAggregator}，解决区间重叠/嵌套问题；</li>
 *   <li>子检测器列表通过构造器以不可变方式注入，运行时不可更改（线程安全）。</li>
 * </ul>
 *
 * <p>性能注意：组合检测器的时间复杂度 = 子检测器时间复杂度之和；
 * 在 Pipeline 中位于 DetectionStage 时，请控制子检测器数量，避免长尾放大。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class CompositeDetector implements SensitiveDataDetector {

    private final List<SensitiveDataDetector> detectors;

    private final WhitelistFilter whitelistFilter;

    /**
     * 构造组合检测器（使用默认白名单过滤器）。
     *
     * @param detectors 子检测器列表，不可为 {@code null}，允许为空列表
     */
    public CompositeDetector(List<SensitiveDataDetector> detectors) {
        this(detectors, new WhitelistFilter());
    }

    /**
     * 构造组合检测器（指定白名单过滤器）。
     *
     * @param detectors       子检测器列表
     * @param whitelistFilter 白名单过滤器（过滤 UUID/时间戳等非敏感匹配）
     */
    public CompositeDetector(List<SensitiveDataDetector> detectors, WhitelistFilter whitelistFilter) {
        this.detectors = List.copyOf(detectors);
        this.whitelistFilter = whitelistFilter;
    }

    /**
     * 执行检测：依次调用所有子检测器，再通过 {@link ResultAggregator#aggregate} 合并重叠区间。
     *
     * <p>合并策略：当多个检测器命中同一位置（例如银行卡正则与字段名检测器同时命中）
     * 时，仅保留长度更大的那个区间，避免下游 Masker 对同一区域重复打码。
     *
     * @param context 日志上下文（含原始 message、mdc、loggerName 等）
     * @return 合并后的检测结果列表（已按 startIndex 升序），无命中时为空列表
     */
    @Override
    public List<DetectionResult> detect(LogContext context) {
        List<DetectionResult> allResults = new ArrayList<>();
        for (SensitiveDataDetector detector : detectors) {
            allResults.addAll(detector.detect(context));
        }
        List<DetectionResult> aggregated = ResultAggregator.aggregate(allResults);
        return whitelistFilter.filter(aggregated);
    }

    /**
     * 当前检测器声明所支持的敏感数据类型。
     *
     * <p>作为组合检测器，对外统一返回 {@link com.example.anonymization.api.enums.SensitiveDataType#CUSTOM}，
     * 表示"由内部多个子检测器共同覆盖"，避免被 {@code DetectorRegistry} 的精确路由重复调度。
     *
     * @return CUSTOM 标识
     */
    @Override
    public com.example.anonymization.api.enums.SensitiveDataType getSupportedType() {
        return com.example.anonymization.api.enums.SensitiveDataType.CUSTOM;
    }

    /**
     * 返回检测器唯一名称。
     *
     * <p>用于：日志输出、指标打点（{@code masking.detector.name} tag）、规则诊断。
     *
     * @return 固定值 {@code "COMPOSITE"}
     */
    @Override
    public String getDetectorName() { return "COMPOSITE"; }
}