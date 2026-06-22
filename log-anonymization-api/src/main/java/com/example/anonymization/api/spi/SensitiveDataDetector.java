package com.example.anonymization.api.spi;

import com.example.anonymization.api.model.DetectionResult;
import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.enums.SensitiveDataType;

import java.util.List;

/**
 * 敏感数据检测器 SPI —— 抽象识别敏感数据的算法实现（正则、关键词、字段名、自定义 AI 等）。
 *
 * <p>使用场景：业务方按需实现该接口（继承
 * {@link com.example.anonymization.core.infrastructure.detector.AbstractRegexDetector}
 * 可大幅简化正则检测器实现），并通过
 * {@link com.example.anonymization.core.domain.DetectorRegistry} 注册。
 *
 * <p>实现规范：
 * <ul>
 *   <li>无状态或只读状态（保证线程安全）</li>
 *   <li>高耗时操作应使用 re2j、Aho-Corasick 等线性时间算法</li>
 *   <li>应通过 {@link #getOrder()} 控制多检测器协作顺序</li>
 * </ul>
 *
 * @author log-anonymization
 */
public interface SensitiveDataDetector extends Comparable<SensitiveDataDetector> {

    /**
     * 执行检测：从日志上下文中识别所有命中的敏感数据片段。
     *
     * <p>返回结果中 {@link DetectionResult#startIndex} 与 {@link DetectionResult#endIndex}
     * 是相对于 {@link LogContext#getMessage()} 的字符偏移量。
     *
     * @param context 日志上下文
     * @return 命中片段列表（无命中时返回空列表，绝不返回 null）
     */
    List<DetectionResult> detect(LogContext context);

    /**
     * 获取本检测器支持的敏感数据类型（用于注册表查找）。
     *
     * @return 数据类型枚举值
     */
    SensitiveDataType getSupportedType();

    /**
     * 获取检测器名称（用于日志与监控指标，如 {@code "RE2J-BANK_CARD"}）。
     *
     * @return 检测器名称
     */
    String getDetectorName();

    /**
     * 获取执行顺序（数值越小越先执行，默认 0）。
     *
     * @return 顺序值
     */
    default int getOrder() { return 0; }

    /**
     * 按 {@link #getOrder()} 升序比较。
     *
     * @param other 另一检测器
     * @return 排序结果
     */
    @Override
    default int compareTo(SensitiveDataDetector other) {
        return Integer.compare(this.getOrder(), other.getOrder());
    }
}