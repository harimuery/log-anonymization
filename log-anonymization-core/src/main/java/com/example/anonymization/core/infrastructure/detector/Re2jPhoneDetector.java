package com.example.anonymization.core.infrastructure.detector;

import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.model.DetectorConfig;

/**
 * re2j 手机号检测器（中国大陆 11 位手机号）。
 *
 * <p>属于基础设施层（infrastructure/detector），继承自 {@link AbstractRegexDetector}，
 * 识别形如 {@code 13800138000} 的 11 位中国大陆手机号。
 * 核心特性：
 * <ul>
 *   <li>使用 re2j 引擎编译正则（线性时间复杂度，彻底规避 ReDoS）；</li>
 *   <li>由 {@link DetectorConfig#getPatterns()} 决定号段（默认 {@code 1[3-9]\d{9}}）；</li>
 *   <li>不依赖二次校验（手机号无统一校验位算法），通过严格号段正则保证低误报；</li>
 *   <li>对外暴露 {@link SensitiveDataType#PHONE}，便于 {@code DetectorRegistry} 路由。</li>
 * </ul>
 *
 * <p>典型调用链路：
 * <pre>
 *   Pipeline → DetectionStage → DetectorRegistry#getDetector(PHONE)
 *     → Re2jPhoneDetector#detect
 *     → AbstractRegexDetector#detect
 * </pre>
 *
 * <p>线程安全：依赖 {@link AbstractRegexDetector#compiledPatterns} 不可变 Pattern，无状态。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class Re2jPhoneDetector extends AbstractRegexDetector {

    /**
     * 构造手机号检测器。
     *
     * @param config 检测器配置，其中 {@link DetectorConfig#getPatterns()} 至少应包含 1 条
     *               手机号正则（默认 {@code \b1[3-9]\d{9}\b}）
     */
    public Re2jPhoneDetector(DetectorConfig config) {
        super(config);
    }

    /**
     * 当前检测器声明所支持的敏感数据类型。
     *
     * @return {@link SensitiveDataType#PHONE}
     */
    @Override
    public SensitiveDataType getSupportedType() { return SensitiveDataType.PHONE; }

    /**
     * 返回检测器唯一名称（用于日志/指标）。
     *
     * @return 固定值 {@code "RE2J-PHONE"}
     */
    @Override
    public String getDetectorName() { return "RE2J-PHONE"; }
}