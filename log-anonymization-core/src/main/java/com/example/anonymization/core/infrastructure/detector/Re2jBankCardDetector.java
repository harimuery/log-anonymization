package com.example.anonymization.core.infrastructure.detector;

import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.model.DetectorConfig;

/**
 * re2j 银行卡号检测器。
 *
 * <p>属于基础设施层（infrastructure/detector），继承自 {@link AbstractRegexDetector}，
 * 实现银行卡号（12~19 位连续数字）的识别。核心特性：
 * <ul>
 *   <li>使用 re2j 引擎编译正则（线性时间复杂度，彻底规避 ReDoS）；</li>
 *   <li>通过 {@link #validate(String)} 钩子叠加 Luhn 二次校验，将误报率降至接近 0；</li>
 *   <li>对外暴露 {@link SensitiveDataType#BANK_CARD}，便于 {@code DetectorRegistry} 路由。</li>
 * </ul>
 *
 * <p>典型调用链路：
 * <pre>
 *   Pipeline → DetectionStage → DetectorRegistry#getDetector(BANK_CARD)
 *     → Re2jBankCardDetector#detect
 *     → AbstractRegexDetector#detect（匹配所有候选）
 *     → 本类#validate（仅放行通过 Luhn 的片段）
 * </pre>
 *
 * <p>线程安全：依赖 {@link AbstractRegexDetector#compiledPatterns} 不可变 Pattern，无状态。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class Re2jBankCardDetector extends AbstractRegexDetector {

    /**
     * 构造银行卡号检测器。
     *
     * @param config 检测器配置，其中 {@link DetectorConfig#getPatterns()} 至少应包含 1 条
     *               银行卡号正则（如 {@code \b(?:\d[ -]*?){13,19}\b} 或 {@code \b\d{16,19}\b}）
     */
    public Re2jBankCardDetector(DetectorConfig config) {
        super(config);
    }

    /**
     * 二次校验钩子：仅当候选片段通过 Luhn 算法才认定为合法卡号。
     *
     * <p>由 {@link AbstractRegexDetector#detect} 在每次正则命中后调用；
     * 该判断将"16 位连续数字"中订单号、流水号、UUID 等伪阳性全部过滤。
     *
     * @param matched 正则命中的候选字符串（纯数字，长度 12~19）
     * @return {@code true} 表示通过 Luhn 校验（即"很可能是真实卡号"），{@code false} 表示忽略此匹配
     */
    @Override
    protected boolean validate(String matched) {
        return LuhnValidator.isValid(matched);
    }

    /**
     * 当前检测器声明所支持的敏感数据类型。
     *
     * @return {@link SensitiveDataType#BANK_CARD}
     */
    @Override
    public SensitiveDataType getSupportedType() { return SensitiveDataType.BANK_CARD; }

    /**
     * 返回检测器唯一名称（用于日志/指标）。
     *
     * @return 固定值 {@code "RE2J-BANK_CARD"}
     */
    @Override
    public String getDetectorName() { return "RE2J-BANK_CARD"; }
}