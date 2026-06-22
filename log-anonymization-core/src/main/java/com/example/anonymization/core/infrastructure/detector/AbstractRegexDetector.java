package com.example.anonymization.core.infrastructure.detector;

import com.example.anonymization.api.model.DetectionResult;
import com.example.anonymization.api.model.DetectorConfig;
import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.spi.SensitiveDataDetector;
import com.google.re2j.Pattern;
import com.google.re2j.Matcher;

import java.util.ArrayList;
import java.util.List;

/**
 * 正则检测器抽象基类 —— 封装 re2j 编译、匹配、二次校验的标准流程。
 *
 * <p>使用场景：所有基于正则的检测器（如 {@link Re2jBankCardDetector}、
 * {@link Re2jIdCardDetector}、{@link Re2jPhoneDetector}）继承本类，
 * 只需实现 {@link #validate}（二次校验）、{@link #confidence}（置信度）、
 * {@link #getSupportedType}（数据类型）即可。
 *
 * <p>关键设计：
 * <ul>
 *   <li>构造期一次性编译所有 Pattern（避免热路径编译开销）</li>
 *   <li>使用 re2j（线性时间复杂度、无回溯）避免 ReDoS</li>
 *   <li>子类通过 {@link #validate} 钩子加入 Luhn/校验位等二次校验</li>
 * </ul>
 *
 * @author log-anonymization
 */
public abstract class AbstractRegexDetector implements SensitiveDataDetector {

    /** 预编译后的 Pattern 列表（构造时一次性编译） */
    protected final List<Pattern> compiledPatterns;

    /**
     * 构造基类，编译配置中的所有正则模式。
     *
     * @param config 检测器配置（含 patterns 列表）
     */
    protected AbstractRegexDetector(DetectorConfig config) {
        this.compiledPatterns = config.getPatterns().stream()
            .map(Pattern::compile)
            .toList();
    }

    /**
     * 执行检测：遍历所有编译后的 Pattern，对日志消息全文匹配。
     *
     * <p>每个 Pattern 的每次命中都会调用 {@link #validate} 二次校验，
     * 校验通过则封装为 {@link DetectionResult} 加入结果列表。
     *
     * @param context 日志上下文
     * @return 所有命中片段的列表
     */
    @Override
    public List<DetectionResult> detect(LogContext context) {
        String text = context.getMessage();
        List<DetectionResult> results = new ArrayList<>();

        for (Pattern pattern : compiledPatterns) {
            Matcher matcher = pattern.matcher(text);
            while (matcher.find()) {
                String matched = matcher.group();
                if (validate(matched)) {
                    results.add(new DetectionResult(
                        matcher.start(), matcher.end(),
                        getSupportedType(), confidence(), matched
                    ));
                }
            }
        }
        return results;
    }

    /**
     * 二次校验钩子（如 Luhn、身份证校验位等），子类按需覆盖。
     *
     * <p>默认实现永远返回 true；典型覆写见 {@link Re2jBankCardDetector}。
     *
     * @param matched 正则匹配到的字符串
     * @return true 表示校验通过（视为敏感数据）
     */
    protected boolean validate(String matched) { return true; }

    /**
     * 置信度钩子（{@code [0.0, 1.0]}），子类按需覆盖。
     *
     * <p>默认 1.0 表示最高置信度。Luhn 通过/校验位通过时通常为 1.0，
     * 否则可降低置信度让上层做加权判断。
     *
     * @return 置信度
     */
    protected double confidence() { return 1.0; }
}