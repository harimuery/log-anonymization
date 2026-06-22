package com.example.anonymization.core.infrastructure.detector;

import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.model.DetectorConfig;

/**
 * re2j 身份证号检测器（中国大陆 18 位身份证）。
 *
 * <p>属于基础设施层（infrastructure/detector），继承自 {@link AbstractRegexDetector}，
 * 识别形如 {@code 11010519491231002X} 的 18 位身份证号（含末位 X）。
 * 核心特性：
 * <ul>
 *   <li>使用 re2j 引擎编译正则（线性时间复杂度，彻底规避 ReDoS）；</li>
 *   <li>叠加 GB 11643-1999 规定的校验位算法（加权因子 + 模 11），将误报率降至接近 0；</li>
 *   <li>对外暴露 {@link SensitiveDataType#ID_CARD}，便于 {@code DetectorRegistry} 路由。</li>
 * </ul>
 *
 * <p>典型调用链路：
 * <pre>
 *   Pipeline → DetectionStage → DetectorRegistry#getDetector(ID_CARD)
 *     → Re2jIdCardDetector#detect
 *     → AbstractRegexDetector#detect（匹配所有候选）
 *     → 本类#validate → 本类#validateIdCardChecksum
 * </pre>
 *
 * <p>线程安全：依赖 {@link AbstractRegexDetector#compiledPatterns} 不可变 Pattern，无状态。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class Re2jIdCardDetector extends AbstractRegexDetector {

    /**
     * 构造身份证检测器。
     *
     * @param config 检测器配置，其中 {@link DetectorConfig#getPatterns()} 至少应包含 1 条
     *               18 位身份证正则（如 {@code \b\d{17}[0-9Xx]\b}）
     */
    public Re2jIdCardDetector(DetectorConfig config) {
        super(config);
    }

    /**
     * 二次校验钩子：仅当候选片段通过身份证校验位才认定为合法身份证号。
     *
     * @param matched 正则命中的候选字符串（长度必须为 18）
     * @return {@code true} 表示通过校验位计算，{@code false} 表示忽略此匹配
     */
    @Override
    protected boolean validate(String matched) {
        return validateIdCardChecksum(matched);
    }

    /**
     * 当前检测器声明所支持的敏感数据类型。
     *
     * @return {@link SensitiveDataType#ID_CARD}
     */
    @Override
    public SensitiveDataType getSupportedType() { return SensitiveDataType.ID_CARD; }

    /**
     * 返回检测器唯一名称（用于日志/指标）。
     *
     * @return 固定值 {@code "RE2J-ID_CARD"}
     */
    @Override
    public String getDetectorName() { return "RE2J-ID_CARD"; }

    /**
     * 身份证校验位算法（GB 11643-1999）。
     *
     * <p>算法步骤：
     * <ol>
     *   <li>将身份证前 17 位与加权因子 {@code {7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2}} 逐位相乘并求和；</li>
     *   <li>求和结果对 11 取模，查表 {@code {'1','0','X','9','8','7','6','5','4','3','2'}} 得到期望校验位；</li>
     *   <li>比较身份证第 18 位（不区分大小写）与期望校验位。</li>
     * </ol>
     *
     * @param idCard 待校验字符串；{@code null} 或长度不为 18 直接返回 {@code false}
     * @return {@code true} 表示校验位匹配，{@code false} 表示不合法
     */
    private boolean validateIdCardChecksum(String idCard) {
        if (idCard == null || idCard.length() != 18) return false;
        int[] weights = {7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2};
        char[] checkCodes = {'1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'};
        int sum = 0;
        for (int i = 0; i < 17; i++) {
            int digit = idCard.charAt(i) - '0';
            if (digit < 0 || digit > 9) return false;
            sum += digit * weights[i];
        }
        char expectedCheckCode = checkCodes[sum % 11];
        char actualCheckCode = Character.toUpperCase(idCard.charAt(17));
        return expectedCheckCode == actualCheckCode;
    }
}