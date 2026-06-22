package com.example.anonymization.test;

import com.example.anonymization.api.enums.DetectorType;
import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.model.DetectorConfig;
import com.example.anonymization.api.model.MaskerConfig;
import com.example.anonymization.api.model.MaskingRule;
import com.example.anonymization.api.model.MaskingScope;

import java.util.List;

/**
 * {@link MaskingRule} 测试工厂（Test Factory）。
 *
 * <p>属于 test 模块，提供常用的"测试用规则"静态构造方法，避免在测试用例中重复 builder 链式调用。
 * 内置 4 类规则：银行卡、手机号、身份证、禁用规则。
 *
 * <p>典型用法：
 * <pre>
 *   MaskingRule rule = RuleTestFactory.bankCardRule();
 *   ruleManager.refreshRules(List.of(rule));
 *   // ...
 * </pre>
 *
 * <p>所有规则均设置为 {@code MaskingScope.global()} + {@code enabled=true}（除 {@link #disabledRule}），
 * 通过 {@code priority} 字段控制路由顺序。
 *
 * @author java-architect
 * @since 1.0.0
 */
public final class RuleTestFactory {

    /**
     * 私有构造器，工具类不允许实例化。
     */
    private RuleTestFactory() {}

    /**
     * 构造银行卡号测试规则：检测 16~19 位连续数字（开启 Luhn 校验），打码采用前 4 后 4 保留。
     *
     * @return 银行卡规则（priority=100）
     */
    public static MaskingRule bankCardRule() {
        return MaskingRule.builder()
            .ruleId("TEST-BANK_CARD-001")
            .name("Test Bank Card Rule")
            .dataType(SensitiveDataType.BANK_CARD)
            .detector(DetectorType.REGEX, DetectorConfig.builder()
                .patterns(List.of("\\b(\\d{16,19})\\b"))
                .enableLuhnCheck(true)
                .build())
            .masker(MaskerType.PARTIAL_MASK, MaskerConfig.builder()
                .keepPrefixLen(4)
                .keepSuffixLen(4)
                .maskChar('*')
                .dataType(SensitiveDataType.BANK_CARD)
                .build())
            .scope(MaskingScope.global())
            .priority(100)
            .enabled(true)
            .build();
    }

    /**
     * 构造手机号测试规则：检测 {@code 1[3-9]\\d{9}} 形式的 11 位号码，打码采用前 3 后 4 保留。
     *
     * @return 手机号规则（priority=80）
     */
    public static MaskingRule phoneRule() {
        return MaskingRule.builder()
            .ruleId("TEST-PHONE-001")
            .name("Test Phone Rule")
            .dataType(SensitiveDataType.PHONE)
            .detector(DetectorType.REGEX, DetectorConfig.builder()
                .patterns(List.of("\\b(1[3-9]\\d{9})\\b"))
                .build())
            .masker(MaskerType.PARTIAL_MASK, MaskerConfig.builder()
                .keepPrefixLen(3)
                .keepSuffixLen(4)
                .maskChar('*')
                .dataType(SensitiveDataType.PHONE)
                .build())
            .scope(MaskingScope.global())
            .priority(80)
            .enabled(true)
            .build();
    }

    /**
     * 构造身份证号测试规则：检测 18 位身份证（开启校验位），打码采用前 3 后 4 保留。
     *
     * @return 身份证规则（priority=90）
     */
    public static MaskingRule idCardRule() {
        return MaskingRule.builder()
            .ruleId("TEST-ID_CARD-001")
            .name("Test ID Card Rule")
            .dataType(SensitiveDataType.ID_CARD)
            .detector(DetectorType.REGEX, DetectorConfig.builder()
                .patterns(List.of("\\b(\\d{17}[0-9Xx])\\b"))
                .enableChecksum(true)
                .build())
            .masker(MaskerType.PARTIAL_MASK, MaskerConfig.builder()
                .keepPrefixLen(3)
                .keepSuffixLen(4)
                .maskChar('*')
                .dataType(SensitiveDataType.ID_CARD)
                .build())
            .scope(MaskingScope.global())
            .priority(90)
            .enabled(true)
            .build();
    }

    /**
     * 构造"始终禁用"的占位规则（用于测试规则过滤逻辑）。
     *
     * <p>使用 {@code enabled=false}，因此即使模式匹配也不会被应用。
     *
     * @return 禁用的占位规则
     */
    public static MaskingRule disabledRule() {
        return MaskingRule.builder()
            .ruleId("TEST-DISABLED-001")
            .name("Test Disabled Rule")
            .dataType(SensitiveDataType.CUSTOM)
            .detector(DetectorType.REGEX, DetectorConfig.builder()
                .patterns(List.of("never-match"))
                .build())
            .masker(MaskerType.FULL_MASK, MaskerConfig.builder()
                .maskChar('*')
                .dataType(SensitiveDataType.CUSTOM)
                .build())
            .scope(MaskingScope.global())
            .priority(0)
            .enabled(false)
            .build();
    }
}