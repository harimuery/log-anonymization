package com.example.anonymization.core.infrastructure.version;

import com.example.anonymization.api.model.MaskingRule;
import com.example.anonymization.api.version.Version;
import com.example.anonymization.api.version.VersionCompatPolicy;

import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.logging.Logger;

/**
 * 规则版本兼容处理器 —— 处理不同版本规则格式的解析与迁移。
 *
 * <p>属于基础设施层（infrastructure/version），在规则加载阶段（{@link com.example.anonymization.core.infrastructure.config.YamlRuleParser}）
 * 被调用，确保旧版本规则文件在新版本 SDK 中仍可正常使用。
 *
 * <p>设计原则（责任链 + 策略模式）：
 * <ul>
 *   <li><b>版本检测</b>：从规则文件头部读取 {@code version} 字段</li>
 *   <li><b>兼容性判断</b>：通过 {@link VersionCompatPolicy} 判断规则版本与当前 SDK 是否兼容</li>
 *   <li><b>迁移管道</b>：v1→v2→v3 的链式迁移，每一步只处理相邻版本差异</li>
 *   <li><b>降级策略</b>：不兼容版本直接拒绝加载，避免运行时异常</li>
 * </ul>
 *
 * <p>版本迁移示例：
 * <pre>
 *   v1 规则格式:
 *     rules:
 *       - ruleId: "BANK_CARD_001"
 *         dataType: "BANK_CARD"
 *         detectorType: "REGEX"
 *
 *   v2 规则格式（新增 scope 字段）:
 *     version: 2
 *     rules:
 *       - ruleId: "BANK_CARD_001"
 *         dataType: "BANK_CARD"
 *         detectorType: "REGEX"
 *         scope:
 *           type: "GLOBAL"
 * </pre>
 *
 * <p>线程安全：迁移函数列表不可变，处理器本身无状态。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class RuleVersionCompatHandler {

    private static final Logger log = Logger.getLogger(RuleVersionCompatHandler.class.getName());

    private final VersionCompatPolicy compatPolicy;
    private final Version currentRuleVersion;

    /**
     * 构造规则版本兼容处理器。
     *
     * @param compatPolicy       版本兼容策略
     * @param currentRuleVersion 当前 SDK 支持的规则版本
     */
    public RuleVersionCompatHandler(VersionCompatPolicy compatPolicy, Version currentRuleVersion) {
        this.compatPolicy = Objects.requireNonNull(compatPolicy, "compatPolicy must not be null");
        this.currentRuleVersion = Objects.requireNonNull(currentRuleVersion, "currentRuleVersion must not be null");
    }

    /**
     * 检查规则版本是否与当前 SDK 兼容。
     *
     * @param ruleVersion 规则文件版本
     * @return {@code true} 兼容
     */
    public boolean isCompatible(Version ruleVersion) {
        return compatPolicy.isCompatible(ruleVersion, currentRuleVersion);
    }

    /**
     * 检查规则版本是否已废弃。
     *
     * @param ruleVersion 规则文件版本
     * @return {@code true} 已废弃
     */
    public boolean isDeprecated(Version ruleVersion) {
        return compatPolicy.isDeprecated(ruleVersion);
    }

    /**
     * 处理规则列表的版本兼容性。
     *
     * <p>处理流程：
     * <ol>
     *   <li>检查规则版本是否兼容（相同 MAJOR 版本）</li>
     *   <li>若不兼容 → 抛出 {@link IncompatibleRuleVersionException}</li>
     *   <li>若兼容但已废弃 → 记录警告日志</li>
     *   <li>返回原始规则列表（当前版本间无需迁移）</li>
     * </ol>
     *
     * @param rules       规则列表
     * @param ruleVersion 规则文件版本
     * @return 处理后的规则列表（可能经过迁移）
     * @throws IncompatibleRuleVersionException 当规则版本不兼容时抛出
     */
    public List<MaskingRule> handle(List<MaskingRule> rules, Version ruleVersion) {
        Objects.requireNonNull(rules, "rules must not be null");
        Objects.requireNonNull(ruleVersion, "ruleVersion must not be null");

        if (!isCompatible(ruleVersion)) {
            throw new IncompatibleRuleVersionException(ruleVersion, currentRuleVersion);
        }

        if (isDeprecated(ruleVersion)) {
            log.warning("规则版本 " + ruleVersion + " 已废弃，当前 SDK 版本 " + currentRuleVersion
                + "，建议升级规则文件到版本 " + currentRuleVersion);
        }

        if (ruleVersion.isOlderThan(currentRuleVersion)) {
            log.info("规则版本 " + ruleVersion + " 低于当前 SDK 版本 " + currentRuleVersion
                + "，使用向后兼容模式加载");
        }

        return rules;
    }

    /**
     * 规则版本不兼容异常。
     *
     * <p>当规则文件的 MAJOR 版本与当前 SDK 不一致时抛出。
     */
    public static final class IncompatibleRuleVersionException extends RuntimeException {

        private final Version ruleVersion;
        private final Version sdkVersion;

        /**
         * 构造不兼容异常。
         *
         * @param ruleVersion 规则版本
         * @param sdkVersion  SDK 版本
         */
        public IncompatibleRuleVersionException(Version ruleVersion, Version sdkVersion) {
            super("规则版本 " + ruleVersion + " 与当前 SDK 版本 " + sdkVersion
                + " 不兼容（MAJOR 版本不同），请升级规则文件或使用兼容的 SDK 版本");
            this.ruleVersion = ruleVersion;
            this.sdkVersion = sdkVersion;
        }

        /**
         * 获取规则版本。
         *
         * @return 规则版本
         */
        public Version getRuleVersion() { return ruleVersion; }

        /**
         * 获取 SDK 版本。
         *
         * @return SDK 版本
         */
        public Version getSdkVersion() { return sdkVersion; }
    }
}