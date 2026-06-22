package com.example.anonymization.core.infrastructure.version;

import com.example.anonymization.api.version.Version;
import com.example.anonymization.api.version.VersionCompatPolicy;

/**
 * 默认版本兼容策略实现 —— 基于 SemVer 规范的兼容性判断。
 *
 * <p>属于基础设施层（infrastructure/version），实现 {@link VersionCompatPolicy} 接口。
 *
 * <p>兼容性规则：
 * <ul>
 *   <li><b>兼容</b>：相同 MAJOR 版本（如 1.0.0 与 1.5.2 兼容）</li>
 *   <li><b>不兼容</b>：不同 MAJOR 版本（如 1.0.0 与 2.0.0 不兼容）</li>
 *   <li><b>废弃</b>：MAJOR 版本落后当前版本 {@code deprecatedThreshold} 个及以上（默认 2）</li>
 * </ul>
 *
 * <p>示例（当前版本 3.x.x）：
 * <pre>
 *   Version 3.0.0 → 兼容, 未废弃, 受支持
 *   Version 2.5.0 → 不兼容, 未废弃, 不受支持
 *   Version 1.0.0 → 不兼容, 已废弃, 不受支持
 * </pre>
 *
 * <p>线程安全：无状态，所有方法纯函数。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class DefaultVersionCompatPolicy implements VersionCompatPolicy {

    /** 当前 SDK 版本。 */
    private final Version currentVersion;

    /** 废弃阈值：MAJOR 版本落后当前版本多少个视为废弃。 */
    private final int deprecatedThreshold;

    /**
     * 使用默认配置构造（当前版本 1.0.0，废弃阈值 2）。
     */
    public DefaultVersionCompatPolicy() {
        this(Version.current(), 2);
    }

    /**
     * 构造自定义版本兼容策略。
     *
     * @param currentVersion     当前版本
     * @param deprecatedThreshold 废弃阈值（MAJOR 版本差 >= 此值视为废弃）
     */
    public DefaultVersionCompatPolicy(Version currentVersion, int deprecatedThreshold) {
        if (currentVersion == null) {
            throw new IllegalArgumentException("currentVersion must not be null");
        }
        if (deprecatedThreshold < 1) {
            throw new IllegalArgumentException("deprecatedThreshold must be >= 1");
        }
        this.currentVersion = currentVersion;
        this.deprecatedThreshold = deprecatedThreshold;
    }

    @Override
    public boolean isCompatible(Version v1, Version v2) {
        if (v1 == null || v2 == null) {
            return false;
        }
        return v1.getMajor() == v2.getMajor();
    }

    @Override
    public boolean isDeprecated(Version version) {
        if (version == null) {
            return true;
        }
        int majorDiff = currentVersion.getMajor() - version.getMajor();
        return majorDiff >= deprecatedThreshold;
    }

    @Override
    public Version getCurrentVersion() {
        return currentVersion;
    }
}