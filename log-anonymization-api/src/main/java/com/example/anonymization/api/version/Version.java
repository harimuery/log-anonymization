package com.example.anonymization.api.version;

import java.util.Objects;

/**
 * 语义化版本号值对象（Semantic Versioning 2.0.0）。
 *
 * <p>遵循 <a href="https://semver.org">SemVer</a> 规范：{@code MAJOR.MINOR.PATCH}
 * <ul>
 *   <li><b>MAJOR</b>：不兼容的 API 修改（如删除方法、改变签名）</li>
 *   <li><b>MINOR</b>：向下兼容的功能新增（如新增 default method）</li>
 *   <li><b>PATCH</b>：向下兼容的问题修复（如 Bug 修复）</li>
 * </ul>
 *
 * <p>版本兼容性判断规则：
 * <ul>
 *   <li>相同 MAJOR 版本 → 向后兼容（MINOR/PATCH 差异不影响兼容性）</li>
 *   <li>不同 MAJOR 版本 → 不兼容（可能有 Breaking Change）</li>
 * </ul>
 *
 * <p>使用场景：
 * <ul>
 *   <li>规则文件版本化：YAML 头部 {@code version: 1} 标识规则格式版本</li>
 *   <li>SPI 接口版本化：检测 {@link com.example.anonymization.api.spi.SensitiveDataDetector} 等接口的版本</li>
 *   <li>灰度发布：根据版本号路由到新旧实现</li>
 *   <li>废弃追踪：标记已废弃的 API 版本</li>
 * </ul>
 *
 * <p>不可变值对象：所有字段 final，线程安全。
 *
 * @author java-architect
 * @since 1.0.0
 */
public final class Version implements Comparable<Version> {

    /** 主版本号（不兼容变更时递增）。 */
    private final int major;
    /** 次版本号（向下兼容的功能新增时递增）。 */
    private final int minor;
    /** 修订号（向下兼容的 Bug 修复时递增）。 */
    private final int patch;

    /**
     * 构造版本号。
     *
     * @param major 主版本号（必须 >= 0）
     * @param minor 次版本号（必须 >= 0）
     * @param patch 修订号（必须 >= 0）
     * @throws IllegalArgumentException 当任一版本号 < 0 时抛出
     */
    public Version(int major, int minor, int patch) {
        if (major < 0 || minor < 0 || patch < 0) {
            throw new IllegalArgumentException(
                "Version numbers must be non-negative: " + major + "." + minor + "." + patch);
        }
        this.major = major;
        this.minor = minor;
        this.patch = patch;
    }

    /**
     * 解析版本字符串为 {@link Version} 对象。
     *
     * <p>支持的格式：
     * <ul>
     *   <li>{@code "1.0.0"} → Version(1, 0, 0)</li>
     *   <li>{@code "2.1"} → Version(2, 1, 0)</li>
     *   <li>{@code "3"} → Version(3, 0, 0)</li>
     *   <li>{@code "1.0.0-SNAPSHOT"} → Version(1, 0, 0)（忽略后缀）</li>
     *   <li>{@code "v1.0.0"} → Version(1, 0, 0)（忽略 v 前缀）</li>
     * </ul>
     *
     * @param versionStr 版本字符串
     * @return {@link Version} 实例
     * @throws IllegalArgumentException 当格式无法解析时抛出
     */
    public static Version parse(String versionStr) {
        if (versionStr == null || versionStr.isBlank()) {
            throw new IllegalArgumentException("Version string must not be null or blank");
        }

        String trimmed = versionStr.trim();
        if (trimmed.toLowerCase().startsWith("v")) {
            trimmed = trimmed.substring(1);
        }

        int dashIndex = trimmed.indexOf('-');
        if (dashIndex > 0) {
            trimmed = trimmed.substring(0, dashIndex);
        }

        String[] parts = trimmed.split("\\.");
        if (parts.length == 0 || parts.length > 3) {
            throw new IllegalArgumentException("Invalid version format: " + versionStr);
        }

        try {
            int major = Integer.parseInt(parts[0].trim());
            int minor = parts.length > 1 ? Integer.parseInt(parts[1].trim()) : 0;
            int patch = parts.length > 2 ? Integer.parseInt(parts[2].trim()) : 0;
            return new Version(major, minor, patch);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid version format: " + versionStr, e);
        }
    }

    /**
     * 获取当前 SDK 版本号。
     *
     * @return SDK 版本 {@code Version(1, 0, 0)}
     */
    public static Version current() {
        return new Version(1, 0, 0);
    }

    /**
     * 判断当前版本是否与目标版本兼容（相同 MAJOR 版本）。
     *
     * @param other 目标版本
     * @return {@code true} 兼容（相同 MAJOR 版本）
     */
    public boolean isCompatibleWith(Version other) {
        return this.major == other.major;
    }

    /**
     * 判断当前版本是否比目标版本新。
     *
     * @param other 目标版本
     * @return {@code true} 当前版本 > 目标版本
     */
    public boolean isNewerThan(Version other) {
        return this.compareTo(other) > 0;
    }

    /**
     * 判断当前版本是否比目标版本旧。
     *
     * @param other 目标版本
     * @return {@code true} 当前版本 < 目标版本
     */
    public boolean isOlderThan(Version other) {
        return this.compareTo(other) < 0;
    }

    /**
     * 获取主版本号。
     *
     * @return MAJOR
     */
    public int getMajor() { return major; }

    /**
     * 获取次版本号。
     *
     * @return MINOR
     */
    public int getMinor() { return minor; }

    /**
     * 获取修订号。
     *
     * @return PATCH
     */
    public int getPatch() { return patch; }

    @Override
    public int compareTo(Version other) {
        int cmp = Integer.compare(this.major, other.major);
        if (cmp != 0) return cmp;
        cmp = Integer.compare(this.minor, other.minor);
        if (cmp != 0) return cmp;
        return Integer.compare(this.patch, other.patch);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Version version = (Version) o;
        return major == version.major && minor == version.minor && patch == version.patch;
    }

    @Override
    public int hashCode() {
        return Objects.hash(major, minor, patch);
    }

    @Override
    public String toString() {
        return major + "." + minor + "." + patch;
    }
}