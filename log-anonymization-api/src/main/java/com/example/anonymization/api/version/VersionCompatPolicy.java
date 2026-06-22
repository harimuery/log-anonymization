package com.example.anonymization.api.version;

/**
 * 版本兼容策略接口 —— 定义版本间兼容性判断的抽象规则。
 *
 * <p>属于领域层（api 模块），零外部依赖。
 * 默认实现见 {@link com.example.anonymization.core.infrastructure.version.DefaultVersionCompatPolicy}。
 *
 * <p>使用场景：
 * <ul>
 *   <li>规则文件加载时：判断规则版本与当前 SDK 版本是否兼容</li>
 *   <li>SPI 加载时：判断第三方扩展实现版本是否与 SDK 兼容</li>
 *   <li>灰度发布时：判断新旧版本是否可共存</li>
 *   <li>废弃 API 追踪：判断 API 版本是否已废弃</li>
 * </ul>
 *
 * <p>设计原则（策略模式）：
 * <ul>
 *   <li>接口隔离：仅定义兼容性判断，不包含版本解析逻辑</li>
 *   <li>可替换：业务方可提供自定义实现覆盖默认策略</li>
 *   <li>无状态：实现类应为无状态，保证线程安全</li>
 * </ul>
 *
 * @author java-architect
 * @since 1.0.0
 */
public interface VersionCompatPolicy {

    /**
     * 判断两个版本是否兼容。
     *
     * <p>兼容性定义：两个版本可以在同一集群中共存，不会因 API 不兼容导致运行时错误。
     * 默认策略：相同 MAJOR 版本 = 兼容。
     *
     * @param v1 版本 1
     * @param v2 版本 2
     * @return {@code true} 兼容
     */
    boolean isCompatible(Version v1, Version v2);

    /**
     * 判断给定版本是否已被废弃。
     *
     * <p>废弃定义：版本已标记为 {@code @Deprecated}，但仍可用，将在未来大版本中移除。
     * 默认策略：MAJOR 版本落后当前版本 2 个及以上 = 废弃。
     *
     * @param version 待检查版本
     * @return {@code true} 已废弃
     */
    boolean isDeprecated(Version version);

    /**
     * 判断给定版本是否仍受支持。
     *
     * <p>支持定义：版本未废弃，且在官方维护期内。
     * 默认策略：未废弃 = 受支持。
     *
     * @param version 待检查版本
     * @return {@code true} 受支持
     */
    default boolean isSupported(Version version) {
        return !isDeprecated(version);
    }

    /**
     * 获取当前 SDK 版本。
     *
     * @return 当前版本
     */
    Version getCurrentVersion();
}