package com.example.anonymization.core.infrastructure.spi;

import com.example.anonymization.api.spi.SensitiveDataDetector;
import com.example.anonymization.api.spi.SensitiveDataMasker;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.ServiceLoader;

/**
 * SPI 扩展加载器 —— 基于 Java {@link ServiceLoader} 机制加载第三方 JAR 中的扩展实现。
 *
 * <p>使用场景：当业务方通过 JAR 包方式提供自定义 {@link SensitiveDataDetector} 或
 * {@link SensitiveDataMasker} 实现（而非 Spring Bean 注册）时，
 * 本加载器从 {@code META-INF/services/} 目录自动发现并加载这些实现。
 *
 * <p>加载策略：
 * <ol>
 *   <li>使用 {@link ServiceLoader} 扫描 classpath 下所有 JAR 的 SPI 配置文件</li>
 *   <li>对每个 SPI 接口独立加载，互不影响</li>
 *   <li>加载异常被捕获并打印警告，不影响其他实现</li>
 *   <li>返回的列表为不可变快照，线程安全</li>
 * </ol>
 *
 * <p>与 Spring Bean 注册的关系：
 * <ul>
 *   <li>Spring Bean 注册：适用于业务方直接在 Spring 上下文中声明 {@code @Component}，优先级更高</li>
 *   <li>SPI 加载：适用于纯 JAR 包扩展（无 Spring 依赖），作为补充</li>
 *   <li>AutoConfiguration 中两者合并：先加载 SPI，再追加 Spring Bean，Bean 可覆盖 SPI 同类型实现</li>
 * </ul>
 *
 * <p>线程安全：{@link ServiceLoader} 本身不是线程安全的，但本类所有方法均为无状态纯函数，
 * 每次调用创建新的 {@link ServiceLoader} 实例，可安全并发调用。
 *
 * @author log-anonymization
 */
public final class SpiExtensionLoader {

    private SpiExtensionLoader() {}

    /**
     * 加载所有 {@link SensitiveDataDetector} SPI 实现。
     *
     * <p>从 {@code META-INF/services/com.example.anonymization.api.spi.SensitiveDataDetector}
     * 配置文件中读取实现类全限定名并实例化。
     *
     * @return 检测器列表（不可变），加载失败时返回空列表
     */
    public static List<SensitiveDataDetector> loadDetectors() {
        return loadSpi(SensitiveDataDetector.class);
    }

    /**
     * 加载所有 {@link SensitiveDataMasker} SPI 实现。
     *
     * <p>从 {@code META-INF/services/com.example.anonymization.api.spi.SensitiveDataMasker}
     * 配置文件中读取实现类全限定名并实例化。
     *
     * @return 脱敏器列表（不可变），加载失败时返回空列表
     */
    public static List<SensitiveDataMasker> loadMaskers() {
        return loadSpi(SensitiveDataMasker.class);
    }

    /**
     * 通用 SPI 加载方法。
     *
     * <p>使用 {@link ServiceLoader#load(Class, ClassLoader)} 指定 ClassLoader，
     * 确保在 OSGi / Fat JAR 环境下也能正确发现实现类。
     *
     * @param spiType SPI 接口类型
     * @param <T>    SPI 接口泛型
     * @return 实现列表（不可变）
     */
    private static <T> List<T> loadSpi(Class<T> spiType) {
        ServiceLoader<T> loader = ServiceLoader.load(spiType, spiType.getClassLoader());
        List<T> implementations = new ArrayList<>();
        try {
            for (T impl : loader) {
                implementations.add(impl);
            }
        } catch (Exception e) {
            System.err.println("[SpiExtensionLoader] Failed to load SPI for " + spiType.getName()
                + ": " + e.getMessage());
        }
        return Collections.unmodifiableList(implementations);
    }
}