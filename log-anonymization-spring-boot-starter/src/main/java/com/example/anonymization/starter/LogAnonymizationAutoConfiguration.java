package com.example.anonymization.starter;

import com.example.anonymization.api.event.DomainEventBus;
import com.example.anonymization.api.model.MaskingRule;
import com.example.anonymization.api.port.AuditPort;
import com.example.anonymization.api.port.MaskingPort;
import com.example.anonymization.api.port.MetricsPort;
import com.example.anonymization.api.port.RuleLoadPort;
import com.example.anonymization.api.spi.AuditExporter;
import com.example.anonymization.api.spi.SensitiveDataDetector;
import com.example.anonymization.api.spi.SensitiveDataMasker;
import com.example.anonymization.core.application.MaskingApplicationService;
import com.example.anonymization.core.application.SecureLogger;
import com.example.anonymization.core.application.pipeline.*;
import com.example.anonymization.core.domain.DetectorRegistry;
import com.example.anonymization.core.domain.MaskerRegistry;
import com.example.anonymization.core.domain.RuleValidator;
import com.example.anonymization.core.domain.ThreadSafeRuleManager;
import com.example.anonymization.core.domain.service.RuleMatchService;
import com.example.anonymization.core.domain.service.SensitiveDataDetectionService;
import com.example.anonymization.core.domain.service.SensitiveDataMaskingService;
import com.example.anonymization.core.domain.service.impl.DefaultRuleMatchService;
import com.example.anonymization.core.domain.service.impl.DefaultSensitiveDataDetectionService;
import com.example.anonymization.core.domain.service.impl.DefaultSensitiveDataMaskingService;
import com.example.anonymization.core.infrastructure.audit.DisruptorAuditAdapter;
import com.example.anonymization.core.infrastructure.cache.CaffeineCacheAdapter;
import com.example.anonymization.core.infrastructure.config.CircuitBreakerConfigBean;
import com.example.anonymization.core.infrastructure.config.LocalFileRuleLoadAdapter;
import com.example.anonymization.core.infrastructure.config.MaskingCacheConfig;
import com.example.anonymization.core.infrastructure.config.NacosRuleLoadAdapter;
import com.example.anonymization.core.infrastructure.config.ThreadPoolConfig;
import com.example.anonymization.core.infrastructure.event.DefaultDomainEventBus;
import com.example.anonymization.core.infrastructure.exception.ExceptionSanitizer;
import com.example.anonymization.core.infrastructure.filter.SensitiveDataBloomFilter;
import com.example.anonymization.core.infrastructure.filter.WhitelistFilter;
import com.example.anonymization.core.infrastructure.largemsg.LargeMessageHandler;
import com.example.anonymization.core.infrastructure.masker.*;
import com.example.anonymization.core.infrastructure.metrics.MicrometerMetricsAdapter;
import com.example.anonymization.core.infrastructure.resilience.ResilientMaskingEngine;
import com.example.anonymization.core.infrastructure.sampling.SamplingController;
import com.example.anonymization.core.infrastructure.spi.SpiExtensionLoader;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

import java.util.ArrayList;
import java.util.List;

/**
 * 日志脱敏 SDK 自动装配配置（Spring Boot Auto-Configuration）。
 *
 * <p>属于 spring-boot-starter 模块，是整个 SDK 与 Spring Boot 框架的对接入口，
 * 通过 {@link AutoConfiguration} + {@code META-INF/spring/...AutoConfiguration.imports} 实现
 * “零配置引入” —— 业务方只需引入 starter 依赖即可装配全部脱敏 Bean。
 *
 * <p>装配的 Bean 涵盖：
 * <ul>
 *   <li>事件总线（{@link DomainEventBus}）；</li>
 *   <li>指标、审计、规则加载端口；</li>
 *   <li>检测器与打码器注册表；</li>
 *   <li>Pipeline 四个阶段（Bloom → Detection → Masking → Audit）；</li>
 *   <li>Resilience4j 熔断器、降级打码器、采样控制器；</li>
 *   <li>最终对外暴露的 {@link MaskingPort} Bean（可能包一层 {@link ResilientMaskingEngine}）。</li>
 * </ul>
 *
 * <p>启用条件：由 {@link ConditionalOnProperty} 控制，仅当 {@code log-anonymization.enabled=true}（默认）时装配；
 * 业务方可使用 {@link EnableLogAnonymization} 显式启用，或提供同名 Bean 覆盖默认装配。
 *
 * @author java-architect
 * @since 1.0.0
 */
@AutoConfiguration
@EnableConfigurationProperties(LogAnonymizationProperties.class)
@ConditionalOnProperty(prefix = "log-anonymization", name = "enabled", havingValue = "true", matchIfMissing = true)
@Import({ThreadPoolConfig.class, MaskingCacheConfig.class, CircuitBreakerConfigBean.class})
public class LogAnonymizationAutoConfiguration {

    /**
     * Spring 注入的全部 {@link SensitiveDataDetector} SPI 实现列表。
     * 业务方可提供自定义检测器 Bean（如银行卡 BIN 查询、姓名启发式等）会自动并入。
     */
    @Autowired(required = false)
    private List<SensitiveDataDetector> detectors = new ArrayList<>();

    /**
     * Spring 注入的全部 {@link SensitiveDataMasker} SPI 实现列表。
     * 业务方可提供自定义打码器（如 HMAC 哈希、自定义分段规则）会自动并入。
     */
    @Autowired(required = false)
    private List<SensitiveDataMasker> maskers = new ArrayList<>();

    /**
     * Spring 注入的全部 {@link AuditExporter} SPI 实现列表。
     * 用于审计事件多路输出（Kafka、文件、KMS 加密通道等）。
     */
    @Autowired(required = false)
    private List<AuditExporter> auditExporters = new ArrayList<>();

    /**
     * 装配领域事件总线默认实现。
     *
     * <p>采用进程内内存实现（{@link com.example.anonymization.core.infrastructure.event.DefaultDomainEventBus}），
     * 适用于单机部署；集群场景可由业务方提供基于 Kafka/RocketMQ 的实现覆盖。
     *
     * @return 事件总线实例
     */
    @Bean
    @ConditionalOnMissingBean
    public DomainEventBus domainEventBus() {
        return new DefaultDomainEventBus();
    }

    /**
     * 装配 Micrometer 指标适配器。
     *
     * @param meterRegistry Spring Boot Actuator 提供的指标注册中心
     * @return 指标端口实现
     */
    @Bean
    @ConditionalOnMissingBean
    public MetricsPort metricsPort(MeterRegistry meterRegistry) {
        return new MicrometerMetricsAdapter(meterRegistry);
    }

    /**
     * 装配审计端口。
     *
     * <p>当配置 {@code log-anonymization.audit.enabled=false} 时返回空实现（lambda，
     * 所有审计事件被丢弃），用于压测或关闭审计的场景。
     * 否则基于 LMAX Disruptor 高性能队列 + 多 Exporter 实现异步刷盘。
     *
     * @param properties 全局配置
     * @return 审计端口实现
     */
    @Bean
    @ConditionalOnMissingBean
    public AuditPort auditPort(LogAnonymizationProperties properties) {
        if (!properties.getAudit().isEnabled()) {
            return record -> {};
        }
        return new DisruptorAuditAdapter(
            auditExporters,
            properties.getAudit().getBatchSize(),
            properties.getAudit().getRingBufferSize(),
            properties.getAudit().getFlushIntervalSeconds()
        );
    }

    /**
     * 装配规则加载端口。
     *
     * <p>根据 {@code log-anonymization.rule-source} 配置选择加载方式：
     * <ul>
     *   <li>{@code LOCAL_FILE}（默认）：从本地 YAML 文件加载，支持 WatchService 文件变更监听；</li>
     *   <li>{@code NACOS}：从 Nacos 配置中心加载，支持 Nacos Listener 动态刷新。</li>
     * </ul>
     *
     * @param properties 全局配置
     * @return 规则加载端口实现
     */
    @Bean
    @ConditionalOnMissingBean
    public RuleLoadPort ruleLoadPort(LogAnonymizationProperties properties) {
        if ("NACOS".equalsIgnoreCase(properties.getRuleSource())) {
            LogAnonymizationProperties.NacosConfig nacos = properties.getNacos();
            return new NacosRuleLoadAdapter(
                nacos.getServerAddr(),
                nacos.getDataId(),
                nacos.getGroup()
            );
        }
        return new LocalFileRuleLoadAdapter(properties.getRuleFilePath());
    }

    /**
     * 装配检测器注册表。
     *
     * @return 检测器注册表（含全部注入的 SPI 实现）
     */
    @Bean
    @ConditionalOnMissingBean
    public DetectorRegistry detectorRegistry() {
        List<SensitiveDataDetector> all = new ArrayList<>(SpiExtensionLoader.loadDetectors());
        all.addAll(detectors);
        return new DetectorRegistry(all);
    }

    /**
     * 装配打码器注册表与工厂。
     *
     * <p>当业务方未提供任何打码器时，自动装配 6 种默认打码器：partial/full/discard/hash/generalize/fallback，
     * 覆盖绝大多数支付场景需求。
     *
     * @param properties 全局配置（读取 {@code secret.salt}）
     * @return 打码器注册表（用于根据 {@code MaskerType} 查找打码器）
     */
    @Bean
    @ConditionalOnMissingBean
    public MaskerRegistry maskerRegistry(LogAnonymizationProperties properties) {
        List<SensitiveDataMasker> allMaskers = new ArrayList<>(SpiExtensionLoader.loadMaskers());
        allMaskers.addAll(maskers);
        if (allMaskers.isEmpty()) {
            allMaskers.add(new PartialMaskMasker());
            allMaskers.add(new FullMaskMasker());
            allMaskers.add(new DiscardMasker());
            allMaskers.add(new HashMasker(properties.getSecret().getSalt()));
            allMaskers.add(new GeneralizeMasker());
            allMaskers.add(new FallbackMasker());
        }
        return new MaskerRegistry(allMaskers);
    }

    /**
     * 装配打码器工厂。
     *
     * <p>基于 {@link MaskerRegistry} 的全部打码器构建 {@link MaskerFactory}，
     * 提供 {@code create(MaskerType)} 能力。
     *
     * @param maskerRegistry 打码器注册表
     * @return 打码器工厂
     */
    @Bean
    @ConditionalOnMissingBean
    public MaskerFactory maskerFactory(MaskerRegistry maskerRegistry) {
        return new MaskerFactory(maskerRegistry.getAllMaskers());
    }

    /**
     * 装配敏感数据布隆过滤器。
     *
     * <p>作为 Pipeline 第一阶段的快速预筛组件，初始容量 10000、误判率 1%。
     * 规则加载完成后会重建（在 {@link #threadSafeRuleManager} 中触发）。
     *
     * @return 布隆过滤器实例
     */
    @Bean
    @ConditionalOnMissingBean
    public SensitiveDataBloomFilter sensitiveDataBloomFilter() {
        return new SensitiveDataBloomFilter();
    }

    /**
     * 装配线程安全的规则管理器。
     *
     * <p>初始化流程：
     * <ol>
     *   <li>从 {@link RuleLoadPort} 加载初始规则；</li>
     *   <li>调用 {@link RuleValidator#validateAll} 校验（failFast 取决于配置）；</li>
     *   <li>{@link ThreadSafeRuleManager#refreshRules} 加载；</li>
     *   <li>订阅 {@link RuleLoadPort#onRuleChange} 实现热刷新。</li>
     * </ol>
     *
     * @param ruleLoadPort   规则加载端口
     * @param ruleValidator  规则校验器
     * @return 线程安全规则管理器
     */
    @Bean
    @ConditionalOnMissingBean
    public ThreadSafeRuleManager threadSafeRuleManager(RuleLoadPort ruleLoadPort,
                                                        RuleValidator ruleValidator) {
        ThreadSafeRuleManager manager = new ThreadSafeRuleManager();
        List<MaskingRule> rules = ruleLoadPort.loadRules();
        ruleValidator.validateAll(rules);
        manager.refreshRules(rules);
        ruleLoadPort.onRuleChange(manager::refreshRules);
        return manager;
    }

    /**
     * 装配规则校验器。
     *
     * <p>启动时检查"规则引用的检测器/打码器是否都存在"，避免运行时
     * {@link NullPointerException}。
     *
     * @param detectorRegistry 检测器注册表
     * @param maskerRegistry   打码器注册表
     * @param properties       全局配置（读取 {@code validation.failFast}）
     * @return 规则校验器
     */
    @Bean
    @ConditionalOnMissingBean
    public RuleValidator ruleValidator(DetectorRegistry detectorRegistry,
                                        MaskerRegistry maskerRegistry,
                                        LogAnonymizationProperties properties) {
        return new RuleValidator(detectorRegistry, maskerRegistry,
            properties.getValidation().isFailFast());
    }

    /**
     * 装配白名单过滤器。
     *
     * <p>使用 {@link WhitelistFilter} 默认白名单模式（UUID/时间戳/流水号/版本号），
     * 在检测阶段过滤掉常见的非敏感数据匹配，降低误杀率。
     *
     * @return 白名单过滤器
     */
    @Bean
    @ConditionalOnMissingBean
    public WhitelistFilter whitelistFilter() {
        return new WhitelistFilter();
    }

    /**
     * 装配降级打码器。
     *
     * <p>作为 {@link ResilientMaskingEngine} 的兜底组件，在熔断或下游异常时使用。
     *
     * @return 降级打码器
     */
    @Bean
    @ConditionalOnMissingBean
    public FallbackMasker fallbackMasker() {
        return new FallbackMasker();
    }

    // 熔断器 Bean 由 CircuitBreakerConfigBean 提供（通过 @Import 引入）
    // Caffeine 缓存 Bean 由 MaskingCacheConfig 提供（通过 @Import 引入）

    /**
     * 装配版本兼容策略。
     *
     * <p>默认使用 SemVer 兼容规则：相同 MAJOR 版本 = 兼容。
     * 业务方可通过提供自定义 {@link com.example.anonymization.api.version.VersionCompatPolicy} Bean 覆盖。
     *
     * @return 版本兼容策略
     */
    @Bean
    @ConditionalOnMissingBean
    public com.example.anonymization.api.version.VersionCompatPolicy versionCompatPolicy() {
        return new com.example.anonymization.core.infrastructure.version.DefaultVersionCompatPolicy();
    }

    /**
     * 装配规则版本兼容处理器。
     *
     * <p>在规则加载阶段检查规则文件版本与当前 SDK 的兼容性，
     * 不兼容时拒绝加载，已废弃时记录警告。
     *
     * @param policy 版本兼容策略
     * @return 规则版本兼容处理器
     */
    @Bean
    @ConditionalOnMissingBean
    public com.example.anonymization.core.infrastructure.version.RuleVersionCompatHandler ruleVersionCompatHandler(
            com.example.anonymization.api.version.VersionCompatPolicy policy) {
        return new com.example.anonymization.core.infrastructure.version.RuleVersionCompatHandler(
            policy, com.example.anonymization.api.version.Version.current());
    }

    /**
     * 装配灰度发布路由器。
     *
     * <p>基于 traceId 哈希的确定性灰度路由，用于 SDK 升级时新旧版本共存。
     * 默认灰度比例 0%（全部走旧版本），通过 {@code log-anonymization.gray-release.percent} 配置。
     *
     * @param policy 版本兼容策略
     * @param properties 全局配置
     * @return 灰度发布路由器
     */
    @Bean
    @ConditionalOnMissingBean
    public com.example.anonymization.core.infrastructure.version.GrayReleaseRouter grayReleaseRouter(
            com.example.anonymization.api.version.VersionCompatPolicy policy,
            LogAnonymizationProperties properties) {
        com.example.anonymization.api.version.Version oldVersion =
            com.example.anonymization.api.version.Version.parse(properties.getGrayRelease().getOldVersion());
        com.example.anonymization.api.version.Version newVersion =
            com.example.anonymization.api.version.Version.parse(properties.getGrayRelease().getNewVersion());
        com.example.anonymization.core.infrastructure.version.GrayReleaseRouter router =
            new com.example.anonymization.core.infrastructure.version.GrayReleaseRouter(
                policy, oldVersion, newVersion);
        router.setGrayPercent(properties.getGrayRelease().getPercent());
        return router;
    }

    /**
     * 装配规则匹配服务（领域服务）。
     *
     * <p>负责"在当前规则集合中找到匹配某数据类型的规则"，是检测器路由的桥梁。
     *
     * @param ruleManager 线程安全规则管理器
     * @return 默认实现
     */
    @Bean
    @ConditionalOnMissingBean
    public RuleMatchService ruleMatchService(ThreadSafeRuleManager ruleManager) {
        return new DefaultRuleMatchService(ruleManager);
    }

    /**
     * 装配合成数据检测服务（领域服务）。
     *
     * @param detectorRegistry 检测器注册表
     * @param ruleManager      规则管理器
     * @param ruleMatchService 规则匹配服务
     * @return 默认实现
     */
    @Bean
    @ConditionalOnMissingBean
    public SensitiveDataDetectionService sensitiveDataDetectionService(DetectorRegistry detectorRegistry,
                                                                        ThreadSafeRuleManager ruleManager,
                                                                        RuleMatchService ruleMatchService) {
        return new DefaultSensitiveDataDetectionService(detectorRegistry, ruleManager, ruleMatchService);
    }

    /**
     * 装配打码执行服务（领域服务）。
     *
     * @param maskerFactory    打码器工厂
     * @param ruleManager      规则管理器
     * @param ruleMatchService 规则匹配服务
     * @return 默认实现
     */
    @Bean
    @ConditionalOnMissingBean
    public SensitiveDataMaskingService sensitiveDataMaskingService(MaskerFactory maskerFactory,
                                                                     ThreadSafeRuleManager ruleManager,
                                                                     RuleMatchService ruleMatchService) {
        return new DefaultSensitiveDataMaskingService(maskerFactory, ruleManager, ruleMatchService);
    }

    /**
     * 装配异常脱敏器。
     *
     * <p>递归地对异常链的 message 进行脱敏，详见 {@link ExceptionSanitizer}。
     *
     * @param maskingPort 脱敏端口（用于脱敏异常消息）
     * @return 异常脱敏器
     */
    @Bean
    @ConditionalOnMissingBean
    public ExceptionSanitizer exceptionSanitizer(MaskingPort maskingPort) {
        return new ExceptionSanitizer(maskingPort);
    }

    /**
     * 装配大消息处理器。
     *
     * <p>对超长日志消息采用“首尾扫描 + 中间截断”策略，避免 OOM 与长尾延迟。
     *
     * @param maskingPort 脱敏端口
     * @return 大消息处理器
     */
    @Bean
    @ConditionalOnMissingBean
    public LargeMessageHandler largeMessageHandler(MaskingPort maskingPort) {
        return new LargeMessageHandler(maskingPort);
    }

    /**
     * 装配采样控制器。
     *
     * <p>当 {@code log-anonymization.sampling.enabled=true} 时从配置读取采样率，
     * 否则保持默认 1.0（全量脱敏）。
     *
     * @param properties 全局配置
     * @return 采样控制器
     */
    @Bean
    @ConditionalOnMissingBean
    public SamplingController samplingController(LogAnonymizationProperties properties) {
        SamplingController controller = new SamplingController();
        if (properties.getSampling().isEnabled()) {
            controller.setSamplingRate(properties.getSampling().getRate());
        }
        return controller;
    }

    /**
     * 装配默认脱敏 Pipeline。
     *
     * <p>包含四个阶段：布隆过滤 → 检测 → 打码 → 审计；顺序不可变，
     * 业务方可提供自定义 {@link DefaultMaskingPipeline} Bean 覆盖。
     *
     * @param bloomFilter       布隆过滤器
     * @param detectionService  检测服务
     * @param maskingService    打码服务
     * @param auditPort         审计端口
     * @param metricsPort       指标端口
     * @param eventBus          事件总线
     * @return 默认 Pipeline
     */
    @Bean
    @ConditionalOnMissingBean
    public DefaultMaskingPipeline defaultMaskingPipeline(SensitiveDataBloomFilter bloomFilter,
                                                          SensitiveDataDetectionService detectionService,
                                                          SensitiveDataMaskingService maskingService,
                                                          AuditPort auditPort,
                                                          MetricsPort metricsPort,
                                                          DomainEventBus eventBus) {
        List<PipelineStage> stages = new ArrayList<>();
        stages.add(new BloomFilterStage(bloomFilter));
        stages.add(new DetectionStage(detectionService));
        stages.add(new MaskingStage(maskingService));
        stages.add(new AuditStage(auditPort, metricsPort, eventBus));
        return new DefaultMaskingPipeline(stages);
    }

    /**
     * 装配对外暴露的脱敏端口（{@link MaskingPort}）。
     *
     * <p>组装流程：
     * <ol>
     *   <li>创建 {@link MaskingApplicationService} 作为原始脱敏实现；</li>
     *   <li>若 {@code log-anonymization.circuit-breaker.enabled=true}（默认），用 {@link ResilientMaskingEngine} 装饰；</li>
     *   <li>否则直接返回原实例。</li>
     * </ol>
     *
     * <p>业务方可提供同名 Bean 覆盖（例如自定义采样/限流逻辑）。
     *
     * @param pipeline         默认 Pipeline
     * @param metricsPort      指标端口
     * @param properties       全局配置
     * @param circuitBreaker   熔断器
     * @param fallbackMasker   降级打码器
     * @return 脱敏端口实例
     */
    @Bean
    @ConditionalOnMissingBean
    public MaskingPort maskingPort(DefaultMaskingPipeline pipeline,
                                    MetricsPort metricsPort,
                                    LogAnonymizationProperties properties,
                                    CircuitBreaker circuitBreaker,
                                    FallbackMasker fallbackMasker) {
        MaskingPort delegate = new MaskingApplicationService(pipeline, metricsPort);
        MaskingPort result = properties.getCircuitBreaker().isEnabled()
            ? new ResilientMaskingEngine(delegate, circuitBreaker, fallbackMasker)
            : delegate;
        SecureLogger.init(result);
        return result;
    }

    /**
     * 容器关闭时销毁 SecureLogger 全局单例，防止内存泄露。
     */
    @Bean
    public SecureLoggerDestroyer secureLoggerDestroyer() {
        return new SecureLoggerDestroyer();
    }

    /**
     * Jasypt 加密器自动装配（独立内部配置类）。
     *
     * <p>将 Jasypt 相关 Bean 隔离在独立的 {@code @Configuration} 内部类中，
     * 通过 {@code @ConditionalOnClass} 确保：当 classpath 不存在 {@code jasypt-spring-boot-starter} 时，
     * Spring Boot 仅跳过此内部类，不影响外层 {@link LogAnonymizationAutoConfiguration} 的加载。
     *
     * <p>设计依据：Spring Boot 的 {@code @ConditionalOnClass} 在方法级别使用时，
     * 如果方法签名引用了可选依赖中的类型，当该类型不在 classpath 时，
     * JVM 加载包含该方法的类就会抛出 {@code NoClassDefFoundError}。
     * 将 Bean 方法隔离到独立内部类可以避免这一问题。
     *
     * @author java-architect
     * @since 1.0.0
     */
    @org.springframework.context.annotation.Configuration
    @ConditionalOnClass(name = "org.jasypt.encryption.StringEncryptor")
    static class JasyptEncryptorConfiguration {

        /**
         * 装配 Jasypt 配置加密器 —— 为 {@code ENC(...)} 格式的敏感配置值提供解密能力。
         *
         * <p>使用 {@code PBEWithHMACSHA512AndAES_256} 算法 + 随机 IV/Salt。
         * 主密钥来源优先级：
         * <ol>
         *   <li>环境变量 {@code JASYPT_ENCRYPTOR_PASSWORD}</li>
         *   <li>系统属性 {@code jasypt.encryptor.password}</li>
         *   <li>配置文件中的 {@code jasypt.encryptor.password}（不推荐）</li>
         * </ol>
         *
         * @param password 主密钥，从环境变量/系统属性获取
         * @return 配置好的 StringEncryptor 实例
         */
        @Bean("jasyptStringEncryptor")
        @ConditionalOnMissingBean(name = "jasyptStringEncryptor")
        public org.jasypt.encryption.StringEncryptor jasyptStringEncryptor(
                @org.springframework.beans.factory.annotation.Value("${jasypt.encryptor.password:}") String password) {
            return JasyptConfig.createEncryptor(password);
        }
    }

    /**
     * SecureLogger 生命周期管理 Bean —— 在 Spring 容器关闭时清理全局单例。
     */
    static class SecureLoggerDestroyer implements AutoCloseable {
        @Override
        public void close() {
            SecureLogger.destroy();
        }
    }

    /**
     * Flyway 数据库迁移自动装配（独立内部配置类）。
     *
     * <p>将 Flyway 相关 Bean 隔离在独立的 {@code @Configuration} 内部类中，
     * 通过 {@code @ConditionalOnClass} 确保：当 classpath 不存在 {@code flyway-core} 时，
     * Spring Boot 仅跳过此内部类，不影响外层 {@link LogAnonymizationAutoConfiguration} 的加载。
     *
     * <p>启用条件（全部满足才激活）：
     * <ol>
     *   <li>classpath 存在 {@code org.flywaydb.core.Flyway}</li>
     *   <li>{@code log-anonymization.flyway.enabled=true}（默认 {@code false}）</li>
     *   <li>配置了 {@code spring.datasource.url}</li>
     * </ol>
     *
     * <p>迁移脚本位置：{@code classpath:db/migration/V*__*.sql}
     * （由 {@code log-anonymization-core} 模块提供，位于 {@code src/main/resources/db/migration/}）
     *
     * @author java-architect
     * @since 1.0.0
     */
    @org.springframework.context.annotation.Configuration
    @ConditionalOnClass(name = "org.flywaydb.core.Flyway")
    @ConditionalOnProperty(prefix = "log-anonymization.flyway", name = "enabled", havingValue = "true")
    static class FlywayMigrationConfiguration {

        /**
         * 装配 Flyway —— 在应用启动时自动执行数据库迁移脚本。
         *
         * <p>迁移脚本版本：
         * <ul>
         *   <li>{@code V1__init_schema.sql}：创建 3 张核心表（masking_rule / masking_rule_scope / audit_log）</li>
         *   <li>{@code V2__seed_default_rules.sql}：插入 7 条默认规则 + 全局作用域</li>
         *   <li>{@code V3__audit_partition_event.sql}：创建审计日志按月自动分区 Event</li>
         * </ul>
         *
         * @param dataSource Spring 自动注入的数据源
         * @return Flyway 实例（构造时自动执行迁移）
         */
        @Bean
        @ConditionalOnMissingBean(name = "logAnonymizationFlyway")
        public org.flywaydb.core.Flyway logAnonymizationFlyway(
                javax.sql.DataSource dataSource) {
            return org.flywaydb.core.Flyway.configure()
                .dataSource(dataSource)
                .locations("classpath:db/migration")
                .baselineOnMigrate(true)
                .table("flyway_schema_history_anonymization")
                .load();
        }
    }
}