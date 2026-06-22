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
import com.example.anonymization.core.infrastructure.config.LocalFileRuleLoadAdapter;
import com.example.anonymization.core.infrastructure.event.DefaultDomainEventBus;
import com.example.anonymization.core.infrastructure.exception.ExceptionSanitizer;
import com.example.anonymization.core.infrastructure.filter.SensitiveDataBloomFilter;
import com.example.anonymization.core.infrastructure.largemsg.LargeMessageHandler;
import com.example.anonymization.core.infrastructure.masker.*;
import com.example.anonymization.core.infrastructure.metrics.MicrometerMetricsAdapter;
import com.example.anonymization.core.infrastructure.resilience.ResilientMaskingEngine;
import com.example.anonymization.core.infrastructure.sampling.SamplingController;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.time.Duration;
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
            properties.getAudit().getFlushIntervalSeconds()
        );
    }

    /**
     * 装配规则加载端口。
     *
     * <p>当前默认从本地 YAML 加载，生产环境可由业务方提供 Nacos/Apollo 加载实现覆盖。
     *
     * @param properties 全局配置（含 {@code ruleFilePath}）
     * @return 规则加载端口实现
     */
    @Bean
    @ConditionalOnMissingBean
    public RuleLoadPort ruleLoadPort(LogAnonymizationProperties properties) {
        return new LocalFileRuleLoadAdapter(properties.getRuleFilePath());
    }

    /**
     * 装配检测器注册表。
     *
     * @return 检测器注册表（含全部注入的 SPI 实现）
     */
    @Bean
    public DetectorRegistry detectorRegistry() {
        return new DetectorRegistry(detectors);
    }

    /**
     * 装配打码器注册表与工厂。
     *
     * <p>当业务方未提供任何打码器时，自动装配 6 种默认打码器：partial/full/discard/hash/generalize/fallback，
     * 覆盖绝大多数支付场景需求。
     *
     * @param properties 全局配置（读取 {@code secret.salt}）
     * @param maskerRegistry 打码器注册表 Bean（由 Spring 保证初始化顺序）
     * @return 打码器工厂（用于根据 {@code MaskerType} 查找打码器）
     */
    @Bean
    public MaskerRegistry maskerRegistry(LogAnonymizationProperties properties) {
        List<SensitiveDataMasker> allMaskers = new ArrayList<>(maskers);
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
    public RuleValidator ruleValidator(DetectorRegistry detectorRegistry,
                                        MaskerRegistry maskerRegistry,
                                        LogAnonymizationProperties properties) {
        return new RuleValidator(detectorRegistry, maskerRegistry,
            properties.getValidation().isFailFast());
    }

    /**
     * 装配 Caffeine 本地缓存适配器。
     *
     * <p>提供两个缓存：规则缓存（1000 条）与编译后 Pattern 缓存（500 条），
     * 减少重复正则编译开销。
     *
     * @return 缓存适配器
     */
    @Bean
    public CaffeineCacheAdapter caffeineCacheAdapter() {
        return new CaffeineCacheAdapter();
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

    /**
     * 装配 Resilience4j 熔断器。
     *
     * <p>默认阈值：失败率 50%、慢调用 10ms、滑动窗口 100、Open 状态持续 30s。
     *
     * @param properties 全局配置
     * @return 熔断器实例（名称固定为 {@code maskingEngine}）
     */
    @Bean
    @ConditionalOnMissingBean
    public CircuitBreaker maskingCircuitBreaker(LogAnonymizationProperties properties) {
        LogAnonymizationProperties.CircuitBreakerConfig cbConfig = properties.getCircuitBreaker();
        CircuitBreakerConfig config = CircuitBreakerConfig.custom()
            .failureRateThreshold((float) cbConfig.getFailureRateThreshold())
            .slowCallDurationThreshold(Duration.ofMillis(10))
            .slidingWindowSize(cbConfig.getSlidingWindowSize())
            .waitDurationInOpenState(Duration.ofSeconds(30))
            .build();
        return CircuitBreaker.of("maskingEngine", config);
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
        if (properties.getCircuitBreaker().isEnabled()) {
            return new ResilientMaskingEngine(delegate, circuitBreaker, fallbackMasker);
        }
        return delegate;
    }
}