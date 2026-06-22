package com.example.anonymization.starter;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * 日志脱敏配置属性（{@code @ConfigurationProperties}）。
 *
 * <p>属于 spring-boot-starter 模块，绑定 {@code application.yml} 中前缀为 {@code log-anonymization} 的全部配置。
 * 主要分组：nacos（规则中心）、cache（本地/远端缓存）、audit（审计落盘）、circuitBreaker（熔断）、
 * secret（盐值）、largeMessage（大消息）、sampling（采样）、validation（校验）。
 *
 * <p>使用示例：
 * <pre>
 *   log-anonymization:
 *     enabled: true
 *     rule-file-path: classpath:log-anonymization-rules.yml
 *     audit:
 *       enabled: true
 *       batch-size: 200
 *     secret:
 *       salt: ${ANON_SALT:please-change-me}
 * </pre>
 *
 * <p>设计取舍：
 * <ul>
 *   <li>全部字段默认值都已设置为"安全默认值"（如 {@code audit.enabled=true}）；</li>
 *   <li>嵌套静态类提供分组语义，避免一个类承载过多字段；</li>
 *   <li>敏感字段（如 salt）建议从环境变量/密钥管理服务注入，不要硬编码在配置文件中。</li>
 * </ul>
 *
 * @author java-architect
 * @since 1.0.0
 */
@ConfigurationProperties(prefix = "log-anonymization")
public class LogAnonymizationProperties {

    /**
     * 是否启用 SDK（总开关）。默认 {@code true}；
     * 设为 {@code false} 时 {@link LogAnonymizationAutoConfiguration} 的所有 Bean 都不会注册。
     */
    private boolean enabled = true;
    /**
     * 规则来源类型：{@code LOCAL_FILE} / {@code NACOS}。
     */
    private String ruleSource = "LOCAL_FILE";
    /**
     * 规则文件路径，默认 {@code classpath:log-anonymization-rules.yml}。
     */
    private String ruleFilePath = "classpath:log-anonymization-rules.yml";

    /**
     * Nacos 配置中心相关参数（仅当 {@link #ruleSource=NACOS} 时生效）。
     */
    private NacosConfig nacos = new NacosConfig();
    /**
     * 缓存配置：本地 Caffeine + 远端 Redis。
     */
    private CacheConfig cache = new CacheConfig();
    /**
     * 审计落盘配置。
     */
    private AuditConfig audit = new AuditConfig();
    /**
     * 熔断器配置。
     */
    private CircuitBreakerConfig circuitBreaker = new CircuitBreakerConfig();
    /**
     * 密钥配置（盐值等）。
     */
    private SecretConfig secret = new SecretConfig();
    /**
     * 大消息处理配置。
     */
    private LargeMessageConfig largeMessage = new LargeMessageConfig();
    /**
     * 采样配置。
     */
    private SamplingConfig sampling = new SamplingConfig();
    /**
     * 规则校验配置。
     */
    private ValidationConfig validation = new ValidationConfig();

    /**
     * 获取总开关状态。
     *
     * @return {@code true} 启用；{@code false} 关闭
     */
    public boolean isEnabled() { return enabled; }
    /**
     * 设置总开关。
     *
     * @param enabled 是否启用
     */
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    /**
     * 获取规则来源类型。
     *
     * @return 规则来源字符串（如 {@code "LOCAL_FILE"} / {@code "NACOS"}）
     */
    public String getRuleSource() { return ruleSource; }
    /**
     * 设置规则来源类型。
     *
     * @param ruleSource 规则来源字符串
     */
    public void setRuleSource(String ruleSource) { this.ruleSource = ruleSource; }

    /**
     * 获取规则文件路径。
     *
     * @return 路径字符串，支持 classpath:/ 前缀
     */
    public String getRuleFilePath() { return ruleFilePath; }
    /**
     * 设置规则文件路径。
     *
     * @param ruleFilePath 路径字符串
     */
    public void setRuleFilePath(String ruleFilePath) { this.ruleFilePath = ruleFilePath; }

    /**
     * 获取 Nacos 配置。
     *
     * @return {@link NacosConfig} 实例（Spring 会注入嵌套字段）
     */
    public NacosConfig getNacos() { return nacos; }
    /**
     * 设置 Nacos 配置。
     */
    public void setNacos(NacosConfig nacos) { this.nacos = nacos; }

    /**
     * 获取缓存配置。
     */
    public CacheConfig getCache() { return cache; }
    /**
     * 设置缓存配置。
     */
    public void setCache(CacheConfig cache) { this.cache = cache; }

    /**
     * 获取审计配置。
     */
    public AuditConfig getAudit() { return audit; }
    /**
     * 设置审计配置。
     */
    public void setAudit(AuditConfig audit) { this.audit = audit; }

    /**
     * 获取熔断器配置。
     */
    public CircuitBreakerConfig getCircuitBreaker() { return circuitBreaker; }
    /**
     * 设置熔断器配置。
     */
    public void setCircuitBreaker(CircuitBreakerConfig circuitBreaker) { this.circuitBreaker = circuitBreaker; }

    /**
     * 获取密钥配置。
     */
    public SecretConfig getSecret() { return secret; }
    /**
     * 设置密钥配置。
     */
    public void setSecret(SecretConfig secret) { this.secret = secret; }

    /**
     * 获取大消息配置。
     */
    public LargeMessageConfig getLargeMessage() { return largeMessage; }
    /**
     * 设置大消息配置。
     */
    public void setLargeMessage(LargeMessageConfig largeMessage) { this.largeMessage = largeMessage; }

    /**
     * 获取采样配置。
     */
    public SamplingConfig getSampling() { return sampling; }
    /**
     * 设置采样配置。
     */
    public void setSampling(SamplingConfig sampling) { this.sampling = sampling; }

    /**
     * 获取规则校验配置。
     */
    public ValidationConfig getValidation() { return validation; }
    /**
     * 设置规则校验配置。
     */
    public void setValidation(ValidationConfig validation) { this.validation = validation; }

    /**
     * Nacos 配置中心连接参数。业务系统推荐使用 Nacos 作为规则中心，
     * 实现规则热更新而无需重启服务。
     */
    public static class NacosConfig {
        /**
         * Nacos 服务器地址（{@code host:port} 形式）。
         */
        private String serverAddr = "localhost:8848";
        /**
         * 配置项 Data ID。
         */
        private String dataId = "log-anonymization-rules.yml";
        /**
         * 配置项 Group。
         */
        private String group = "DEFAULT_GROUP";

        /**
         * 获取 Nacos 服务器地址。
         *
         * @return {@code host:port} 形式字符串
         */
        public String getServerAddr() { return serverAddr; }
        /**
         * 设置 Nacos 服务器地址。
         *
         * @param serverAddr {@code host:port}
         */
        public void setServerAddr(String serverAddr) { this.serverAddr = serverAddr; }
        /**
         * 获取配置项 Data ID。
         *
         * @return Data ID
         */
        public String getDataId() { return dataId; }
        /**
         * 设置配置项 Data ID。
         *
         * @param dataId Data ID
         */
        public void setDataId(String dataId) { this.dataId = dataId; }
        /**
         * 获取配置项 Group。
         *
         * @return Group 名
         */
        public String getGroup() { return group; }
        /**
         * 设置配置项 Group。
         *
         * @param group Group 名
         */
        public void setGroup(String group) { this.group = group; }
    }

    /**
     * 缓存配置：本地 Caffeine + 远端 Redis。
     * 业务上一般只启用 Caffeine 即可；Redis 用于跨节点共享编译后的 Pattern 缓存。
     */
    public static class CacheConfig {
        /**
         * 本地 Caffeine 缓存配置。
         */
        private CaffeineConfig caffeine = new CaffeineConfig();
        /**
         * 远端 Redis 缓存配置。
         */
        private RedisConfig redis = new RedisConfig();

        /**
         * 获取 Caffeine 本地缓存配置。
         *
         * @return Caffeine 配置
         */
        public CaffeineConfig getCaffeine() { return caffeine; }
        /**
         * 设置 Caffeine 本地缓存配置。
         *
         * @param caffeine 配置对象
         */
        public void setCaffeine(CaffeineConfig caffeine) { this.caffeine = caffeine; }
        /**
         * 获取 Redis 远端缓存配置。
         *
         * @return Redis 配置
         */
        public RedisConfig getRedis() { return redis; }
        /**
         * 设置 Redis 远端缓存配置。
         *
         * @param redis 配置对象
         */
        public void setRedis(RedisConfig redis) { this.redis = redis; }
    }

    /**
     * Caffeine 本地缓存配置。
     */
    public static class CaffeineConfig {
        /**
         * 最大条目数。超过后按 LRU 淘汰。
         */
        private int maxSize = 1000;
        /**
         * 写入后多久异步刷新（仅 Refresh 而非 Expire）。
         */
        private int refreshSeconds = 30;

        /**
         * 获取本地缓存最大条目数。
         *
         * @return 条目数
         */
        public int getMaxSize() { return maxSize; }
        /**
         * 设置本地缓存最大条目数。
         *
         * @param maxSize 条目数（超过后按 LRU 淘汰）
         */
        public void setMaxSize(int maxSize) { this.maxSize = maxSize; }
        /**
         * 获取异步刷新周期。
         *
         * @return 刷新秒数
         */
        public int getRefreshSeconds() { return refreshSeconds; }
        /**
         * 设置异步刷新周期。
         *
         * @param refreshSeconds 刷新秒数
         */
        public void setRefreshSeconds(int refreshSeconds) { this.refreshSeconds = refreshSeconds; }
    }

    /**
     * Redis 远端缓存配置。
     */
    public static class RedisConfig {
        /**
         * 是否启用 Redis。默认 {@code false}（单节点使用本地缓存即可）。
         */
        private boolean enabled = false;
        /**
         * 远端缓存 TTL（秒）。
         */
        private int ttlSeconds = 60;

        /**
         * 是否启用 Redis 缓存。
         *
         * @return {@code true} 启用
         */
        public boolean isEnabled() { return enabled; }
        /**
         * 设置是否启用 Redis 缓存。
         *
         * @param enabled 开关
         */
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        /**
         * 获取 Redis 远端缓存 TTL。
         *
         * @return 秒数
         */
        public int getTtlSeconds() { return ttlSeconds; }
        /**
         * 设置 Redis 远端缓存 TTL。
         *
         * @param ttlSeconds 秒数
         */
        public void setTtlSeconds(int ttlSeconds) { this.ttlSeconds = ttlSeconds; }
    }

    /**
     * 审计落盘配置（控制 {@code DisruptorAuditAdapter}）。
     */
    public static class AuditConfig {
        /**
         * 是否启用审计。默认 {@code true}。
         */
        private boolean enabled = true;
        /**
         * 审计日志文件路径。
         */
        private String logFilePath = "/var/log/anonymization/audit.log";
        /**
         * 批量刷盘阈值（达到该条数则触发刷盘）。
         */
        private int batchSize = 100;
        /**
         * 定时刷盘周期（秒）。
         */
        private int flushIntervalSeconds = 5;
        /**
         * Disruptor RingBuffer 大小（必须为 2 的幂）。
         */
        private int ringBufferSize = 65536;

        /**
         * 是否启用审计。
         *
         * @return {@code true} 启用
         */
        public boolean isEnabled() { return enabled; }
        /**
         * 设置是否启用审计。
         *
         * @param enabled 开关
         */
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        /**
         * 获取审计日志文件路径。
         *
         * @return 文件路径
         */
        public String getLogFilePath() { return logFilePath; }
        /**
         * 设置审计日志文件路径。
         *
         * @param logFilePath 路径
         */
        public void setLogFilePath(String logFilePath) { this.logFilePath = logFilePath; }
        /**
         * 获取批量刷盘阈值。
         *
         * @return 条目数
         */
        public int getBatchSize() { return batchSize; }
        /**
         * 设置批量刷盘阈值。
         *
         * @param batchSize 条目数
         */
        public void setBatchSize(int batchSize) { this.batchSize = batchSize; }
        /**
         * 获取定时刷盘周期。
         *
         * @return 秒数
         */
        public int getFlushIntervalSeconds() { return flushIntervalSeconds; }
        /**
         * 设置定时刷盘周期。
         *
         * @param flushIntervalSeconds 秒数
         */
        public void setFlushIntervalSeconds(int flushIntervalSeconds) { this.flushIntervalSeconds = flushIntervalSeconds; }
        /**
         * 获取 RingBuffer 大小。
         *
         * @return 必须为 2 的幂
         */
        public int getRingBufferSize() { return ringBufferSize; }
        /**
         * 设置 RingBuffer 大小。
         *
         * @param ringBufferSize 必须为 2 的幂
         */
        public void setRingBufferSize(int ringBufferSize) { this.ringBufferSize = ringBufferSize; }
    }

    /**
     * 熔断器配置（控制 Resilience4j {@code CircuitBreaker}）。
     */
    public static class CircuitBreakerConfig {
        /**
         * 是否启用熔断器。默认 {@code true}。
         */
        private boolean enabled = true;
        /**
         * 失败率阈值（百分比），超过则熔断打开。
         */
        private double failureRateThreshold = 50;
        /**
         * 慢调用阈值（字符串，如 {@code "10ms"}）。仅参考字段，实际解析在 AutoConfiguration。
         */
        private String slowCallDurationThreshold = "10ms";
        /**
         * 滑动窗口大小（最近 N 次调用）。
         */
        private int slidingWindowSize = 100;
        /**
         * Open 状态等待时间（字符串，如 {@code "30s"}）。
         */
        private String waitDurationInOpenState = "30s";

        /**
         * 是否启用熔断器。
         *
         * @return {@code true} 启用
         */
        public boolean isEnabled() { return enabled; }
        /**
         * 设置是否启用熔断器。
         *
         * @param enabled 开关
         */
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        /**
         * 获取失败率阈值（百分比）。
         *
         * @return 百分比
         */
        public double getFailureRateThreshold() { return failureRateThreshold; }
        /**
         * 设置失败率阈值。
         *
         * @param failureRateThreshold 百分比（{@code 0~100}）
         */
        public void setFailureRateThreshold(double failureRateThreshold) { this.failureRateThreshold = failureRateThreshold; }
        /**
         * 获取慢调用阈值字符串。
         *
         * @return 如 {@code "10ms"}
         */
        public String getSlowCallDurationThreshold() { return slowCallDurationThreshold; }
        /**
         * 设置慢调用阈值字符串。
         *
         * @param slowCallDurationThreshold 如 {@code "10ms"}
         */
        public void setSlowCallDurationThreshold(String slowCallDurationThreshold) { this.slowCallDurationThreshold = slowCallDurationThreshold; }
        /**
         * 获取滑动窗口大小。
         *
         * @return 调用次数
         */
        public int getSlidingWindowSize() { return slidingWindowSize; }
        /**
         * 设置滑动窗口大小。
         *
         * @param slidingWindowSize 调用次数
         */
        public void setSlidingWindowSize(int slidingWindowSize) { this.slidingWindowSize = slidingWindowSize; }
        /**
         * 获取 Open 状态等待时间字符串。
         *
         * @return 如 {@code "30s"}
         */
        public String getWaitDurationInOpenState() { return waitDurationInOpenState; }
        /**
         * 设置 Open 状态等待时间字符串。
         *
         * @param waitDurationInOpenState 如 {@code "30s"}
         */
        public void setWaitDurationInOpenState(String waitDurationInOpenState) { this.waitDurationInOpenState = waitDurationInOpenState; }
    }

    /**
     * 密钥配置（盐值等敏感参数）。
     */
    public static class SecretConfig {
        /**
         * 全局哈希盐值（用于 {@code HashMasker}）。
         * <p><b>警告</b>：默认值为占位符，生产环境务必替换为从 KMS / 环境变量注入的安全随机串。
         * <p>支持 Jasypt 加密格式：{@code ENC(密文字符串)}，配合 {@link JasyptConfig} 使用。
         */
        private String salt = "default-salt-change-me-in-production";

        /**
         * 是否启用 Jasypt 配置加密。
         *
         * <p>启用后，{@link #salt} 等敏感字段支持 {@code ENC(...)} 格式，
         * 由 {@link JasyptConfig} 提供的 {@code StringEncryptor} 自动解密。
         *
         * <p>前提条件：classpath 下需存在 {@code jasypt-spring-boot-starter} 依赖。
         */
        private boolean jasyptEnabled = false;

        /**
         * 获取全局哈希盐值。
         *
         * @return 盐值字符串（可能为 {@code ENC(...)} 格式，由 Jasypt 自动解密）
         */
        public String getSalt() { return salt; }
        /**
         * 设置全局哈希盐值。
         *
         * <p><b>警告</b>：生产环境务必从 KMS / 环境变量注入安全随机串。
         * 推荐使用 {@code ENC(...)} 格式存储密文，通过环境变量 {@code JASYPT_ENCRYPTOR_PASSWORD} 注入主密钥。
         *
         * @param salt 盐值字符串（明文或 {@code ENC(...)} 格式）
         */
        public void setSalt(String salt) { this.salt = salt; }
        /**
         * 是否启用 Jasypt 配置加密。
         *
         * @return {@code true} 启用
         */
        public boolean isJasyptEnabled() { return jasyptEnabled; }
        /**
         * 设置是否启用 Jasypt 配置加密。
         *
         * @param jasyptEnabled 开关
         */
        public void setJasyptEnabled(boolean jasyptEnabled) { this.jasyptEnabled = jasyptEnabled; }
    }

    /**
     * 大消息处理配置（控制 {@code LargeMessageHandler}）。
     */
    public static class LargeMessageConfig {
        /**
         * 单次扫描总字节数（首段 + 尾段）。
         */
        private int maxScanSize = 8192;
        /**
         * 超过此长度的消息视为超大消息，将被截断为占位符。
         */
        private int maxMessageSize = 65536;

        /**
         * 获取单次扫描总字节数。
         *
         * @return 字节数
         */
        public int getMaxScanSize() { return maxScanSize; }
        /**
         * 设置单次扫描总字节数。
         *
         * @param maxScanSize 字节数（首段 + 尾段）
         */
        public void setMaxScanSize(int maxScanSize) { this.maxScanSize = maxScanSize; }
        /**
         * 获取大消息阈值。
         *
         * @return 字节数
         */
        public int getMaxMessageSize() { return maxMessageSize; }
        /**
         * 设置大消息阈值。
         *
         * @param maxMessageSize 字节数（超过将被截断）
         */
        public void setMaxMessageSize(int maxMessageSize) { this.maxMessageSize = maxMessageSize; }
    }

    /**
     * 采样配置（控制 {@code SamplingController}）。
     */
    public static class SamplingConfig {
        /**
         * 是否启用采样。默认 {@code false}（全量脱敏）。
         */
        private boolean enabled = false;
        /**
         * 采样率（{@code [0.0, 1.0]}）。{@code 1.0} 表示全量。
         */
        private double rate = 1.0;

        /**
         * 是否启用采样。
         *
         * @return {@code true} 启用
         */
        public boolean isEnabled() { return enabled; }
        /**
         * 设置是否启用采样。
         *
         * @param enabled 开关
         */
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        /**
         * 获取采样率。
         *
         * @return 采样率 {@code [0.0, 1.0]}
         */
        public double getRate() { return rate; }
        /**
         * 设置采样率。
         *
         * @param rate 采样率
         */
        public void setRate(double rate) { this.rate = rate; }
    }

    /**
     * 规则校验配置（控制 {@code RuleValidator}）。
     */
    public static class ValidationConfig {
        /**
         * 是否快速失败（首次发现非法规则即抛出异常）。
         * 设为 {@code false} 时收集所有错误后统一抛出。
         */
        private boolean failFast = true;

        /**
         * 是否快速失败。
         *
         * @return {@code true} 首次发现非法规则即抛出异常；{@code false} 收集所有错误后统一抛出
         */
        public boolean isFailFast() { return failFast; }
        /**
         * 设置是否快速失败。
         *
         * @param failFast 开关
         */
        public void setFailFast(boolean failFast) { this.failFast = failFast; }
    }
}