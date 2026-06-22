package com.example.anonymization.core.infrastructure.config;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

/**
 * 独立熔断器配置类 —— 集中管理 Resilience4j {@link CircuitBreaker} 相关 Bean。
 *
 * <p>属于基础设施层（infrastructure/config），通过 Spring {@code @Configuration} 注解
 * 被 {@link com.example.anonymization.starter.LogAnonymizationAutoConfiguration}
 * 通过 {@code @Import} 引入。
 *
 * <p>设计原则：
 * <ul>
 *   <li><b>集中管理</b>：所有熔断器配置集中在此类，避免散落在各业务 Bean 中</li>
 *   <li><b>可配置</b>：阈值、窗口大小等通过 {@code application.yml} 动态调整</li>
 *   <li><b>字符串解析</b>：支持 {@code "10ms"} / {@code "30s"} 等人类可读的时间格式</li>
 *   <li><b>注册表模式</b>：通过 {@link CircuitBreakerRegistry} 统一管理多个熔断器实例</li>
 * </ul>
 *
 * <p>配置示例：
 * <pre>
 *   log-anonymization:
 *     circuit-breaker:
 *       enabled: true
 *       failure-rate-threshold: 50
 *       slow-call-duration-threshold: "10ms"
 *       slow-call-rate-threshold: 80
 *       sliding-window-size: 100
 *       minimum-number-of-calls: 10
 *       wait-duration-in-open-state: "30s"
 *       permitted-number-of-calls-in-half-open-state: 5
 * </pre>
 *
 * <p>熔断状态机：
 * <pre>
 *   CLOSED（正常）
 *     │ 失败率/慢调用率超阈值
 *     ▼
 *   OPEN（熔断，快速失败）
 *     │ 等待 wait-duration-in-open-state
 *     ▼
 *   HALF_OPEN（半开，放行少量请求探测）
 *     │ 探测成功 → CLOSED
 *     │ 探测失败 → OPEN
 * </pre>
 *
 * @author java-architect
 * @since 1.0.0
 */
@Configuration
public class CircuitBreakerConfigBean {

    private static final Logger log = LoggerFactory.getLogger(CircuitBreakerConfigBean.class);

    /**
     * 熔断器名称常量 —— 用于在监控指标和日志中标识脱敏引擎的熔断器。
     */
    public static final String MASKING_ENGINE_BREAKER = "maskingEngine";

    /**
     * 熔断器注册表 —— 统一管理所有熔断器实例。
     *
     * <p>使用 {@link CircuitBreakerRegistry} 而非直接创建 {@link CircuitBreaker}，
     * 便于未来扩展多个熔断器（如分别对检测、脱敏、审计设置独立熔断器）。
     *
     * @param failureRateThreshold           失败率阈值（百分比）
     * @param slowCallDurationThresholdStr   慢调用阈值（字符串，如 {@code "10ms"}）
     * @param slowCallRateThreshold          慢调用率阈值（百分比）
     * @param slidingWindowSize              滑动窗口大小
     * @param minimumNumberOfCalls           最小调用次数（达到后才开始计算失败率）
     * @param waitDurationInOpenStateStr     Open 状态等待时间（字符串，如 {@code "30s"}）
     * @param permittedCallsInHalfOpen       半开状态允许的探测请求数
     * @return 熔断器注册表
     */
    @Bean
    @ConditionalOnMissingBean
    public CircuitBreakerRegistry circuitBreakerRegistry(
            @Value("${log-anonymization.circuit-breaker.failure-rate-threshold:50}") double failureRateThreshold,
            @Value("${log-anonymization.circuit-breaker.slow-call-duration-threshold:10ms}") String slowCallDurationThresholdStr,
            @Value("${log-anonymization.circuit-breaker.slow-call-rate-threshold:80}") double slowCallRateThreshold,
            @Value("${log-anonymization.circuit-breaker.sliding-window-size:100}") int slidingWindowSize,
            @Value("${log-anonymization.circuit-breaker.minimum-number-of-calls:10}") int minimumNumberOfCalls,
            @Value("${log-anonymization.circuit-breaker.wait-duration-in-open-state:30s}") String waitDurationInOpenStateStr,
            @Value("${log-anonymization.circuit-breaker.permitted-number-of-calls-in-half-open-state:5}") int permittedCallsInHalfOpen) {

        CircuitBreakerConfig config = CircuitBreakerConfig.custom()
            .failureRateThreshold((float) failureRateThreshold)
            .slowCallDurationThreshold(parseDuration(slowCallDurationThresholdStr, Duration.ofMillis(10)))
            .slowCallRateThreshold((float) slowCallRateThreshold)
            .slidingWindowSize(slidingWindowSize)
            .minimumNumberOfCalls(minimumNumberOfCalls)
            .waitDurationInOpenState(parseDuration(waitDurationInOpenStateStr, Duration.ofSeconds(30)))
            .permittedNumberOfCallsInHalfOpenState(permittedCallsInHalfOpen)
            .automaticTransitionFromOpenToHalfOpenEnabled(true)
            .writableStackTraceEnabled(false)
            .build();

        log.info("熔断器注册表已初始化: failureRate={}%, slowCall={}, slidingWindow={}, waitOpen={}",
            failureRateThreshold, slowCallDurationThresholdStr, slidingWindowSize, waitDurationInOpenStateStr);

        return CircuitBreakerRegistry.of(config);
    }

    /**
     * 脱敏引擎熔断器 —— 保护脱敏主路径不被下游故障拖垮。
     *
     * <p>当脱敏失败率超过阈值时，熔断器打开，后续请求直接走 {@link com.example.anonymization.core.infrastructure.masker.FallbackMasker}
     * 降级路径，避免故障扩散。
     *
     * @param registry 熔断器注册表
     * @return 脱敏引擎熔断器实例
     */
    @Bean
    @ConditionalOnMissingBean(name = "maskingCircuitBreaker")
    public CircuitBreaker maskingCircuitBreaker(CircuitBreakerRegistry registry) {
        return registry.circuitBreaker(MASKING_ENGINE_BREAKER);
    }

    /**
     * 解析时间字符串为 {@link Duration}。
     *
     * <p>支持的格式：
     * <ul>
     *   <li>{@code "10ms"} → 10 毫秒</li>
     *   <li>{@code "5s"} → 5 秒</li>
     *   <li>{@code "2m"} → 2 分钟</li>
     *   <li>{@code "1h"} → 1 小时</li>
     *   <li>{@code "100"} → 100 毫秒（纯数字默认毫秒）</li>
     * </ul>
     *
     * @param value        时间字符串
     * @param defaultValue 解析失败时的默认值
     * @return 解析后的 Duration
     */
    static Duration parseDuration(String value, Duration defaultValue) {
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        String trimmed = value.trim().toLowerCase();
        try {
            if (trimmed.endsWith("ms")) {
                return Duration.ofMillis(Long.parseLong(trimmed.substring(0, trimmed.length() - 2)));
            } else if (trimmed.endsWith("s")) {
                return Duration.ofSeconds(Long.parseLong(trimmed.substring(0, trimmed.length() - 1)));
            } else if (trimmed.endsWith("m")) {
                return Duration.ofMinutes(Long.parseLong(trimmed.substring(0, trimmed.length() - 1)));
            } else if (trimmed.endsWith("h")) {
                return Duration.ofHours(Long.parseLong(trimmed.substring(0, trimmed.length() - 1)));
            } else {
                return Duration.ofMillis(Long.parseLong(trimmed));
            }
        } catch (NumberFormatException e) {
            log.warn("无法解析时间字符串 '{}', 使用默认值 {}", value, defaultValue);
            return defaultValue;
        }
    }
}