package com.example.anonymization.core.infrastructure.metrics;

import com.example.anonymization.api.port.MetricsPort;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;

import java.util.concurrent.TimeUnit;

/**
 * Micrometer 指标适配器（Metrics Adapter）。
 *
 * <p>属于基础设施层（infrastructure/metrics），是 {@link MetricsPort} 接口的 Micrometer 实现，
 * 将脱敏管道的关键运行时数据暴露为 Micrometer 指标，供 Prometheus / Grafana 采集与展示。
 *
 * <p>注册的指标：
 * <ul>
 *   <li>{@code masking.processed.total}：处理的总日志条数（Counter）；</li>
 *   <li>{@code masking.hits.total}：命中敏感数据的次数（Counter）；</li>
 *   <li>{@code masking.errors.total}：脱敏失败的次数（Counter）；</li>
 *   <li>{@code masking.bloom.filter.skips}：布隆过滤器拦截跳过的次数（Counter）；</li>
 *   <li>{@code masking.latency}：单次脱敏处理延迟（Timer，发布 P50/P90/P99/P999 分位数）。</li>
 * </ul>
 *
 * <p>设计取舍：{@code dataType} 参数当前未绑定到 tag（保持 tag 基数稳定，避免 Prometheus 高基数问题），
 * 后续可按需增加 {@code .tag("dataType", dataType)}。
 *
 * <p>线程安全：Micrometer 的 Counter / Timer 内部已使用无锁 CAS，适配器自身无状态。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class MicrometerMetricsAdapter implements MetricsPort {

    /**
     * 已处理日志条数计数器（{@code masking.processed.total}）。
     */
    private final Counter totalProcessed;

    /**
     * 命中敏感数据次数计数器（{@code masking.hits.total}）。
     */
    private final Counter totalHits;

    /**
     * 脱敏错误次数计数器（{@code masking.errors.total}）。
     */
    private final Counter totalErrors;

    /**
     * 布隆过滤器拦截跳过次数计数器（{@code masking.bloom.filter.skips}）。
     */
    private final Counter bloomFilterSkips;

    /**
     * 脱敏处理延迟计时器（{@code masking.latency}），发布 P50/P90/P99/P999 分位数。
     */
    private final Timer maskingLatency;

    /**
     * 构造指标适配器，立即向注册中心注册全部指标。
     *
     * @param registry Micrometer 注册中心，由 Spring Boot 启动时自动注入
     *                 （通常来自 actuator 的 {@code MeterRegistry} bean）
     */
    public MicrometerMetricsAdapter(MeterRegistry registry) {
        this.totalProcessed = Counter.builder("masking.processed.total")
            .description("Total processed log entries").register(registry);
        this.totalHits = Counter.builder("masking.hits.total")
            .description("Total sensitive data hits").register(registry);
        this.totalErrors = Counter.builder("masking.errors.total")
            .description("Total masking errors").register(registry);
        this.bloomFilterSkips = Counter.builder("masking.bloom.filter.skips")
            .description("Bloom filter fast skips").register(registry);
        this.maskingLatency = Timer.builder("masking.latency")
            .description("Masking processing latency")
            .publishPercentiles(0.50, 0.90, 0.99, 0.999)
            .register(registry);
    }

    /**
     * 增加"已处理日志条数"计数。
     *
     * <p>由 {@link com.example.anonymization.core.application.MaskingApplicationService} 在每次
     * {@link com.example.anonymization.api.port.MaskingPort#process(String, com.example.anonymization.api.model.LogContext)} 调用结束后递增。
     */
    @Override
    public void incrementProcessed() {
        totalProcessed.increment();
    }

    /**
     * 增加"命中敏感数据"计数。
     *
     * @param dataType 命中的数据类型（当前未绑定到 tag，预留扩展点）
     */
    @Override
    public void incrementHits(String dataType) {
        totalHits.increment();
    }

    /**
     * 增加"脱敏错误"计数。
     *
     * @param dataType 出错的数据类型（当前未绑定到 tag，预留扩展点）
     */
    @Override
    public void incrementErrors(String dataType) {
        totalErrors.increment();
    }

    /**
     * 记录单次脱敏处理耗时。
     *
     * @param nanos 耗时（纳秒）；由调用方使用 {@code System.nanoTime()} 计算并传入
     */
    @Override
    public void recordLatency(long nanos) {
        maskingLatency.record(nanos, TimeUnit.NANOSECONDS);
    }

    /**
     * 增加"布隆过滤器拦截跳过"计数。
     *
     * <p>由 {@link com.example.anonymization.core.application.pipeline.BloomFilterStage} 调用，
     * 用于衡量布隆过滤器带来的整体性能收益。
     */
    @Override
    public void recordBloomFilterSkip() {
        bloomFilterSkips.increment();
    }
}