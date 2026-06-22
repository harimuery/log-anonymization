package com.example.anonymization.api.port;

/**
 * 指标端口 —— 抽象脱敏组件对外暴露的运行时指标。
 *
 * <p>使用场景：在管道各 Stage（如 {@link com.example.anonymization.core.application.pipeline.AuditStage}、
 * {@link com.example.anonymization.core.application.pipeline.BloomFilterStage}）中上报指标，
 * 由 {@link com.example.anonymization.core.infrastructure.metrics.MicrometerMetricsAdapter}
 * 桥接到 Prometheus/StatsD 等监控系统。
 *
 * @author log-anonymization
 */
public interface MetricsPort {
    /**
     * 自增"已处理日志总数"计数器。
     *
     * <p>每条进入脱敏管道的日志调用一次，对应监控指标 {@code masking.processed.total}。
     */
    void incrementProcessed();

    /**
     * 自增"命中"计数器（按数据类型分桶）。
     *
     * <p>每次检测命中敏感数据时调用，对应监控指标 {@code masking.hits.total}，
     * 通过 tag 区分不同 dataType 用于业务报表。
     *
     * @param dataType 命中的敏感数据类型名称（如 {@code "BANK_CARD"}）
     */
    void incrementHits(String dataType);

    /**
     * 自增"错误"计数器（按数据类型分桶）。
     *
     * @param dataType 出错的数据类型名称
     */
    void incrementErrors(String dataType);

    /**
     * 记录单次脱敏处理耗时（纳秒）。
     *
     * <p>实现内部会归一化到 Timer（如 Micrometer Timer），
     * 自动产出 P50/P90/P99/P999 等分位数指标。
     *
     * @param nanos 处理耗时纳秒数
     */
    void recordLatency(long nanos);

    /**
     * 自增 BloomFilter 快速跳过计数器。
     *
     * <p>对应监控指标 {@code masking.bloom.filter.skips}，用于评估 BloomFilter
     * 预筛的命中率与性能收益。
     */
    void recordBloomFilterSkip();
}