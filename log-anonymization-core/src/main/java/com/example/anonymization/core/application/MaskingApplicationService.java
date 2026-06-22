package com.example.anonymization.core.application;

import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.model.MaskingContext;
import com.example.anonymization.api.model.MaskingResult;
import com.example.anonymization.api.port.MaskingPort;
import com.example.anonymization.api.port.MetricsPort;
import com.example.anonymization.core.application.pipeline.DefaultMaskingPipeline;

/**
 * 脱敏应用服务 —— 应用层主入口，是日志框架与脱敏管道之间的协调器。
 *
 * <p>职责：
 * <ol>
 *   <li>构建 {@link MaskingContext}（携带消息与日志上下文）</li>
 *   <li>委派给 {@link DefaultMaskingPipeline} 执行实际管道</li>
 *   <li>无论成败均上报耗时指标至 {@link MetricsPort}</li>
 * </ol>
 *
 * <p>使用场景：作为 {@link MaskingPort} 的标准实现被 Logback/Log4j2 Converter 调用，
 * 也可由业务代码直接调用做"日志产生端预脱敏"。
 *
 * <p>线程安全：本类无状态，所有依赖（pipeline/metricsPort）均为线程安全实现。
 *
 * @author log-anonymization
 */
public class MaskingApplicationService implements MaskingPort {

    /** 脱敏管道（BloomFilter → Detection → Masking → Audit） */
    private final DefaultMaskingPipeline pipeline;
    /** 指标端口（用于上报处理耗时） */
    private final MetricsPort metricsPort;

    /**
     * 构造脱敏应用服务。
     *
     * @param pipeline    脱敏管道实例
     * @param metricsPort 指标端口实例
     */
    public MaskingApplicationService(DefaultMaskingPipeline pipeline, MetricsPort metricsPort) {
        this.pipeline = pipeline;
        this.metricsPort = metricsPort;
    }

    /**
     * 对单条日志执行脱敏处理（{@link MaskingPort} 主入口）。
     *
     * <p>流程：
     * <ol>
     *   <li>记录起始纳秒时间戳</li>
     *   <li>构建 {@link MaskingContext}，调用 pipeline.execute</li>
     *   <li>finally 块中上报耗时（确保异常路径也记录）</li>
     * </ol>
     *
     * @param message 原始日志消息
     * @param context 日志上下文
     * @return 脱敏结果（来自管道最终写入 context 的 {@link MaskingResult}）
     */
    @Override
    public MaskingResult process(String message, LogContext context) {
        long start = System.nanoTime();
        try {
            MaskingContext maskingContext = new MaskingContext(message, context);
            MaskingResult result = pipeline.execute(maskingContext);
            return result;
        } finally {
            metricsPort.recordLatency(System.nanoTime() - start);
        }
    }
}