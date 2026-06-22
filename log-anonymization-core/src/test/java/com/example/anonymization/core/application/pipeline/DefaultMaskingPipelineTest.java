package com.example.anonymization.core.application.pipeline;

import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.event.DomainEventBus;
import com.example.anonymization.api.event.MaskingCompletedEvent;
import com.example.anonymization.api.model.DetectionResult;
import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.model.MaskingContext;
import com.example.anonymization.api.model.MaskingResult;
import com.example.anonymization.api.port.AuditPort;
import com.example.anonymization.api.port.MetricsPort;
import com.example.anonymization.core.domain.service.SensitiveDataDetectionService;
import com.example.anonymization.core.domain.service.SensitiveDataMaskingService;
import com.example.anonymization.core.infrastructure.filter.SensitiveDataBloomFilter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DefaultMaskingPipelineTest {

    @Nested
    @DisplayName("BloomFilterStage")
    class BloomFilterStageTest {

        @Test
        @DisplayName("布隆过滤器判断无敏感数据时短路返回unchanged")
        void process_shortCircuit(@Mock SensitiveDataBloomFilter bloomFilter) {
            when(bloomFilter.mightContainSensitiveData(any())).thenReturn(false);
            BloomFilterStage stage = new BloomFilterStage(bloomFilter);
            MaskingContext ctx = new MaskingContext("normal message",
                LogContext.builder().message("normal message").loggerName("test").threadName("main").build());
            stage.process(ctx);
            assertNotNull(ctx.result());
            assertFalse(ctx.result().isChanged());
        }

        @Test
        @DisplayName("布隆过滤器判断可能含敏感数据时传递到下一Stage")
        void process_continue(@Mock SensitiveDataBloomFilter bloomFilter) {
            when(bloomFilter.mightContainSensitiveData(any())).thenReturn(true);
            BloomFilterStage stage = new BloomFilterStage(bloomFilter);
            MaskingContext ctx = new MaskingContext("card=6222021234567890",
                LogContext.builder().message("card=6222021234567890").loggerName("test").threadName("main").build());
            stage.process(ctx);
            assertNull(ctx.result());
        }
    }

    @Nested
    @DisplayName("DetectionStage")
    class DetectionStageTest {

        @Test
        @DisplayName("检测结果为空时短路返回unchanged")
        void process_noDetections(@Mock SensitiveDataDetectionService detectionService) {
            when(detectionService.detect(any())).thenReturn(Collections.emptyList());
            DetectionStage stage = new DetectionStage(detectionService);
            MaskingContext ctx = new MaskingContext("normal",
                LogContext.builder().message("normal").loggerName("test").threadName("main").build());
            stage.process(ctx);
            assertNotNull(ctx.result());
            assertFalse(ctx.result().isChanged());
        }

        @Test
        @DisplayName("检测到敏感数据时写入detections并传递")
        void process_withDetections(@Mock SensitiveDataDetectionService detectionService) {
            DetectionResult detection = new DetectionResult(
                0, 16, SensitiveDataType.BANK_CARD, 1.0, "6222021234567890");
            when(detectionService.detect(any())).thenReturn(List.of(detection));
            DetectionStage stage = new DetectionStage(detectionService);
            MaskingContext ctx = new MaskingContext("6222021234567890",
                LogContext.builder().message("6222021234567890").loggerName("test").threadName("main").build());
            stage.process(ctx);
            assertFalse(ctx.detections().isEmpty());
            assertNull(ctx.result());
        }
    }

    @Nested
    @DisplayName("MaskingStage")
    class MaskingStageTest {

        @Test
        @DisplayName("调用maskingService执行替换并写入result")
        void process_masking(@Mock SensitiveDataMaskingService maskingService) {
            when(maskingService.mask(any(), any())).thenReturn(MaskingResult.masked("6222021234567890", "6222************7890"));
            MaskingStage stage = new MaskingStage(maskingService);
            DetectionResult detection = new DetectionResult(
                0, 16, SensitiveDataType.BANK_CARD, 1.0, "6222021234567890");
            MaskingContext ctx = new MaskingContext("6222021234567890",
                LogContext.builder().message("6222021234567890").loggerName("test").threadName("main").build());
            ctx.setDetections(List.of(detection));
            stage.process(ctx);
            assertNotNull(ctx.result());
            assertTrue(ctx.result().isChanged());
        }
    }

    @Nested
    @DisplayName("AuditStage")
    class AuditStageTest {

        @Test
        @DisplayName("changed=true时上报指标和事件")
        void process_changed(
            @Mock AuditPort auditPort,
            @Mock MetricsPort metricsPort,
            @Mock DomainEventBus eventBus
        ) {
            AuditStage stage = new AuditStage(auditPort, metricsPort, eventBus);
            DetectionResult detection = new DetectionResult(
                0, 16, SensitiveDataType.BANK_CARD, 1.0, "6222021234567890");
            MaskingContext ctx = new MaskingContext("6222021234567890",
                LogContext.builder().message("6222021234567890").loggerName("test").threadName("main").build());
            ctx.setDetections(List.of(detection));
            ctx.setResult(MaskingResult.masked("6222021234567890", "6222************7890"));
            stage.process(ctx);
            verify(metricsPort).incrementProcessed();
            verify(metricsPort).incrementHits(SensitiveDataType.BANK_CARD.name());
            verify(eventBus).publish(any(MaskingCompletedEvent.class));
        }

        @Test
        @DisplayName("changed=false时仅上报processed计数")
        void process_unchanged(
            @Mock AuditPort auditPort,
            @Mock MetricsPort metricsPort,
            @Mock DomainEventBus eventBus
        ) {
            AuditStage stage = new AuditStage(auditPort, metricsPort, eventBus);
            MaskingContext ctx = new MaskingContext("normal",
                LogContext.builder().message("normal").loggerName("test").threadName("main").build());
            ctx.setResult(MaskingResult.unchanged("normal"));
            stage.process(ctx);
            verify(metricsPort).incrementProcessed();
            verify(metricsPort, never()).incrementHits(any());
            verify(eventBus, never()).publish(any());
        }
    }

    @Nested
    @DisplayName("DefaultMaskingPipeline完整管道")
    class FullPipelineTest {

        @Test
        @DisplayName("空stages列表抛IllegalArgumentException")
        void construct_emptyStages() {
            assertThrows(IllegalArgumentException.class, () -> new DefaultMaskingPipeline(List.of()));
        }

        @Test
        @DisplayName("null stages抛IllegalArgumentException")
        void construct_nullStages() {
            assertThrows(IllegalArgumentException.class, () -> new DefaultMaskingPipeline(null));
        }

        @Test
        @DisplayName("单Stage管道正常执行")
        void singleStagePipeline(@Mock SensitiveDataBloomFilter bloomFilter) {
            when(bloomFilter.mightContainSensitiveData(any())).thenReturn(false);
            BloomFilterStage stage = new BloomFilterStage(bloomFilter);
            DefaultMaskingPipeline pipeline = new DefaultMaskingPipeline(List.of(stage));
            MaskingContext ctx = new MaskingContext("normal",
                LogContext.builder().message("normal").loggerName("test").threadName("main").build());
            MaskingResult result = pipeline.execute(ctx);
            assertNotNull(result);
            assertFalse(result.isChanged());
        }
    }
}