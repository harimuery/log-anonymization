package com.example.anonymization.core.application;

import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.model.MaskingContext;
import com.example.anonymization.api.model.MaskingResult;
import com.example.anonymization.api.port.MetricsPort;
import com.example.anonymization.core.application.pipeline.DefaultMaskingPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MaskingApplicationServiceTest {

    @Mock
    private DefaultMaskingPipeline pipeline;

    @Mock
    private MetricsPort metricsPort;

    private MaskingApplicationService service;

    @BeforeEach
    void setUp() {
        service = new MaskingApplicationService(pipeline, metricsPort);
    }

    @Test
    @DisplayName("process委派给pipeline并返回结果")
    void process_delegatesToPipeline() {
        MaskingResult expectedResult = MaskingResult.masked("6222021234567890", "6222************7890");
        when(pipeline.execute(any(MaskingContext.class))).thenReturn(expectedResult);
        LogContext ctx = LogContext.builder().message("6222021234567890").loggerName("test").threadName("main").build();
        MaskingResult result = service.process("6222021234567890", ctx);
        assertEquals(expectedResult, result);
        verify(pipeline).execute(any(MaskingContext.class));
    }

    @Test
    @DisplayName("process无论成败都上报耗时指标")
    void process_recordsLatency() {
        when(pipeline.execute(any(MaskingContext.class))).thenReturn(MaskingResult.unchanged("test"));
        LogContext ctx = LogContext.builder().message("test").loggerName("test").threadName("main").build();
        service.process("test", ctx);
        verify(metricsPort).recordLatency(anyLong());
    }

    @Test
    @DisplayName("process异常时仍上报耗时指标")
    void process_recordsLatencyOnError() {
        when(pipeline.execute(any(MaskingContext.class))).thenThrow(new RuntimeException("pipeline error"));
        LogContext ctx = LogContext.builder().message("test").loggerName("test").threadName("main").build();
        assertThrows(RuntimeException.class, () -> service.process("test", ctx));
        verify(metricsPort).recordLatency(anyLong());
    }
}