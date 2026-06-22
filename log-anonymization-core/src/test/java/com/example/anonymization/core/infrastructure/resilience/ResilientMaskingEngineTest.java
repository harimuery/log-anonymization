package com.example.anonymization.core.infrastructure.resilience;

import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.model.MaskingResult;
import com.example.anonymization.api.port.MaskingPort;
import com.example.anonymization.core.infrastructure.masker.FallbackMasker;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class ResilientMaskingEngineTest {

    private ResilientMaskingEngine engine;
    private MaskingPort delegate;
    private CircuitBreaker circuitBreaker;

    @BeforeEach
    void setUp() {
        delegate = (message, context) -> MaskingResult.masked(message, "***MASKED***");
        circuitBreaker = CircuitBreaker.of("test",
            CircuitBreakerConfig.custom()
                .failureRateThreshold(50)
                .slowCallRateThreshold(80)
                .slowCallDurationThreshold(Duration.ofMillis(10))
                .waitDurationInOpenState(Duration.ofSeconds(30))
                .slidingWindowSize(10)
                .build());
        engine = new ResilientMaskingEngine(delegate, circuitBreaker, new FallbackMasker());
    }

    @Test
    @DisplayName("正常路径返回脱敏结果")
    void process_normal() {
        LogContext ctx = LogContext.builder().message("test").loggerName("test").threadName("main").build();
        MaskingResult result = engine.process("test message", ctx);
        assertTrue(result.isChanged());
        assertEquals("***MASKED***", result.getMasked());
    }

    @Test
    @DisplayName("下游异常时降级到FallbackMasker")
    void process_fallbackOnError() {
        MaskingPort failingDelegate = (message, context) -> {
            throw new RuntimeException("downstream failure");
        };
        ResilientMaskingEngine failingEngine = new ResilientMaskingEngine(
            failingDelegate, circuitBreaker, new FallbackMasker());
        LogContext ctx = LogContext.builder().message("test").loggerName("test").threadName("main").build();
        MaskingResult result = failingEngine.process("test message", ctx);
        assertTrue(result.isDegraded());
    }

    @Test
    @DisplayName("熔断器状态可查询")
    void process_circuitBreakerState() {
        assertEquals(CircuitBreaker.State.CLOSED, circuitBreaker.getState());
        LogContext ctx = LogContext.builder().message("test").loggerName("test").threadName("main").build();
        engine.process("test", ctx);
        assertEquals(CircuitBreaker.State.CLOSED, circuitBreaker.getState());
    }
}