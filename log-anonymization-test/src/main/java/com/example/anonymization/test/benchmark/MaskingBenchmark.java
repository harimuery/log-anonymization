package com.example.anonymization.test.benchmark;

import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.event.DomainEvent;
import com.example.anonymization.api.event.DomainEventBus;
import com.example.anonymization.api.model.*;
import com.example.anonymization.api.port.AuditPort;
import com.example.anonymization.api.port.MetricsPort;
import com.example.anonymization.api.spi.SensitiveDataDetector;
import com.example.anonymization.core.application.pipeline.*;
import com.example.anonymization.core.domain.DetectorRegistry;
import com.example.anonymization.core.domain.ThreadSafeRuleManager;
import com.example.anonymization.core.domain.service.RuleMatchService;
import com.example.anonymization.core.domain.service.SensitiveDataDetectionService;
import com.example.anonymization.core.domain.service.SensitiveDataMaskingService;
import com.example.anonymization.core.domain.service.impl.DefaultSensitiveDataDetectionService;
import com.example.anonymization.core.domain.service.impl.DefaultSensitiveDataMaskingService;
import com.example.anonymization.core.infrastructure.detector.*;
import com.example.anonymization.core.infrastructure.filter.SensitiveDataBloomFilter;
import com.example.anonymization.core.infrastructure.masker.*;
import com.example.anonymization.core.infrastructure.util.SensitiveToStringHelper;
import org.openjdk.jmh.annotations.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

@BenchmarkMode({Mode.AverageTime, Mode.Throughput, Mode.SampleTime})
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(1)
@State(Scope.Benchmark)
public class MaskingBenchmark {

    private DefaultMaskingPipeline pipelineWithRules;
    private DefaultMaskingPipeline emptyPipeline;
    private SensitiveDataBloomFilter bloomFilter;
    private ThreadSafeRuleManager ruleManager;
    private CompositeDetector compositeDetector;

    private static final String NON_SENSITIVE_LOG = "用户登录成功，userId=10086，traceId=550e8400-e29b-41d4-a716-446655440000";
    private static final String SENSITIVE_LOG_PHONE = "用户支付，手机号：13812345678，金额：100.00";
    private static final String SENSITIVE_LOG_CARD = "银行卡号：6222021234567890123，CVV：123，有效期：2025/08";
    private static final String LARGE_LOG_8KB = generateLargeLog(8192);
    private static final String EXCEPTION_STACK = generateExceptionStack();

    @Setup
    public void setup() {
        bloomFilter = new SensitiveDataBloomFilter();
        ruleManager = new ThreadSafeRuleManager();

        List<SensitiveDataDetector> detectors = new ArrayList<>();
        detectors.add(new Re2jPhoneDetector(DetectorConfig.builder()
            .patterns(List.of("\\b(1[3-9]\\d{9})\\b"))
            .build()));
        detectors.add(new Re2jBankCardDetector(DetectorConfig.builder()
            .patterns(List.of("\\b(\\d{16,19})\\b"))
            .enableLuhnCheck(true)
            .build()));
        detectors.add(new Re2jIdCardDetector(DetectorConfig.builder()
            .patterns(List.of("\\b(\\d{17}[0-9Xx])\\b"))
            .enableChecksum(true)
            .build()));
        detectors.add(new AhoCorasickKeywordDetector(DetectorConfig.builder()
            .keywords(List.of("password", "cardNo", "apiKey", "cvv", "secretKey"))
            .contextPattern("([A-Za-z0-9+/=]{20,})")
            .build()));
        detectors.add(new FieldNameDetector(DetectorConfig.builder()
            .fieldNames(List.of("password", "cardNo", "mobile", "idCard", "pan"))
            .build()));

        compositeDetector = new CompositeDetector(detectors);

        List<MaskingRule> rules = new ArrayList<>();
        rules.add(com.example.anonymization.test.RuleTestFactory.bankCardRule());
        rules.add(com.example.anonymization.test.RuleTestFactory.phoneRule());
        rules.add(com.example.anonymization.test.RuleTestFactory.idCardRule());

        ruleManager.refreshRules(rules);
        bloomFilter.rebuild(rules);

        pipelineWithRules = createPipeline(ruleManager);
        emptyPipeline = createEmptyPipeline();
    }

    @Benchmark
    public void bloomFilterSkip_NonSensitive() {
        bloomFilter.mightContainSensitiveData(NON_SENSITIVE_LOG);
    }

    @Benchmark
    public MaskingResult maskSingleLog_WithSensitiveData() {
        LogContext context = LogContext.builder().message(SENSITIVE_LOG_PHONE).build();
        return pipelineWithRules.execute(new MaskingContext(SENSITIVE_LOG_PHONE, context));
    }

    @Benchmark
    public MaskingResult maskSingleLog_BankCard() {
        LogContext context = LogContext.builder().message(SENSITIVE_LOG_CARD).build();
        return pipelineWithRules.execute(new MaskingContext(SENSITIVE_LOG_CARD, context));
    }

    @Benchmark
    public MaskingResult maskEmptyRule_NoHit() {
        LogContext context = LogContext.builder().message(NON_SENSITIVE_LOG).build();
        return emptyPipeline.execute(new MaskingContext(NON_SENSITIVE_LOG, context));
    }

    @Benchmark
    public List<DetectionResult> acKeywordDetect_MultiKeywords() {
        DetectorConfig config = DetectorConfig.builder()
            .keywords(List.of("password", "cardNo", "apiKey", "cvv"))
            .contextPattern("([A-Za-z0-9]{20,})")
            .build();
        AhoCorasickKeywordDetector detector = new AhoCorasickKeywordDetector(config);
        LogContext context = LogContext.builder()
            .message("apiKey=AKIAIOSFODNN7EXAMPLE password=mySecret1234567890 cvv=123 cardNo=6222021234567890")
            .build();
        return detector.detect(context);
    }

    @Benchmark
    public List<DetectionResult> compositeDetect_AllDetectors() {
        LogContext context = LogContext.builder()
            .message("用户张三的手机号是13812345678，银行卡号6222021234567890123，密码abc123")
            .build();
        return compositeDetector.detect(context);
    }

    @Benchmark
    public String sensitiveToString_AnnotatedObject() {
        TestPaymentRequest request = new TestPaymentRequest(
            "张三",
            "13812345678",
            "6222021234567890123",
            "mypassword"
        );
        return SensitiveToStringHelper.safeToString(request);
    }

    @Benchmark
    public MaskingResult maskLargeMessage_8KB() {
        LogContext context = LogContext.builder().message(LARGE_LOG_8KB).build();
        return pipelineWithRules.execute(new MaskingContext(LARGE_LOG_8KB, context));
    }

    @Benchmark
    public String exceptionSanitize_5LayerCauseChain() {
        Exception ex = buildDeepExceptionChain(5);
        return SensitiveToStringHelper.maskValue(ex.getMessage(),
            SensitiveDataType.BANK_CARD);
    }

    @Threads(50)
    @Benchmark
    public MaskingResult concurrentMasking_50Threads() {
        LogContext context = LogContext.builder().message(SENSITIVE_LOG_PHONE).build();
        return pipelineWithRules.execute(new MaskingContext(SENSITIVE_LOG_PHONE, context));
    }

    private DefaultMaskingPipeline createPipeline(ThreadSafeRuleManager manager) {
        MetricsPort metricsPort = new MetricsPort() {
            @Override public void incrementProcessed() {}
            @Override public void incrementHits(String dataType) {}
            @Override public void incrementErrors(String dataType) {}
            @Override public void recordLatency(long nanos) {}
            @Override public void recordBloomFilterSkip() {}
        };

        DomainEventBus eventBus = new DomainEventBus() {
            @Override public void publish(DomainEvent event) {}
            @Override public <T extends DomainEvent> void subscribe(Class<T> eventType, Consumer<T> handler) {}
        };

        AuditPort auditPort = record -> {};

        DetectorRegistry detectorRegistry = new DetectorRegistry(List.of(compositeDetector));

        RuleMatchService ruleMatchService = new RuleMatchService() {
            @Override
            public List<MaskingRule> findApplicableRules(LogContext context) {
                return manager.getCurrentRules();
            }

            @Override
            public Optional<MaskingRule> findRuleForDetection(DetectionResult detection) {
                return manager.getCurrentRules().stream()
                    .filter(r -> r.getDataType() == detection.dataType())
                    .findFirst();
            }
        };

        SensitiveDataDetectionService detectionService =
            new DefaultSensitiveDataDetectionService(detectorRegistry, manager, ruleMatchService);

        MaskerFactory maskerFactory = new MaskerFactory(List.of(
            new PartialMaskMasker(),
            new FullMaskMasker(),
            new DiscardMasker(),
            new HashMasker("benchmark-salt"),
            new GeneralizeMasker()
        ));

        SensitiveDataMaskingService maskingService =
            new DefaultSensitiveDataMaskingService(maskerFactory, manager, ruleMatchService);

        List<PipelineStage> stages = new ArrayList<>();
        stages.add(new BloomFilterStage(bloomFilter));
        stages.add(new DetectionStage(detectionService));
        stages.add(new MaskingStage(maskingService));
        stages.add(new AuditStage(auditPort, metricsPort, eventBus));
        return new DefaultMaskingPipeline(stages);
    }

    private DefaultMaskingPipeline createEmptyPipeline() {
        return createPipeline(new ThreadSafeRuleManager());
    }

    private static String generateLargeLog(int size) {
        StringBuilder sb = new StringBuilder(size);
        sb.append("[INFO] 用户请求开始，traceId=550e8400-");
        while (sb.length() < size - 200) {
            sb.append("普通业务日志内容，时间戳=").append(System.currentTimeMillis())
              .append(" 操作=查询 计数=100 状态=OK ");
        }
        sb.append("敏感信息: 手机号=13800138000 银行卡=6222021234567890 [INFO] 请求结束");
        return sb.toString();
    }

    private static String generateExceptionStack() {
        try {
            throw new RuntimeException("Outer exception with cardNo=6222021234567890",
                new RuntimeException("Middle layer error, phone=13812345678",
                    new RuntimeException("Inner SQL error: Duplicate entry '6222021234567890' for key")));
        } catch (Exception e) {
            StringBuilder sb = new StringBuilder();
            Throwable current = e;
            int depth = 0;
            while (current != null && depth < 5) {
                sb.append(current.getClass().getName())
                  .append(": ").append(current.getMessage()).append("\n");
                for (StackTraceElement ste : current.getStackTrace()) {
                    sb.append("\tat ").append(ste.toString()).append("\n");
                    if (sb.length() > 4096) break;
                }
                current = current.getCause();
                depth++;
            }
            return sb.toString();
        }
    }

    private static Exception buildDeepExceptionChain(int depth) {
        Exception root = new Exception("Level-0: cardNo=6222021234567890");
        Exception current = root;
        for (int i = 1; i < depth; i++) {
            current = new Exception("Level-" + i + ": phone=138" + String.format("%08d", i), current);
        }
        return root;
    }

    @SuppressWarnings("unused")
    public static class TestPaymentRequest {
        private String name;
        @com.example.anonymization.api.annotation.SensitiveField(
            com.example.anonymization.api.enums.SensitiveDataType.PHONE)
        private String phone;
        @com.example.anonymization.api.annotation.SensitiveField(
            com.example.anonymization.api.enums.SensitiveDataType.BANK_CARD)
        private String bankCard;
        @com.example.anonymization.api.annotation.SensitiveField(
            com.example.anonymization.api.enums.SensitiveDataType.PASSWORD)
        private String password;

        public TestPaymentRequest(String name, String phone,
                                   String bankCard, String password) {
            this.name = name;
            this.phone = phone;
            this.bankCard = bankCard;
            this.password = password;
        }
    }
}