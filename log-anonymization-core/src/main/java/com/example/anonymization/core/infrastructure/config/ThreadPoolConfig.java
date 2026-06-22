package com.example.anonymization.core.infrastructure.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 独立线程池配置类 —— 集中管理 SDK 内部所有线程池 Bean。
 *
 * <p>属于基础设施层（infrastructure/config），通过 Spring {@code @Configuration} 注解
 * 被 {@link com.example.anonymization.starter.LogAnonymizationAutoConfiguration}
 * 通过 {@code @Import} 引入。
 *
 * <p>设计原则：
 * <ul>
 *   <li><b>线程隔离</b>：审计线程池与业务线程池物理隔离，避免审计 I/O 阻塞影响主路径</li>
 *   <li><b>有界队列</b>：所有线程池使用有界队列，防止 OOM；溢出时按策略降级</li>
 *   <li><b>守护线程</b>：所有线程设置为 daemon，不阻止 JVM 退出</li>
 *   <li><b>可配置</b>：核心参数通过 {@code application.yml} 动态调整，无需改代码</li>
 *   <li><b>优雅关闭</b>：实现 {@link AutoCloseable}，Spring 容器关闭时自动 shutdown</li>
 * </ul>
 *
 * <p>配置示例：
 * <pre>
 *   log-anonymization:
 *     thread-pool:
 *       audit:
 *         core-size: 1
 *         max-size: 2
 *         queue-capacity: 5000
 *         keep-alive-seconds: 60
 *         thread-name-prefix: "audit-"
 * </pre>
 *
 * <p>性能考量（5000 万用户量级）：
 * <ul>
 *   <li>审计线程池核心 1 线程 + 队列 5000，足够应对 ~5000 QPS 的审计写入</li>
 *   <li>队列满时 {@code DiscardOldestPolicy} 丢弃最旧审计记录（保最新），优先保障主路径</li>
 *   <li>Disruptor RingBuffer（65536）作为一级缓冲，本线程池仅作为 Exporter 异步 I/O 的二级执行器</li>
 * </ul>
 *
 * @author java-architect
 * @since 1.0.0
 */
@Configuration
public class ThreadPoolConfig {

    private static final Logger log = LoggerFactory.getLogger(ThreadPoolConfig.class);

    /**
     * 审计异步执行器 —— 用于审计 Exporter 的异步 I/O 操作（写文件、发 Kafka 等）。
     *
     * <p>设计参数（执行计划 §11.5）：
     * <ul>
     *   <li>核心线程：1（单线程保证审计顺序性）</li>
     *   <li>最大线程：2（突发流量时扩容）</li>
     *   <li>队列容量：5000（约 1 秒的审计缓冲）</li>
     *   <li>拒绝策略：{@link ThreadPoolExecutor.DiscardOldestPolicy}（丢弃最旧，保最新审计）</li>
     *   <li>线程命名：{@code audit-0}, {@code audit-1}（便于线程 dump 排查）</li>
     * </ul>
     *
     * @param coreSize          核心线程数
     * @param maxSize           最大线程数
     * @param queueCapacity     队列容量
     * @param keepAliveSeconds  空闲线程存活秒数
     * @param threadNamePrefix  线程名前缀
     * @return 审计执行器（Spring 容器关闭时自动 shutdown）
     */
    @Bean("auditExecutor")
    @ConditionalOnMissingBean(name = "auditExecutor")
    public ExecutorService auditExecutor(
            @Value("${log-anonymization.thread-pool.audit.core-size:1}") int coreSize,
            @Value("${log-anonymization.thread-pool.audit.max-size:2}") int maxSize,
            @Value("${log-anonymization.thread-pool.audit.queue-capacity:5000}") int queueCapacity,
            @Value("${log-anonymization.thread-pool.audit.keep-alive-seconds:60}") int keepAliveSeconds,
            @Value("${log-anonymization.thread-pool.audit.thread-name-prefix:audit-}") String threadNamePrefix) {

        ThreadFactory threadFactory = createDaemonThreadFactory(threadNamePrefix);
        ExecutorService executor = new ThreadPoolExecutor(
            coreSize,
            maxSize,
            keepAliveSeconds,
            TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(queueCapacity),
            threadFactory,
            new ThreadPoolExecutor.DiscardOldestPolicy()
        );

        log.info("审计线程池已初始化: core={}, max={}, queue={}, prefix={}",
            coreSize, maxSize, queueCapacity, threadNamePrefix);

        return new AutoCloseableExecutorService(executor);
    }

    /**
     * 创建守护线程工厂 —— 统一线程命名规范与 daemon 属性。
     *
     * @param namePrefix 线程名前缀
     * @return 线程工厂
     */
    private static ThreadFactory createDaemonThreadFactory(String namePrefix) {
        AtomicInteger counter = new AtomicInteger(0);
        return runnable -> {
            Thread thread = new Thread(runnable, namePrefix + counter.getAndIncrement());
            thread.setDaemon(true);
            thread.setPriority(Thread.NORM_PRIORITY);
            return thread;
        };
    }

    /**
     * 可自动关闭的 ExecutorService 包装器 —— Spring 容器关闭时触发优雅 shutdown。
     *
     * <p>关闭策略：
     * <ol>
     *   <li>{@code shutdown()}：停止接收新任务</li>
     *   <li>等待 5 秒让已提交任务执行完</li>
     *   <li>超时后 {@code shutdownNow()}：强制中断剩余任务</li>
     * </ol>
     */
    public static final class AutoCloseableExecutorService
            implements ExecutorService, AutoCloseable {

        private final ExecutorService delegate;

        AutoCloseableExecutorService(ExecutorService delegate) {
            this.delegate = delegate;
        }

        @Override
        public void close() {
            delegate.shutdown();
            try {
                if (!delegate.awaitTermination(5, TimeUnit.SECONDS)) {
                    log.warn("审计线程池 5 秒内未完成关闭，执行强制 shutdown");
                    delegate.shutdownNow();
                }
            } catch (InterruptedException e) {
                delegate.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }

        @Override
        public void shutdown() { delegate.shutdown(); }

        @Override
        public java.util.List<Runnable> shutdownNow() { return delegate.shutdownNow(); }

        @Override
        public boolean isShutdown() { return delegate.isShutdown(); }

        @Override
        public boolean isTerminated() { return delegate.isTerminated(); }

        @Override
        public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
            return delegate.awaitTermination(timeout, unit);
        }

        @Override
        public <T> java.util.concurrent.Future<T> submit(java.util.concurrent.Callable<T> task) {
            return delegate.submit(task);
        }

        @Override
        public <T> java.util.concurrent.Future<T> submit(Runnable task, T result) {
            return delegate.submit(task, result);
        }

        @Override
        public java.util.concurrent.Future<?> submit(Runnable task) {
            return delegate.submit(task);
        }

        @Override
        public <T> java.util.List<java.util.concurrent.Future<T>> invokeAll(
                java.util.Collection<? extends java.util.concurrent.Callable<T>> tasks)
                throws InterruptedException {
            return delegate.invokeAll(tasks);
        }

        @Override
        public <T> java.util.List<java.util.concurrent.Future<T>> invokeAll(
                java.util.Collection<? extends java.util.concurrent.Callable<T>> tasks,
                long timeout, TimeUnit unit) throws InterruptedException {
            return delegate.invokeAll(tasks, timeout, unit);
        }

        @Override
        public <T> T invokeAny(java.util.Collection<? extends java.util.concurrent.Callable<T>> tasks)
                throws InterruptedException, java.util.concurrent.ExecutionException {
            return delegate.invokeAny(tasks);
        }

        @Override
        public <T> T invokeAny(java.util.Collection<? extends java.util.concurrent.Callable<T>> tasks,
                               long timeout, TimeUnit unit)
                throws InterruptedException, java.util.concurrent.ExecutionException, java.util.concurrent.TimeoutException {
            return delegate.invokeAny(tasks, timeout, unit);
        }

        @Override
        public void execute(Runnable command) { delegate.execute(command); }
    }
}