package com.example.anonymization.core.infrastructure.event;

import com.example.anonymization.api.event.DomainEvent;
import com.example.anonymization.api.event.DomainEventBus;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * 内存版领域事件总线（默认实现）。
 *
 * <p>属于基础设施层（infrastructure/event），是 {@link DomainEventBus} 接口的进程内实现，
 * 提供同 JVM 内的发布/订阅能力。核心特性：
 * <ul>
 *   <li>以事件类型为 Key，按 {@link CopyOnWriteArrayList} 存储订阅者；</li>
 *   <li>发布时同步调用所有订阅者，订阅者异常被独立捕获并输出到 {@code System.err}；</li>
 *   <li>适用于单机/单进程场景；跨 JVM 场景请使用 RocketMQ/Kafka 实现。</li>
 * </ul>
 *
 * <p>线程安全：
 * <ul>
 *   <li>{@link ConcurrentHashMap} 保证注册与发布互不干扰；</li>
 *   <li>{@link CopyOnWriteArrayList} 避免遍历时增改发生 {@code ConcurrentModificationException}。</li>
 * </ul>
 *
 * <p>典型使用：{@link com.example.anonymization.core.application.pipeline.AuditStage} 订阅 {@link com.example.anonymization.api.event.MaskingCompletedEvent}，
 * 异步落审计表。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class DefaultDomainEventBus implements DomainEventBus {

    /**
     * 事件类型 → 订阅者列表的映射。
     * Key 为具体事件 Class（如 {@code MaskingCompletedEvent.class}），
     * Value 为该事件的所有订阅回调（{@link Consumer}）。
     */
    private final Map<Class<? extends DomainEvent>, List<Consumer<? extends DomainEvent>>> subscribers =
        new ConcurrentHashMap<>();

    /**
     * 发布领域事件：查找该事件类型的所有订阅者，依次同步调用。
     *
     * <p>异常隔离：单个订阅者抛出异常不会影响后续订阅者；
     * 异常信息写入 {@code System.err}（生产环境建议接入 SLF4J/BusinessLog）。
     *
     * @param event 待发布的领域事件，不可为 {@code null}；
     *              若无任何订阅者则静默返回（不报错）
     */
    @Override
    public void publish(DomainEvent event) {
        List<Consumer<? extends DomainEvent>> handlers = subscribers.get(event.getClass());
        if (handlers != null) {
            for (Consumer<? extends DomainEvent> handler : handlers) {
                try {
                    @SuppressWarnings("unchecked")
                    Consumer<DomainEvent> typedHandler = (Consumer<DomainEvent>) handler;
                    typedHandler.accept(event);
                } catch (Exception e) {
                    System.err.println("[DomainEventBus] Error handling event: " + e.getMessage());
                }
            }
        }
    }

    /**
     * 订阅指定类型的事件。
     *
     * <p>同一事件类型可被多次订阅（按注册顺序链式调用），
     * {@link CopyOnWriteArrayList} 保证遍历期间可继续注册新订阅者。
     *
     * @param eventType 事件类型 Class，不可为 {@code null}
     * @param handler   事件处理回调，不可为 {@code null}；建议实现为幂等
     * @param <T>       事件泛型
     */
    @Override
    public <T extends DomainEvent> void subscribe(Class<T> eventType, Consumer<T> handler) {
        subscribers.computeIfAbsent(eventType, k -> new CopyOnWriteArrayList<>())
            .add(handler);
    }
}