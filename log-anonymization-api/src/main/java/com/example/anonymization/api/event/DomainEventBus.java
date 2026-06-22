package com.example.anonymization.api.event;

import java.util.function.Consumer;

/**
 * 领域事件总线接口 —— 抽象发布/订阅模型，解耦事件源与消费者。
 *
 * <p>使用场景：作为端口（Port），被 core 模块的
 * {@link com.example.anonymization.core.infrastructure.event.DefaultDomainEventBus} 实现，
 * 也可由业务方替换为基于 Kafka/RocketMQ 的实现以做跨进程事件分发。
 *
 * @author log-anonymization
 */
public interface DomainEventBus {
    /**
     * 发布事件：将事件异步/同步分发至所有已订阅该事件类型的处理器。
     *
     * <p>实现需保证：单个处理器抛出异常不影响其它处理器分发（隔离性），
     * 且发布动作非阻塞或具备超时控制，避免影响业务主链路。
     *
     * @param event 待发布的事件实例，不可为 null
     */
    void publish(DomainEvent event);

    /**
     * 订阅事件：将处理器注册到指定事件类型上，后续该类型事件发布时会被调用。
     *
     * <p>订阅关系在实现内部通常以 {@code Map<Class<?>, List<Consumer<?>>>} 存储，
     * 调用方需自行保证处理器的线程安全性（多线程并发调用）。
     *
     * @param <T>         具体事件类型
     * @param eventType   事件 Class 对象（如 {@code MaskingCompletedEvent.class}）
     * @param handler     事件处理器，类型为 {@link java.util.function.Consumer}，接收事件实例
     */
    <T extends DomainEvent> void subscribe(Class<T> eventType, Consumer<T> handler);
}