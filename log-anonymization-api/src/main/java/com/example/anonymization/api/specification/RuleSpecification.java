package com.example.anonymization.api.specification;

import com.example.anonymization.api.model.LogContext;
import com.example.anonymization.api.model.MaskingScope;

/**
 * 规则作用域规约 —— Specification 模式实现，将 {@link MaskingScope#matches} 封装为可组合的规约对象。
 *
 * <p>使用场景：在需要 AND/OR/NOT 组合多个作用域（如"全局 OR 某包路径"）时，
 * 通过 {@link Specification#and} / {@link Specification#or} 链式构造，避免硬编码复杂 if-else。
 *
 * @author log-anonymization
 */
public class RuleSpecification implements Specification<LogContext> {

    /** 规则作用域委托 */
    private final MaskingScope scope;

    /**
     * 创建基于给定作用域的规约。
     *
     * @param scope 规则作用域，不可为 null
     */
    public RuleSpecification(MaskingScope scope) {
        this.scope = scope;
    }

    /**
     * 判定给定日志上下文是否满足本规约（等价于 {@code scope.matches(context)}）。
     *
     * @param context 日志上下文
     * @return true 表示规则适用
     */
    @Override
    public boolean isSatisfiedBy(LogContext context) {
        return scope.matches(context);
    }
}