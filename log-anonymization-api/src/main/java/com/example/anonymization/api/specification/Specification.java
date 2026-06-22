package com.example.anonymization.api.specification;

/**
 * 规约模式（Specification Pattern）通用接口 —— 用于以可组合的方式表达业务规则。
 *
 * <p>使用场景：在脱敏领域用于规则作用域组合
 * （{@link RuleSpecification#isSatisfiedBy}）；同时也是一个通用的领域驱动设计工具，
 * 业务方可基于此接口实现任意谓词组合。
 *
 * <p>参考：Eric Evans《领域驱动设计》第 9 章。
 *
 * @param <T> 被规约判定的对象类型
 * @author log-anonymization
 */
public interface Specification<T> {
    /**
     * 判断候选对象是否满足本规约。
     *
     * @param candidate 候选对象
     * @return true 表示满足
     */
    boolean isSatisfiedBy(T candidate);

    /**
     * 与另一规约组合（AND 语义）。
     *
     * <p>组合后的规约仅在两个子规约同时满足时返回 true。
     *
     * @param other 另一规约
     * @return 组合后的新规约
     */
    default Specification<T> and(Specification<T> other) {
        return candidate -> this.isSatisfiedBy(candidate) && other.isSatisfiedBy(candidate);
    }

    /**
     * 与另一规约组合（OR 语义）。
     *
     * @param other 另一规约
     * @return 组合后的新规约
     */
    default Specification<T> or(Specification<T> other) {
        return candidate -> this.isSatisfiedBy(candidate) || other.isSatisfiedBy(candidate);
    }

    /**
     * 取反（NOT 语义）。
     *
     * @return 取反后的新规约
     */
    default Specification<T> not() {
        return candidate -> !this.isSatisfiedBy(candidate);
    }
}