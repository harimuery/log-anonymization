package com.example.anonymization.api.enums;

/**
 * 脱敏动作枚举 —— 记录单条日志被处理后的实际动作结果。
 *
 * <p>使用场景：{@link com.example.anonymization.api.model.MaskingResult} 通过此枚举
 * 描述本次脱敏行为（用于审计、上报监控、规则命中分析）。
 *
 * @author log-anonymization
 */
public enum MaskingAction {
    /** 已执行遮盖/部分遮盖（如手机号 138****1234） */
    MASKED,
    /** 已执行哈希（如 SHA-256 + 盐，常用于密码） */
    HASHED,
    /** 已丢弃（值被替换为空字符串，如 CVV） */
    DISCARDED,
    /** 降级占位（脱敏组件异常或超时，输出降级占位符避免泄露明文） */
    DEGRADED,
    /** 脱敏失败（异常未恢复，最终输出原值，由调用方决定是否上报） */
    FAILED,
    /** 跳过（消息中无敏感数据，未做任何改动） */
    SKIPPED
}