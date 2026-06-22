package com.example.anonymization.api.enums;

/**
 * 风险等级枚举 —— 用于给敏感数据类型/规则打标签，决定采样与告警策略。
 *
 * <p>使用场景：
 * <ul>
 *   <li>{@link com.example.anonymization.core.infrastructure.sampling.SamplingController#shouldMask(RiskLevel)}
 *       —— CRITICAL/HIGH 等级的数据强制全量脱敏，不走采样</li>
 *   <li>SIEM 集成时按风险等级路由告警（CRITICAL 直接通知安全团队）</li>
 * </ul>
 *
 * @author log-anonymization
 */
public enum RiskLevel {
    /** 严重（如 CVV、磁道数据、密码明文） —— 一旦检测立即触发最高级别告警 */
    CRITICAL,
    /** 高风险（如银行卡号、身份证号） —— 强制脱敏、不采样 */
    HIGH,
    /** 中风险（如手机号、邮箱） —— 常规脱敏 */
    MEDIUM,
    /** 低风险（如 IP 地址、交易金额） —— 可配置采样 */
    LOW
}