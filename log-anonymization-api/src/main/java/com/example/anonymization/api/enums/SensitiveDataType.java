package com.example.anonymization.api.enums;

/**
 * 敏感数据类型枚举 —— 全量定义支付/金融场景下需要脱敏处理的数据分类。
 *
 * <p>分类覆盖：
 * <ul>
 *   <li><b>金融数据</b>：{@link #BANK_CARD}、{@link #CVV}、{@link #PAYMENT_TOKEN}、{@link #TRANSACTION_AMOUNT}</li>
 *   <li><b>个人身份信息（PII）</b>：{@link #ID_CARD}、{@link #PHONE}、{@link #EMAIL}、{@link #NAME}</li>
 *   <li><b>认证凭证</b>：{@link #PASSWORD}、{@link #API_KEY}</li>
 *   <li><b>系统数据</b>：{@link #IP_ADDRESS}</li>
 *   <li><b>扩展</b>：{@link #CUSTOM}（用户通过自定义 SPI 注入新类型）</li>
 * </ul>
 *
 * <p>使用场景：作为 {@link com.example.anonymization.api.model.MaskingRule}、
 * {@link com.example.anonymization.api.model.DetectionResult} 的关键字段，
 * 决定使用哪个检测器与哪种脱敏算法。
 *
 * @author log-anonymization
 */
public enum SensitiveDataType {
    /** 银行卡号（一般需配合 Luhn 校验位二次确认，避免误杀长数字串） */
    BANK_CARD,
    /** 身份证号（18 位，含校验位算法） */
    ID_CARD,
    /** 手机号（中国大陆 11 位手机号） */
    PHONE,
    /** 邮箱地址 */
    EMAIL,
    /** 自然人姓名 */
    NAME,
    /** 登录/支付密码 —— PCI DSS 严格要求不可留存 */
    PASSWORD,
    /** 信用卡安全码（PCI DSS 严禁留存 CVV，明文记录即视为严重违规） */
    CVV,
    /** 支付令牌（令牌化后的支付凭证） */
    PAYMENT_TOKEN,
    /** API Key / Secret 等接口凭证 */
    API_KEY,
    /** IP 地址 */
    IP_ADDRESS,
    /** 交易金额（可配置保留/泛化为区间） */
    TRANSACTION_AMOUNT,
    /** 用户自定义类型（通过 SPI 扩展点注入） */
    CUSTOM
}