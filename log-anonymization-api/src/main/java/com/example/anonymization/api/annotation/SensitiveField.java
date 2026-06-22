package com.example.anonymization.api.annotation;

import com.example.anonymization.api.enums.SensitiveDataType;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 敏感字段标注注解 —— 用于在业务对象上声明某个字段属于特定敏感数据类型。
 *
 * <p>设计目的：在"日志产生端预脱敏"场景下，业务代码可使用 {@code SecureLogger} 等工具
 * 反射读取对象字段上的 {@code @SensitiveField} 注解，从而在写入日志前对字段值执行
 * 与敏感类型匹配的脱敏算法，避免明文落盘。
 *
 * <p>使用场景：
 * <ul>
 *   <li>DTO / 领域对象的字段上，声明其敏感类型（例如银行卡号、身份证号）</li>
 *   <li>结合 {@link com.example.anonymization.api.spi.SensitiveDataDetector} 实现自定义反射扫描器</li>
 * </ul>
 *
 * <p>注意：本注解仅作为元数据标记，真正执行脱敏仍由 core 模块的检测器/脱敏器完成。
 *
 * @author log-anonymization
 * @since 1.0.0
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface SensitiveField {
    /**
     * 指定字段对应的敏感数据类型。
     *
     * @return 敏感数据类型枚举值，不可为 null
     */
    SensitiveDataType value();
}