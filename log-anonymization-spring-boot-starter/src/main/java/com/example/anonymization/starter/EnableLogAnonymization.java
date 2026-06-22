package com.example.anonymization.starter;

import org.springframework.context.annotation.Import;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 启用日志脱敏注解（Enable Log Anonymization）。
 *
 * <p>属于 spring-boot-starter 模块，提供"显式启用 SDK"的注解入口，
 * 业务方在 {@code @SpringBootApplication} 类上标注后即可加载全部脱敏相关 Bean：
 * <pre>
 *   &#64;SpringBootApplication
 *   &#64;EnableLogAnonymization
 *   public class PaymentApplication { ... }
 * </pre>
 *
 * <p>实现机制：通过 {@link Import} 引入 {@link LogAnonymizationAutoConfiguration}，
 * 触发全部 {@code @Bean} 装配。设计为 {@code @Target(TYPE)} + {@code RUNTIME}，
 * 仅允许标注在类上，且能被 Spring 反射读取。
 *
 * <p>与 {@code log-anonymization.enabled=true} 配置属性的关系：
 * <ul>
 *   <li>本注解相当于"强制启用"，即便配置关闭也会装配 Bean；</li>
 *   <li>配置属性 {@code log-anonymization.enabled=false} 则会跳过所有 Bean 注册（即便使用本注解）。</li>
 * </ul>
 *
 * @author java-architect
 * @since 1.0.0
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import(LogAnonymizationAutoConfiguration.class)
public @interface EnableLogAnonymization {
}