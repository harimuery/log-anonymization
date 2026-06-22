package com.example.anonymization.starter;

import org.jasypt.encryption.StringEncryptor;
import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.iv.RandomIvGenerator;
import org.jasypt.salt.RandomSaltGenerator;

import java.util.Objects;

/**
 * Jasypt 配置加密集成 —— 为日志脱敏 SDK 的敏感配置项（如盐值）提供加密存储能力。
 *
 * <p>属于 spring-boot-starter 模块，是执行计划 §13.1 中定义的安全设计落地。
 * 核心目标：确保 {@code log-anonymization.secret.salt} 等敏感配置项
 * 在配置文件中以密文形式存储（{@code ENC(...)} 格式），避免明文泄露。
 *
 * <p>使用方式：
 * <ol>
 *   <li>在 {@code application.yml} 中使用 {@code ENC(...)} 包裹敏感值：
 *       <pre>
 *       log-anonymization:
 *         secret:
 *           salt: ENC(密文字符串)
 *       </pre>
 *   </li>
 *   <li>通过环境变量 {@code JASYPT_ENCRYPTOR_PASSWORD} 注入主密钥；</li>
 *   <li>SDK 启动时自动解密 {@code ENC(...)} 格式的配置值。</li>
 * </ol>
 *
 * <p>密钥管理策略（v1）：
 * <ul>
 *   <li>主密钥通过环境变量 {@code JASYPT_ENCRYPTOR_PASSWORD} 注入，不硬编码；</li>
 *   <li>加密算法：{@code PBEWithHMACSHA512AndAES_256}（NIST 推荐）；</li>
 *   <li>IV 生成：{@link RandomIvGenerator}（每次加密产生不同密文）；</li>
 *   <li>Salt 生成：{@link RandomSaltGenerator}（随机盐，防彩虹表）；</li>
 *   <li>连接池：2 个并发加密器实例（满足多线程解密需求）。</li>
 * </ul>
 *
 * <p>安全注意事项：
 * <ul>
 *   <li>生产环境务必设置 {@code JASYPT_ENCRYPTOR_PASSWORD} 环境变量；</li>
 *   <li>密钥轮换需重新加密所有 {@code ENC(...)} 值并重启服务；</li>
 *   <li>v2 将升级为 KMS 集成（阿里云/AWS/Vault），支持自动轮换。</li>
 * </ul>
 *
 * @author java-architect
 * @since 1.0.0
 */
public class JasyptConfig {

    /**
     * 默认加密算法 —— PBE + HMAC-SHA512 + AES-256-CBC。
     *
     * <p>选型理由：
     * <ul>
     *   <li>AES-256 对称加密，NIST SP 800-38A 推荐的分组密码模式；</li>
     *   <li>HMAC-SHA512 作为 PRF（伪随机函数），提供密钥派生和完整性校验；</li>
     *   <li>JCE 无限强度策略文件在 JDK 17+ 已默认启用，无需额外配置。</li>
     * </ul>
     */
    static final String DEFAULT_ALGORITHM = "PBEWithHMACSHA512AndAES_256";

    /**
     * 默认连接池大小 —— 2 个加密器实例，满足日志脱敏场景下的并发解密需求。
     *
     * <p>日志脱敏场景中，Jasypt 仅在启动时解密配置值（非热路径），
     * 2 个实例足够应对 Spring 上下文刷新时的并发访问。
     */
    static final int DEFAULT_POOL_SIZE = 2;

    /**
     * 创建默认的 Jasypt {@link StringEncryptor} Bean。
     *
     * <p>此方法由 {@link LogAnonymizationAutoConfiguration} 中通过
     * {@code @Bean("jasyptStringEncryptor")} 注册，覆盖 Jasypt Spring Boot Starter
     * 的默认加密器，使用更强的算法和随机 IV/Salt。
     *
     * <p>主密钥来源优先级：
     * <ol>
     *   <li>环境变量 {@code JASYPT_ENCRYPTOR_PASSWORD}</li>
     *   <li>系统属性 {@code jasypt.encryptor.password}</li>
     *   <li>配置文件中的 {@code jasypt.encryptor.password}（不推荐）</li>
     * </ol>
     *
     * @param password 主密钥，从环境变量/系统属性获取；为 null 时使用空串（仅开发环境）
     * @return 配置好的 {@link StringEncryptor} 实例
     */
    public static StringEncryptor createEncryptor(String password) {
        PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
        encryptor.setPoolSize(DEFAULT_POOL_SIZE);
        encryptor.setPassword(Objects.requireNonNullElse(password, ""));
        encryptor.setAlgorithm(DEFAULT_ALGORITHM);
        encryptor.setIvGenerator(new RandomIvGenerator());
        encryptor.setSaltGenerator(new RandomSaltGenerator());
        return encryptor;
    }

    private JasyptConfig() {}
}