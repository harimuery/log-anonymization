package com.example.anonymization.core.infrastructure.masker;

import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.model.MaskerConfig;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * 哈希型打码器（Hash Masker）。
 *
 * <p>属于基础设施层（infrastructure/masker），使用加密哈希算法（如 SHA-256）将原始值散列为定长十六进制字符串。
 * 适用场景：
 * <ul>
 *   <li>用户 ID、设备指纹 —— 需要"跨日志关联但不可还原"；</li>
 *   <li>业务上需要"幂等脱敏"（同一原文在不同次调用中得到相同哈希），便于 ELK/ClickHouse 按哈希聚合统计。</li>
 * </ul>
 *
 * <p>安全性：单纯哈希可被彩虹表攻击，必须叠加 {@code salt} 才能用于生产。
 * salt 在 Spring 装配阶段通过 {@link com.example.anonymization.starter.LogAnonymizationProperties.SecretConfig#getSalt()} 注入。
 *
 * <p>不可逆（{@code isReversible = false}）。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class HashMasker extends AbstractMasker {

    /**
     * 全局盐值（与原始值拼接后再哈希）。
     * 通过构造器注入，避免硬编码在源码中。
     */
    private final String salt;

    /**
     * 构造哈希打码器。
     *
     * @param salt 盐值字符串；不可为 {@code null}（空串也可，但安全性大幅下降）
     */
    public HashMasker(String salt) {
        this.salt = salt;
    }

    /**
     * 实际打码逻辑：{@code sha256(salt + original).hex()}。
     *
     * @param original 原始字符串
     * @param config   打码配置，使用 {@link MaskerConfig#getAlgorithm()}（默认 {@code SHA-256}）
     * @return 十六进制小写哈希字符串；算法不支持时降级返回 {@code ***HASH_ERROR***}
     */
    @Override
    protected String doMask(String original, MaskerConfig config) {
        try {
            String algorithm = config.getAlgorithm() != null ? config.getAlgorithm() : "SHA-256";
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            String salted = salt + original;
            byte[] hashBytes = digest.digest(salted.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            return "***HASH_ERROR***";
        }
    }

    /**
     * 当前打码器类型。
     *
     * @return {@link MaskerType#HASH}
     */
    @Override
    public MaskerType getMaskerType() { return MaskerType.HASH; }

    /**
     * 是否可逆。
     *
     * @return {@code false}
     */
    @Override
    public boolean isReversible() { return false; }
}