package com.example.anonymization.core.infrastructure.masker;

import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.model.MaskerConfig;

/**
 * 泛化型打码器（Generalize Masker）。
 *
 * <p>属于基础设施层（infrastructure/masker），将原始值泛化为一个"区间/桶"或"保留前 N 段"的形式，
 * 适用于需要在脱敏的同时保留一定的统计意义（如 IP 归属地、金额分桶）。
 *
 * <p>支持两种泛化模式（按配置自动选择）：
 * <ul>
 *   <li>IP 泛化：{@code ipSegmentsToKeep > 0} 时按 {@code 192.*.*.*} 形式保留前 N 段；</li>
 *   <li>金额分桶：{@code amountBuckets} 非空时按给定分桶返回 {@code <N} 或 {@code >N}。</li>
 * </ul>
 *
 * <p>注意：泛化结果仍可能存在一定信息泄漏（如 IP 前 16 位可定位到市级），
 * 请根据合规要求评估是否使用 {@link DiscardMasker} / {@link FullMaskMasker}。
 *
 * <p>不可逆（{@code isReversible = false}）。
 *
 * @author java-architect
 * @since 1.0.0
 */
public class GeneralizeMasker extends AbstractMasker {

    /**
     * 实际打码逻辑：根据配置自动路由到 IP 泛化或金额分桶。
     *
     * @param original 原始字符串
     * @param config   打码配置
     * @return 泛化后的字符串；未匹配任何模式时返回 {@code ***GENERALIZED***}
     */
    @Override
    protected String doMask(String original, MaskerConfig config) {
        if (config.getIpSegmentsToKeep() > 0) {
            return generalizeIp(original, config.getIpSegmentsToKeep());
        }
        if (!config.getAmountBuckets().isEmpty()) {
            return generalizeAmount(original, config.getAmountBuckets());
        }
        return "***GENERALIZED***";
    }

    /**
     * IP 泛化：按 {@code .} 拆分，保留前 {@code segmentsToKeep} 段，后续段替换为 {@code *}。
     *
     * @param ip              原始 IPv4 字符串
     * @param segmentsToKeep  保留段数（{@code 1~3}，{@code 4} 等价于不脱敏）
     * @return 泛化后的 IP；非 4 段格式直接返回 {@code ***.***.***.***}
     */
    private String generalizeIp(String ip, int segmentsToKeep) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return "***.***.***.***";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            if (i > 0) sb.append(".");
            sb.append(i < segmentsToKeep ? parts[i] : "*");
        }
        return sb.toString();
    }

    /**
     * 金额分桶：将 {@code value} 中非数字字符（货币符号、千分位逗号等）剔除后转为 {@code double}，
     * 在 {@code buckets} 中找到第一个大于该金额的桶并返回 {@code <N}；若大于所有桶则返回 {@code >最大桶}。
     *
     * @param value   原始金额字符串（可含 {@code ¥}、{@code ,} 等）
     * @param buckets 分桶阈值列表（升序）
     * @return 分桶字符串；解析失败返回 {@code ***AMOUNT***}
     */
    private String generalizeAmount(String value, java.util.List<Double> buckets) {
        try {
            double amount = Double.parseDouble(value.replaceAll("[^0-9.]", ""));
            for (Double bucket : buckets) {
                if (amount < bucket.doubleValue()) {
                    return "<" + bucket.intValue();
                }
            }
            return ">" + buckets.get(buckets.size() - 1).intValue();
        } catch (NumberFormatException e) {
            return "***AMOUNT***";
        }
    }

    /**
     * 当前打码器类型。
     *
     * @return {@link MaskerType#GENERALIZE}
     */
    @Override
    public MaskerType getMaskerType() { return MaskerType.GENERALIZE; }

    /**
     * 是否可逆。
     *
     * @return {@code false}
     */
    @Override
    public boolean isReversible() { return false; }
}