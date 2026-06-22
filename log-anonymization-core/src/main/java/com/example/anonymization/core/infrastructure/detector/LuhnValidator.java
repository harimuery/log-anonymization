package com.example.anonymization.core.infrastructure.detector;

/**
 * Luhn 算法校验器（银行卡号校验）。
 *
 * <p>属于基础设施层（infrastructure/detector），是一个无状态的工具类，
 * 实现 ISO/IEC 7812 中规定的银行卡号校验位算法（俗称"模 10 算法"）。
 *
 * <p>算法要点：
 * <ul>
 *   <li>从右向左遍历数字；</li>
 *   <li>奇数位（从右数第 1、3、5...位）保持原值；</li>
 *   <li>偶数位翻倍：若结果 ≥ 10，则减去 9（即"两位数各位数字之和"）；</li>
 *   <li>所有位求和后，若能被子 10 整除则为合法卡号。</li>
 * </ul>
 *
 * <p>使用场景：作为 {@link Re2jBankCardDetector} 的二次校验钩子，
 * 大幅降低"16~19 位连续数字"的误报率（例如订单号、流水号都不会通过 Luhn）。
 *
 * <p>线程安全：纯函数实现，无共享状态，可并发调用。
 *
 * @author java-architect
 * @since 1.0.0
 */
public final class LuhnValidator {

    /**
     * 私有构造器，工具类不允许实例化。
     */
    private LuhnValidator() {}

    /**
     * 判断给定字符串是否符合 Luhn 算法（即是否为合法的银行卡号）。
     *
     * <p>前置过滤：
     * <ul>
     *   <li>{@code null} 直接返回 {@code false}；</li>
     *   <li>长度小于 12（VISA Electron 等最小卡种）或大于 19（UnionPay 19 位上限）直接返回 {@code false}；</li>
     *   <li>包含非数字字符直接返回 {@code false}。</li>
     * </ul>
     *
     * @param number 待校验的字符串（应为纯数字，长度 12~19）
     * @return {@code true} 表示通过 Luhn 校验（即"可能是合法卡号"）；{@code false} 表示一定不合法
     */
    public static boolean isValid(String number) {
        if (number == null || number.length() < 12 || number.length() > 19) {
            return false;
        }
        int sum = 0;
        boolean alternate = false;
        for (int i = number.length() - 1; i >= 0; i--) {
            int digit = number.charAt(i) - '0';
            if (digit < 0 || digit > 9) return false;
            if (alternate) {
                digit *= 2;
                if (digit > 9) digit -= 9;
            }
            sum += digit;
            alternate = !alternate;
        }
        return sum % 10 == 0;
    }
}