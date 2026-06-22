package com.example.anonymization.core.infrastructure.filter;

import com.google.re2j.Pattern;
import com.google.re2j.PatternSyntaxException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 默认白名单模式常量 —— 预编译的排除模式集合，用于过滤掉常见的非敏感数据匹配。
 *
 * <p>设计目标：在检测阶段之前，将 UUID、时间戳、流水号、版本号等常见格式
 * 从检测结果中排除，避免误识别（如 13 位时间戳被误判为手机号）。
 *
 * <p>包含 4 种预编译模式：
 * <ol>
 *   <li>{@link #UUID_PATTERN} — UUID 格式（如 {@code 550e8400-e29b-41d4-a716-446655440000}）</li>
 *   <li>{@link #TIMESTAMP_PATTERN} — 毫秒级时间戳（如 {@code 1700000000000}）</li>
 *   <li>{@link #SERIAL_NUMBER_PATTERN} — 标准流水号（如 {@code TX20240622150000123456}）</li>
 *   <li>{@link #VERSION_PATTERN} — 版本号（如 {@code 1.0.0}、{@code v2.3.1}）</li>
 * </ol>
 *
 * <p>线程安全：所有字段均为 {@code static final} 不可变引用，可安全并发访问。
 *
 * @author log-anonymization
 */
public final class DefaultWhitelistPatterns {

    /**
     * UUID 格式：8-4-4-4-12 十六进制字符。
     *
     * <p>示例：{@code 550e8400-e29b-41d4-a716-446655440000}
     */
    public static final Pattern UUID_PATTERN = Pattern.compile(
        "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        Pattern.CASE_INSENSITIVE
    );

    /**
     * 毫秒级时间戳：13 位数字，首位 1，第二位 3-9（覆盖 1970 ~ 2286 年）。
     *
     * <p>示例：{@code 1700000000000}
     */
    public static final Pattern TIMESTAMP_PATTERN = Pattern.compile(
        "1[3-9]\\d{11}"
    );

    /**
     * 标准流水号：2-6 位大写字母前缀 + 14-20 位数字。
     *
     * <p>示例：{@code TX20240622150000123456}、{@code ORD20240622150012345}
     */
    public static final Pattern SERIAL_NUMBER_PATTERN = Pattern.compile(
        "[A-Z]{2,6}\\d{14,20}"
    );

    /**
     * 版本号：可选 {@code v} 前缀 + 至少 2 段数字（{@code x.y} 或 {@code x.y.z}）。
     *
     * <p>示例：{@code 1.0}、{@code v2.3.1}、{@code 10.20.30}
     */
    public static final Pattern VERSION_PATTERN = Pattern.compile(
        "v?\\d+\\.\\d+(\\.\\d+)*"
    );

    /**
     * 默认白名单模式列表（不可变）。
     *
     * <p>用于 {@link WhitelistFilter#WhitelistFilter()} 构造时自动注入。
     */
    public static final List<Pattern> DEFAULT_PATTERNS;

    static {
        List<Pattern> patterns = new ArrayList<>();
        patterns.add(UUID_PATTERN);
        patterns.add(TIMESTAMP_PATTERN);
        patterns.add(SERIAL_NUMBER_PATTERN);
        patterns.add(VERSION_PATTERN);
        DEFAULT_PATTERNS = Collections.unmodifiableList(patterns);
    }

    private DefaultWhitelistPatterns() {}
}