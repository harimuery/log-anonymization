package com.example.anonymization.test;

import com.example.anonymization.api.model.MaskingResult;
import org.assertj.core.api.AbstractAssert;

/**
 * {@link MaskingResult} AssertJ 断言工具。
 *
 * <p>属于 test 模块，继承自 AssertJ 的 {@link AbstractAssert}，
 * 提供面向 {@link MaskingResult} 的链式断言 API，使测试代码更具可读性。
 *
 * <p>典型用法：
 * <pre>
 *   MaskingResultAssert.assertThat(result)
 *       .isMasked()
 *       .hasMaskedValue("6222 **** **** 7890")
 *       .isDegraded();  // 失败：不是降级结果
 * </pre>
 *
 * <p>与 {@code assertEquals(expected, actual.getMasked())} 相比的优势：
 * <ul>
 *   <li>断言失败时打印 {@code expected: <X> but was: <Y>} 的友好提示；</li>
 *   <li>链式调用减少模板代码；</li>
 *   <li>语义化方法名（{@code isMasked()} / {@code isDegraded()}）提升测试可读性。</li>
 * </ul>
 *
 * @author java-architect
 * @since 1.0.0
 */
public class MaskingResultAssert extends AbstractAssert<MaskingResultAssert, MaskingResult> {

    /**
     * 构造断言器。
     *
     * @param actual 待断言的 {@link MaskingResult}
     */
    public MaskingResultAssert(MaskingResult actual) {
        super(actual, MaskingResultAssert.class);
    }

    /**
     * 静态工厂方法（与 AssertJ 标准风格保持一致）。
     *
     * @param actual 待断言的 {@link MaskingResult}
     * @return 断言器实例
     */
    public static MaskingResultAssert assertThat(MaskingResult actual) {
        return new MaskingResultAssert(actual);
    }

    /**
     * 断言结果为"已脱敏"（{@code isChanged=true}）。
     *
     * @return 当前断言器（支持链式调用）
     * @throws AssertionError 当结果未变化时抛出
     */
    public MaskingResultAssert isMasked() {
        isNotNull();
        if (!actual.isChanged()) {
            failWithMessage("Expected masking result to be changed but it was not");
        }
        return this;
    }

    /**
     * 断言结果为"未变化"（{@code isChanged=false}）。
     *
     * @return 当前断言器
     * @throws AssertionError 当结果已变化时抛出
     */
    public MaskingResultAssert isUnchanged() {
        isNotNull();
        if (actual.isChanged()) {
            failWithMessage("Expected masking result to be unchanged but it was changed");
        }
        return this;
    }

    /**
     * 断言结果为"降级"（{@code isDegraded=true}，即走了 {@link com.example.anonymization.core.infrastructure.masker.FallbackMasker}）。
     *
     * @return 当前断言器
     * @throws AssertionError 当结果未降级时抛出
     */
    public MaskingResultAssert isDegraded() {
        isNotNull();
        if (!actual.isDegraded()) {
            failWithMessage("Expected masking result to be degraded but it was not");
        }
        return this;
    }

    /**
     * 断言脱敏值等于预期字符串（精确匹配）。
     *
     * @param expected 期望的脱敏字符串
     * @return 当前断言器
     * @throws AssertionError 当实际值不匹配时抛出
     */
    public MaskingResultAssert hasMaskedValue(String expected) {
        isNotNull();
        if (!expected.equals(actual.getMasked())) {
            failWithMessage("Expected masked value to be <%s> but was <%s>", expected, actual.getMasked());
        }
        return this;
    }

    /**
     * 断言脱敏值包含指定子串（模糊匹配）。
     *
     * <p>适用于只需校验"打码是否生效"而不关心具体格式的场景，例如
     * 校验 {@code result.getMasked().contains("****")}。
     *
     * @param expectedSubstring 期望包含的子串
     * @return 当前断言器
     * @throws AssertionError 当实际值不包含子串时抛出
     */
    public MaskingResultAssert containsMaskedValue(String expectedSubstring) {
        isNotNull();
        if (!actual.getMasked().contains(expectedSubstring)) {
            failWithMessage("Expected masked value to contain <%s> but was <%s>", expectedSubstring, actual.getMasked());
        }
        return this;
    }

    /**
     * 断言脱敏值不包含指定子串（反向模糊匹配）。
     *
     * <p>适用于校验"敏感数据已被完全脱敏"的场景，例如
     * 校验 {@code !result.getMasked().contains("6222021234567890")}。
     *
     * @param unexpectedSubstring 不期望包含的子串
     * @return 当前断言器
     * @throws AssertionError 当实际值包含子串时抛出
     */
    public MaskingResultAssert doesNotContainMaskedValue(String unexpectedSubstring) {
        isNotNull();
        if (actual.getMasked().contains(unexpectedSubstring)) {
            failWithMessage("Expected masked value NOT to contain <%s> but it did: <%s>", unexpectedSubstring, actual.getMasked());
        }
        return this;
    }
}