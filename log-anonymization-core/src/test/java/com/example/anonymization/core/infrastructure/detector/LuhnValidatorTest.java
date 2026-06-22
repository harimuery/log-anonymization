package com.example.anonymization.core.infrastructure.detector;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class LuhnValidatorTest {

    @Test
    @DisplayName("有效16位Visa卡号通过Luhn校验")
    void validCard() {
        assertTrue(LuhnValidator.isValid("4111111111111111"));
    }

    @Test
    @DisplayName("无效银行卡号不通过Luhn校验")
    void invalidCard() {
        assertFalse(LuhnValidator.isValid("4111111111111112"));
    }

    @Test
    @DisplayName("全零卡号通过Luhn校验（sum=0, 0%10=0）")
    void allZeros() {
        assertTrue(LuhnValidator.isValid("0000000000000000"));
    }

    @Test
    @DisplayName("空字符串不通过校验")
    void emptyString() {
        assertFalse(LuhnValidator.isValid(""));
    }

    @Test
    @DisplayName("null不通过校验")
    void nullInput() {
        assertFalse(LuhnValidator.isValid(null));
    }

    @Test
    @DisplayName("非数字字符不通过校验")
    void nonNumeric() {
        assertFalse(LuhnValidator.isValid("411111111111111a"));
    }

    @Test
    @DisplayName("15位Amex卡号通过Luhn校验")
    void fifteenDigitCard() {
        assertTrue(LuhnValidator.isValid("378282246310005"));
    }

    @Test
    @DisplayName("19位卡号通过Luhn校验")
    void nineteenDigitCard() {
        assertTrue(LuhnValidator.isValid("4111111111111111110"));
    }

    @Test
    @DisplayName("短于12位不通过校验")
    void tooShort() {
        assertFalse(LuhnValidator.isValid("12345678901"));
    }

    @Test
    @DisplayName("超过19位不通过校验")
    void tooLong() {
        assertFalse(LuhnValidator.isValid("12345678901234567890"));
    }
}