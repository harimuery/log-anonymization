package com.example.anonymization.core.domain;

import com.example.anonymization.api.enums.DetectorType;
import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.model.DetectorConfig;
import com.example.anonymization.api.model.MaskerConfig;
import com.example.anonymization.api.model.MaskingRule;
import com.example.anonymization.api.model.MaskingScope;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ThreadSafeRuleManagerTest {

    private ThreadSafeRuleManager manager;

    private static MaskingRule bankCardRule() {
        return MaskingRule.builder()
            .ruleId("TEST-BANK_CARD-001").name("BankCard").dataType(SensitiveDataType.BANK_CARD)
            .detector(DetectorType.REGEX, DetectorConfig.builder()
                .patterns(List.of("\\b(\\d{16,19})\\b")).enableLuhnCheck(true).build())
            .masker(MaskerType.PARTIAL_MASK, MaskerConfig.builder()
                .keepPrefixLen(4).keepSuffixLen(4).maskChar('*')
                .dataType(SensitiveDataType.BANK_CARD).build())
            .scope(MaskingScope.global()).priority(100).enabled(true).build();
    }

    private static MaskingRule phoneRule() {
        return MaskingRule.builder()
            .ruleId("TEST-PHONE-001").name("Phone").dataType(SensitiveDataType.PHONE)
            .detector(DetectorType.REGEX, DetectorConfig.builder()
                .patterns(List.of("\\b(1[3-9]\\d{9})\\b")).build())
            .masker(MaskerType.PARTIAL_MASK, MaskerConfig.builder()
                .keepPrefixLen(3).keepSuffixLen(4).maskChar('*')
                .dataType(SensitiveDataType.PHONE).build())
            .scope(MaskingScope.global()).priority(80).enabled(true).build();
    }

    private static MaskingRule idCardRule() {
        return MaskingRule.builder()
            .ruleId("TEST-ID_CARD-001").name("IdCard").dataType(SensitiveDataType.ID_CARD)
            .detector(DetectorType.REGEX, DetectorConfig.builder()
                .patterns(List.of("\\b(\\d{17}[0-9Xx])\\b")).enableChecksum(true).build())
            .masker(MaskerType.PARTIAL_MASK, MaskerConfig.builder()
                .keepPrefixLen(3).keepSuffixLen(4).maskChar('*')
                .dataType(SensitiveDataType.ID_CARD).build())
            .scope(MaskingScope.global()).priority(90).enabled(true).build();
    }

    private static MaskingRule disabledRule() {
        return MaskingRule.builder()
            .ruleId("TEST-DISABLED-001").name("Disabled").dataType(SensitiveDataType.EMAIL)
            .detector(DetectorType.REGEX, DetectorConfig.builder()
                .patterns(List.of("\\b[\\w.+-]+@[\\w-]+\\.[\\w.]+\\b")).build())
            .masker(MaskerType.PARTIAL_MASK, MaskerConfig.builder()
                .keepPrefixLen(1).keepSuffixLen(0).maskChar('*')
                .dataType(SensitiveDataType.EMAIL).build())
            .scope(MaskingScope.global()).priority(50).enabled(false).build();
    }

    @BeforeEach
    void setUp() {
        manager = new ThreadSafeRuleManager();
    }

    @Test
    @DisplayName("初始状态规则列表为空")
    void initialRules_empty() {
        assertTrue(manager.getCurrentRules().isEmpty());
    }

    @Test
    @DisplayName("refreshRules后可获取规则")
    void refreshRules_basic() {
        manager.refreshRules(List.of(bankCardRule()));
        assertEquals(1, manager.getCurrentRules().size());
    }

    @Test
    @DisplayName("禁用规则被过滤")
    void refreshRules_disabledFiltered() {
        MaskingRule enabled = bankCardRule();
        MaskingRule disabled = disabledRule();
        manager.refreshRules(List.of(enabled, disabled));
        assertEquals(1, manager.getCurrentRules().size());
        assertEquals(enabled.getRuleId(), manager.getCurrentRules().get(0).getRuleId());
    }

    @Test
    @DisplayName("规则按priority降序排列")
    void refreshRules_sortedByPriority() {
        manager.refreshRules(List.of(phoneRule(), bankCardRule(), idCardRule()));
        List<MaskingRule> rules = manager.getCurrentRules();
        assertEquals(3, rules.size());
        assertTrue(rules.get(0).getPriority() >= rules.get(1).getPriority());
        assertTrue(rules.get(1).getPriority() >= rules.get(2).getPriority());
    }

    @Test
    @DisplayName("多次refreshRules原子替换")
    void refreshRules_atomicReplace() {
        manager.refreshRules(List.of(bankCardRule()));
        assertEquals(1, manager.getCurrentRules().size());
        manager.refreshRules(List.of(bankCardRule(), phoneRule()));
        assertEquals(2, manager.getCurrentRules().size());
    }

    @Test
    @DisplayName("空列表refreshRules清空规则")
    void refreshRules_emptyList() {
        manager.refreshRules(List.of(bankCardRule()));
        assertFalse(manager.getCurrentRules().isEmpty());
        manager.refreshRules(Collections.emptyList());
        assertTrue(manager.getCurrentRules().isEmpty());
    }

    @Test
    @DisplayName("getCurrentRules返回不可变列表")
    void getCurrentRules_immutable() {
        manager.refreshRules(List.of(bankCardRule()));
        assertThrows(UnsupportedOperationException.class, () ->
            manager.getCurrentRules().add(phoneRule()));
    }

    @Test
    @DisplayName("并发refreshRules不抛异常")
    void refreshRules_concurrent() throws InterruptedException {
        int threadCount = 10;
        Thread[] threads = new Thread[threadCount];
        for (int i = 0; i < threadCount; i++) {
            final int idx = i;
            threads[i] = new Thread(() -> {
                if (idx % 2 == 0) {
                    manager.refreshRules(List.of(bankCardRule()));
                } else {
                    manager.refreshRules(List.of(phoneRule()));
                }
            });
        }
        for (Thread t : threads) t.start();
        for (Thread t : threads) t.join();
        assertTrue(manager.getCurrentRules().size() <= 1);
    }
}