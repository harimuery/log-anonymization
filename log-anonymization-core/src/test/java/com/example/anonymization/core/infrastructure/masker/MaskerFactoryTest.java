package com.example.anonymization.core.infrastructure.masker;

import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.model.MaskerConfig;
import com.example.anonymization.api.model.MaskingResult;
import com.example.anonymization.api.spi.SensitiveDataMasker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MaskerFactoryTest {

    private MaskerFactory factory;

    @BeforeEach
    void setUp() {
        factory = new MaskerFactory(List.of(
            new PartialMaskMasker(),
            new FullMaskMasker(),
            new HashMasker("test-salt"),
            new DiscardMasker()
        ));
    }

    @Test
    @DisplayName("按类型获取打码器")
    void create_byType() {
        SensitiveDataMasker masker = factory.create(MaskerType.PARTIAL_MASK);
        assertNotNull(masker);
        assertEquals(MaskerType.PARTIAL_MASK, masker.getMaskerType());
    }

    @Test
    @DisplayName("未注册类型抛IllegalArgumentException")
    void create_unregisteredType() {
        assertThrows(IllegalArgumentException.class, () -> factory.create(MaskerType.GENERALIZE));
    }

    @Test
    @DisplayName("所有已注册类型均可获取")
    void create_allRegistered() {
        assertNotNull(factory.create(MaskerType.PARTIAL_MASK));
        assertNotNull(factory.create(MaskerType.FULL_MASK));
        assertNotNull(factory.create(MaskerType.HASH));
        assertNotNull(factory.create(MaskerType.DISCARD));
    }

    @Test
    @DisplayName("空列表构造不抛异常")
    void create_emptyFactory() {
        MaskerFactory emptyFactory = new MaskerFactory(List.of());
        assertThrows(IllegalArgumentException.class, () -> emptyFactory.create(MaskerType.PARTIAL_MASK));
    }
}