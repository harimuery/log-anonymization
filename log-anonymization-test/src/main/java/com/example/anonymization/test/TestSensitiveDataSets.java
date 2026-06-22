package com.example.anonymization.test;

import com.example.anonymization.api.enums.SensitiveDataType;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public final class TestSensitiveDataSets {

    private TestSensitiveDataSets() {}

    public static final List<String> BANK_CARD_NUMBERS = List.of(
        "6222021234567890",
        "6228480402564890018",
        "6217001234567890123",
        "6225880137920836",
        "6222021234561234"
    );

    public static final List<String> INVALID_BANK_CARD_NUMBERS = List.of(
        "1234567890123456",
        "0000000000000000",
        "1111222233334444"
    );

    public static final List<String> PHONE_NUMBERS = List.of(
        "13800138000",
        "15912345678",
        "18612345678",
        "19912345678",
        "17012345678"
    );

    public static final List<String> ID_CARD_NUMBERS = List.of(
        "11010519491231002X",
        "440308199901010012",
        "320102198501020017"
    );

    public static final List<String> EMAIL_ADDRESSES = List.of(
        "user@example.com",
        "admin@company.cn",
        "test.user+tag@domain.org"
    );

    public static final List<String> PASSWORDS = List.of(
        "P@ssw0rd123",
        "MySecret123!",
        "admin888"
    );

    public static final List<String> IP_ADDRESSES = List.of(
        "192.168.1.100",
        "10.0.0.1",
        "172.16.254.1"
    );

    public static final List<String> NON_SENSITIVE_DATA = List.of(
        "550e8400-e29b-41d4-a716-446655440000",
        "1700000000000",
        "TX20240622150000123456",
        "1.0.0",
        "v2.3.1",
        "order-2024-001",
        "user_id=12345"
    );

    public static final List<String> MIXED_MESSAGES = List.of(
        "User card=6222021234567890 paid 100.00",
        "Phone: 13800138000, email: user@example.com",
        "Login with password=P@ssw0rd123 from 192.168.1.100",
        "ID: 11010519491231002X, name: Zhang",
        "Transaction traceId=550e8400-e29b-41d4-a716-446655440000 amount=500.00"
    );

    public static final Map<SensitiveDataType, List<String>> BY_TYPE = Map.of(
        SensitiveDataType.BANK_CARD, BANK_CARD_NUMBERS,
        SensitiveDataType.PHONE, PHONE_NUMBERS,
        SensitiveDataType.ID_CARD, ID_CARD_NUMBERS,
        SensitiveDataType.EMAIL, EMAIL_ADDRESSES,
        SensitiveDataType.PASSWORD, PASSWORDS,
        SensitiveDataType.IP_ADDRESS, IP_ADDRESSES
    );

    public static List<String> forType(SensitiveDataType type) {
        return BY_TYPE.getOrDefault(type, Collections.emptyList());
    }
}