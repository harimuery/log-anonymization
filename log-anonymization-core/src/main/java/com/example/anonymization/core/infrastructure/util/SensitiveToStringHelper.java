package com.example.anonymization.core.infrastructure.util;

import com.example.anonymization.api.annotation.SensitiveField;
import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.model.MaskerConfig;
import com.example.anonymization.api.model.MaskingResult;
import com.example.anonymization.core.infrastructure.masker.*;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

/**
 * 敏感 toString 辅助工具 —— 反射扫描 {@link SensitiveField} 注解并执行脱敏。
 *
 * <p>属于基础设施层（infrastructure/util），是执行计划 §5.8 中定义的"第二层防护"，
 * 配合 {@code @SensitiveField} 注解使用，对业务对象生成脱敏后的字符串表示。
 *
 * <p>使用场景：
 * <pre>
 *   // 业务代码中主动调用
 *   log.info("处理支付请求: {}", SensitiveToStringHelper.safeToString(request));
 * </pre>
 *
 * <p>设计要点：
 * <ul>
 *   <li>通过反射遍历对象字段，查找 {@code @SensitiveField} 标记的字段；</li>
 *   <li>根据注解声明的 {@link SensitiveDataType} 选择对应的脱敏算法；</li>
 *   <li>输出格式为 {@code ClassName(field1=value1, field2=***, ...)}；</li>
 *   <li>缓存反射元数据（Caffeine Cache）避免重复扫描；</li>
 *   <li>线程安全：无状态工具类，所有方法均为静态。</li>
 * </ul>
 *
 * @author log-anonymization
 * @since 1.0.0
 */
public final class SensitiveToStringHelper {

    private static final Cache<Class<?>, List<FieldMeta>>
        FIELD_META_CACHE = Caffeine.newBuilder()
        .maximumSize(500)
        .build();

    private static final PartialMaskMasker PARTIAL_MASK = new PartialMaskMasker();
    private static final FullMaskMasker FULL_MASK = new FullMaskMasker();
    private static final DiscardMasker DISCARD = new DiscardMasker();
    private static final HashMasker HASH_MASKER = new HashMasker("default-salt-change-me");
    private static final GeneralizeMasker GENERALIZE = new GeneralizeMasker();

    private SensitiveToStringHelper() {}

    /**
     * 生成对象的脱敏 toString 表示。
     *
     * <p>流程：
     * <ol>
     *   <li>获取对象的 Class 及其所有声明字段（含父类）；</li>
     *   <li>筛选出带 {@code @SensitiveField} 注解的字段；</li>
     *   <li>对敏感字段执行对应类型的脱敏算法；</li>
     *   <li>非敏感字段直接调用 {@code toString()}；</li>
     *   <li>拼接为 {@code ClassName(field=value, ...)} 格式。</li>
     * </ol>
     *
     * @param obj 目标对象
     * @return 脱敏后的字符串表示；obj 为 null 时返回 "null"
     */
    public static String safeToString(Object obj) {
        if (obj == null) {
            return "null";
        }
        if (isPrimitiveOrWrapper(obj.getClass()) || obj instanceof String) {
            return obj.toString();
        }

        List<FieldMeta> fields = FIELD_META_CACHE.get(obj.getClass(), SensitiveToStringHelper::scanFields);
        StringBuilder sb = new StringBuilder();
        sb.append(obj.getClass().getSimpleName()).append("(");

        for (int i = 0; i < fields.size(); i++) {
            FieldMeta meta = fields.get(i);
            sb.append(meta.field.getName()).append("=");
            try {
                Object value = meta.field.get(obj);
                if (meta.sensitiveType != null && value != null) {
                    String masked = maskValue(value.toString(), meta.sensitiveType);
                    sb.append(masked);
                } else {
                    sb.append(value);
                }
            } catch (IllegalAccessException e) {
                sb.append("[ACCESS_ERROR]");
            }
            if (i < fields.size() - 1) {
                sb.append(", ");
            }
        }

        sb.append(")");
        return sb.toString();
    }

    /**
     * 对单个值按数据类型执行脱敏。
     *
     * @param value    原始值
     * @param dataType 敏感数据类型
     * @return 脱敏后的值
     */
    public static String maskValue(String value, SensitiveDataType dataType) {
        MaskerConfig config = MaskerConfig.builder()
            .dataType(dataType)
            .build();
        switch (dataType) {
            case BANK_CARD:
                return PARTIAL_MASK.mask(
                    value,
                    configWithPrefixSuffix(config, 6, 4)
                ).getMasked();
            case ID_CARD:
                return PARTIAL_MASK.mask(
                    value,
                    configWithPrefixSuffix(config, 3, 4)
                ).getMasked();
            case PHONE:
                return PARTIAL_MASK.mask(
                    value,
                    configWithPrefixSuffix(config, 3, 4)
                ).getMasked();
            case EMAIL:
                return PARTIAL_MASK.mask(
                    value,
                    configWithPrefixSuffix(config, 1, 0)
                ).getMasked();
            case NAME:
                return PARTIAL_MASK.mask(
                    value,
                    configWithPrefixSuffix(config, 1, 0)
                ).getMasked();
            case PASSWORD:
            case CVV:
                return DISCARD.mask(value, config).getMasked();
            case API_KEY:
            case PAYMENT_TOKEN:
                return PARTIAL_MASK.mask(
                    value,
                    configWithPrefixSuffix(config, 4, 4)
                ).getMasked();
            case IP_ADDRESS:
                return GENERALIZE.mask(value, config).getMasked();
            default:
                return FULL_MASK.mask(value, config).getMasked();
        }
    }

    private static MaskerConfig configWithPrefixSuffix(MaskerConfig base, int prefix, int suffix) {
        return MaskerConfig.builder()
            .dataType(base.getDataType())
            .keepPrefixLen(prefix)
            .keepSuffixLen(suffix)
            .build();
    }

    private static boolean isPrimitiveOrWrapper(Class<?> clazz) {
        return clazz.isPrimitive()
            || clazz == Boolean.class || clazz == Byte.class || clazz == Character.class
            || clazz == Short.class || clazz == Integer.class || clazz == Long.class
            || clazz == Float.class || clazz == Double.class;
    }

    private static List<FieldMeta> scanFields(Class<?> clazz) {
        List<FieldMeta> result = new ArrayList<>();
        Class<?> current = clazz;
        while (current != null && current != Object.class) {
            for (Field field : current.getDeclaredFields()) {
                field.setAccessible(true);
                SensitiveField annotation = field.getAnnotation(SensitiveField.class);
                result.add(new FieldMeta(
                    field,
                    annotation != null ? annotation.value() : null
                ));
            }
            current = current.getSuperclass();
        }
        return result;
    }

    private record FieldMeta(Field field, SensitiveDataType sensitiveType) {}
}