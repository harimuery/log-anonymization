package com.example.anonymization.core.infrastructure.config;

import com.example.anonymization.api.enums.DetectorType;
import com.example.anonymization.api.enums.MaskerType;
import com.example.anonymization.api.enums.SensitiveDataType;
import com.example.anonymization.api.model.DetectorConfig;
import com.example.anonymization.api.model.MaskerConfig;
import com.example.anonymization.api.model.MaskingRule;
import com.example.anonymization.api.model.MaskingScope;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.LoaderOptions;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * YAML 规则解析器 —— 将 YAML 格式的脱敏规则配置解析为 {@link MaskingRule} 列表。
 *
 * <p>属于基础设施层（infrastructure/config），被 {@link LocalFileRuleLoadAdapter}
 * 和 {@link NacosRuleLoadAdapter} 共享使用，统一规则解析逻辑。
 *
 * <p>支持的 YAML 结构（参考执行计划 §8.2）：
 * <pre>
 *   log-anonymization:
 *     default-rules:
 *       - data-type: BANK_CARD
 *         priority: 50
 *         detector:
 *           type: REGEX
 *           patterns: ['\\b4[0-9]{12}(?:[0-9]{3})?\\b']
 *           enable-luhn-check: true
 *         masker:
 *           type: PARTIAL_MASK
 *           keep-prefix-length: 6
 *           keep-suffix-length: 4
 * </pre>
 *
 * @author log-anonymization
 * @since 1.0.0
 */
public class YamlRuleParser {

    private final Yaml yaml;

    public YamlRuleParser() {
        this.yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
    }

    /**
     * 解析 YAML 内容为规则列表。
     *
     * @param yamlContent YAML 文本内容
     * @return 规则列表
     */
    @SuppressWarnings("unchecked")
    public List<MaskingRule> parse(String yamlContent) {
        Map<String, Object> root = yaml.load(yamlContent);
        if (root == null) {
            return List.of();
        }
        Object anonymizationObj = root.get("log-anonymization");
        if (!(anonymizationObj instanceof Map)) {
            return List.of();
        }
        Map<String, Object> anonymization = (Map<String, Object>) anonymizationObj;
        List<Map<String, Object>> defaultRules =
            (List<Map<String, Object>>) anonymization.get("default-rules");
        if (defaultRules == null || defaultRules.isEmpty()) {
            return List.of();
        }

        int version = parseVersion(anonymization);
        List<MaskingRule> rules = new ArrayList<>();
        for (int i = 0; i < defaultRules.size(); i++) {
            try {
                MaskingRule rule = parseRule(defaultRules.get(i), version);
                if (rule != null) {
                    rules.add(rule);
                }
            } catch (Exception e) {
                throw new RuntimeException(
                    "解析第 " + (i + 1) + " 条规则失败: " + e.getMessage(), e);
            }
        }
        return rules;
    }

    private int parseVersion(Map<String, Object> anonymization) {
        Object versionObj = anonymization.get("version");
        if (versionObj instanceof Number) {
            return ((Number) versionObj).intValue();
        }
        return 1;
    }

    @SuppressWarnings("unchecked")
    private MaskingRule parseRule(Map<String, Object> ruleMap, int version) {
        String dataTypeStr = getString(ruleMap, "data-type");
        SensitiveDataType dataType = parseSensitiveDataType(dataTypeStr);
        if (dataType == null) {
            return null;
        }

        int priority = getInteger(ruleMap, "priority", 0);
        boolean enabled = getBoolean(ruleMap, "enabled", true);

        Map<String, Object> detectorMap = (Map<String, Object>) ruleMap.get("detector");
        ParsedDetector parsedDetector = parseDetectorConfig(detectorMap);

        Map<String, Object> maskerMap = (Map<String, Object>) ruleMap.get("masker");
        ParsedMasker parsedMasker = parseMaskerConfig(maskerMap, dataType);

        return MaskingRule.builder()
            .ruleId(dataTypeStr + "-" + priority)
            .name(dataTypeStr + "-rule")
            .dataType(dataType)
            .detector(parsedDetector.type, parsedDetector.config)
            .masker(parsedMasker.type, parsedMasker.config)
            .scope(MaskingScope.global())
            .priority(priority)
            .enabled(enabled)
            .version(version)
            .build();
    }

    private ParsedDetector parseDetectorConfig(Map<String, Object> detectorMap) {
        if (detectorMap == null) {
            return new ParsedDetector(DetectorType.REGEX, DetectorConfig.builder().build());
        }
        String typeStr = getString(detectorMap, "type");
        DetectorType type = parseDetectorType(typeStr);
        List<String> patterns = getListOfString(detectorMap, "patterns");
        List<String> keywords = getListOfString(detectorMap, "keywords");
        List<String> fieldNames = getListOfString(detectorMap, "field-names");
        String contextPattern = getString(detectorMap, "context-pattern");
        boolean enableLuhnCheck = getBoolean(detectorMap, "enable-luhn-check", false);
        boolean enableChecksum = getBoolean(detectorMap, "enable-checksum", false);

        DetectorConfig config = DetectorConfig.builder()
            .patterns(patterns)
            .keywords(keywords)
            .fieldNames(fieldNames)
            .contextPattern(contextPattern)
            .enableLuhnCheck(enableLuhnCheck)
            .enableChecksum(enableChecksum)
            .build();
        return new ParsedDetector(type, config);
    }

    private ParsedMasker parseMaskerConfig(Map<String, Object> maskerMap,
                                            SensitiveDataType dataType) {
        if (maskerMap == null) {
            return new ParsedMasker(MaskerType.PARTIAL_MASK,
                MaskerConfig.builder().dataType(dataType).build());
        }
        String typeStr = getString(maskerMap, "type");
        MaskerType maskerType = parseMaskerType(typeStr);
        int prefixLen = getInteger(maskerMap, "keep-prefix-length", 3);
        int suffixLen = getInteger(maskerMap, "keep-suffix-length", 4);
        char maskChar = getChar(maskerMap, "mask-char", '*');
        String algorithm = getString(maskerMap, "algorithm");
        String salt = getString(maskerMap, "salt");
        int ipSegmentsToKeep = getInteger(maskerMap, "ip-segments-to-keep", 2);
        List<Double> amountBuckets = getListOfDouble(maskerMap, "amount-buckets");
        boolean maskDomain = getBoolean(maskerMap, "mask-domain", true);

        MaskerConfig.Builder configBuilder = MaskerConfig.builder()
            .dataType(dataType)
            .keepPrefixLen(prefixLen)
            .keepSuffixLen(suffixLen)
            .maskChar(maskChar)
            .ipSegmentsToKeep(ipSegmentsToKeep)
            .amountBuckets(amountBuckets)
            .maskDomain(maskDomain);

        if (algorithm != null) {
            configBuilder.algorithm(algorithm);
        }
        if (salt != null) {
            configBuilder.saltSource(salt);
        }

        return new ParsedMasker(maskerType, configBuilder.build());
    }

    private SensitiveDataType parseSensitiveDataType(String str) {
        if (str == null || str.isBlank()) return null;
        try {
            return SensitiveDataType.valueOf(str.toUpperCase());
        } catch (IllegalArgumentException e) {
            return SensitiveDataType.CUSTOM;
        }
    }

    private DetectorType parseDetectorType(String str) {
        if (str == null || str.isBlank()) return DetectorType.REGEX;
        try {
            return DetectorType.valueOf(str.toUpperCase());
        } catch (IllegalArgumentException e) {
            return DetectorType.REGEX;
        }
    }

    private MaskerType parseMaskerType(String str) {
        if (str == null || str.isBlank()) return MaskerType.PARTIAL_MASK;
        try {
            return MaskerType.valueOf(str.toUpperCase());
        } catch (IllegalArgumentException e) {
            return MaskerType.PARTIAL_MASK;
        }
    }

    @SuppressWarnings("unchecked")
    private List<String> getListOfString(Map<String, Object> map, String key) {
        Object obj = map.get(key);
        if (obj instanceof List) {
            return ((List<Object>) obj).stream()
                .map(Object::toString)
                .toList();
        }
        return List.of();
    }

    @SuppressWarnings("unchecked")
    private List<Double> getListOfDouble(Map<String, Object> map, String key) {
        Object obj = map.get(key);
        if (obj instanceof List) {
            return ((List<Object>) obj).stream()
                .filter(o -> o instanceof Number)
                .map(o -> ((Number) o).doubleValue())
                .toList();
        }
        return List.of();
    }

    private String getString(Map<String, Object> map, String key) {
        Object obj = map.get(key);
        return obj != null ? obj.toString() : null;
    }

    private int getInteger(Map<String, Object> map, String key, int defaultValue) {
        Object obj = map.get(key);
        if (obj instanceof Number) {
            return ((Number) obj).intValue();
        }
        return defaultValue;
    }

    private boolean getBoolean(Map<String, Object> map, String key, boolean defaultValue) {
        Object obj = map.get(key);
        if (obj instanceof Boolean) {
            return (Boolean) obj;
        }
        return defaultValue;
    }

    private char getChar(Map<String, Object> map, String key, char defaultValue) {
        Object obj = map.get(key);
        if (obj instanceof String s && !s.isEmpty()) {
            return s.charAt(0);
        }
        return defaultValue;
    }

    private record ParsedDetector(DetectorType type, DetectorConfig config) {}

    private record ParsedMasker(MaskerType type, MaskerConfig config) {}
}