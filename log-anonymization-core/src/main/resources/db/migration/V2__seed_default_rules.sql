-- ============================================================
-- Flyway 迁移: V2__seed_default_rules.sql
-- 描述: 初始化默认脱敏规则数据（7 条核心规则 + 全局作用域）
-- 设计依据: 执行计划-优化版.md §9.2 初始化默认规则数据
-- ============================================================

USE log_anonymization;

-- ------------------------------------------------------------
-- 插入 7 条默认脱敏规则
-- 覆盖支付系统最常见的敏感数据类型:
--   1. 银行卡号（Luhn 校验 + 部分遮盖）
--   2. 身份证号（校验位验证 + 部分遮盖）
--   3. 手机号（部分遮盖）
--   4. 密码（字段名检测 + 加盐哈希）
--   5. CVV（字段名检测 + 直接丢弃）
--   6. 邮箱（正则检测 + 部分遮盖）
--   7. IP 地址（正则检测 + 泛化）
-- ------------------------------------------------------------
INSERT INTO masking_rule (rule_name, data_type, detector_type, detector_conf, masker_type, masker_conf, priority, is_enabled, version, description)
VALUES
('银行卡号-部分遮盖', 'BANK_CARD', 'REGEX',
 '{"patterns":["\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b"],"enableLuhnCheck":true}',
 'PARTIAL_MASK', '{"keepPrefixLen":6,"keepSuffixLen":4,"maskChar":"*"}', 50, 1, 1,
 '银行卡号检测：支持 Visa/MasterCard/Amex/UnionPay，启用 Luhn 校验降低误杀'),

('身份证号-部分遮盖', 'ID_CARD', 'REGEX',
 '{"patterns":["\\b[1-9]\\d{5}(?:19|20)\\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\\d|3[01])\\d{3}[\\dXx]\\b"],"enableChecksum":true}',
 'PARTIAL_MASK', '{"keepPrefixLen":3,"keepSuffixLen":4,"maskChar":"*"}', 50, 1, 1,
 '身份证号检测：18 位，启用校验位验证（ISO 7064 MOD-11）'),

('手机号-部分遮盖', 'PHONE', 'REGEX',
 '{"patterns":["\\b1[3-9]\\d{9}\\b"]}',
 'PARTIAL_MASK', '{"keepPrefixLen":3,"keepSuffixLen":4,"maskChar":"*"}', 40, 1, 1,
 '手机号检测：11 位，号段 13x-19x'),

('密码-加盐哈希', 'PASSWORD', 'FIELD_NAME',
 '{"fieldNames":["password","pwd","passwd","secret","pin"]}',
 'HASH', '{"algorithm":"SHA-256","saltSource":"CONFIG"}', 100, 1, 1,
 '密码字段检测：基于字段名匹配，SHA-256 加盐哈希（不可逆）'),

('CVV-直接丢弃', 'CVV', 'FIELD_NAME',
 '{"fieldNames":["cvv","cvv2","cvc","securityCode"]}',
 'DISCARD', '{}', 200, 1, 1,
 'CVV 字段检测：基于字段名匹配，直接丢弃（合规要求不记录）'),

('邮箱-部分遮盖', 'EMAIL', 'REGEX',
 '{"patterns":["\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"]}',
 'PARTIAL_MASK', '{"keepPrefixLen":1,"keepSuffixLen":0,"maskDomain":false}', 40, 1, 1,
 '邮箱检测：保留首字符 + 域名，遮盖中间部分'),

('IP地址-泛化', 'IP_ADDRESS', 'REGEX',
 '{"patterns":["\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"]}',
 'GENERALIZE', '{"ipSegmentsToKeep":2}', 30, 1, 1,
 'IP 地址检测：保留前 2 段，后 2 段泛化为 0.0');

-- ------------------------------------------------------------
-- 为所有默认规则创建全局作用域
-- ------------------------------------------------------------
INSERT INTO masking_rule_scope (rule_id, scope_type, is_active)
SELECT id, 'GLOBAL', 1 FROM masking_rule;