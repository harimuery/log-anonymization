-- ============================================================
-- Flyway 迁移: V1__init_schema.sql
-- 描述: 初始化日志脱敏 SDK 数据库 schema（3 张核心表）
-- 数据库: MySQL 8.0+
-- 字符集: utf8mb4, 排序规则: utf8mb4_unicode_ci
-- 设计依据: 执行计划-优化版.md §9.2 DDL 脚本（V2.0 精简版）
-- ============================================================

-- 创建数据库（如不存在）
CREATE DATABASE IF NOT EXISTS log_anonymization
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE log_anonymization;

-- ------------------------------------------------------------
-- 1. 脱敏规则主表
--    存储所有脱敏规则的配置（检测器 + 脱敏器 + 优先级 + 版本）
--    预估数据量: < 1000 条（单库单表足够）
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS masking_rule (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '主键 ID',
    rule_name       VARCHAR(100)  NOT NULL COMMENT '规则名称（可读，用于审计报表）',
    data_type       VARCHAR(50)   NOT NULL COMMENT '敏感数据类型: BANK_CARD/ID_CARD/PHONE/EMAIL/IP_ADDRESS/PASSWORD/CVV/CUSTOM',
    detector_type   VARCHAR(50)   NOT NULL COMMENT '识别器类型: REGEX/KEYWORD/FIELD_NAME/COMPOSITE',
    detector_conf   JSON          NOT NULL COMMENT '识别器配置(JSON): patterns/keywords/fieldNames/enableLuhnCheck 等',
    masker_type     VARCHAR(50)   NOT NULL COMMENT '脱敏器类型: PARTIAL_MASK/FULL_MASK/HASH/DISCARD/GENERALIZE',
    masker_conf     JSON          NOT NULL COMMENT '脱敏器配置(JSON): keepPrefixLen/keepSuffixLen/maskChar/algorithm 等',
    priority        INT           NOT NULL DEFAULT 0 COMMENT '优先级（数值越大越优先匹配）',
    is_enabled      TINYINT(1)    NOT NULL DEFAULT 1 COMMENT '是否启用: 1=启用, 0=禁用',
    version         INT           NOT NULL DEFAULT 1 COMMENT '规则版本号（用于灰度/回滚）',
    description     VARCHAR(500)  DEFAULT NULL COMMENT '规则描述（可选）',
    created_at      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    updated_at      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    INDEX idx_data_type (data_type) COMMENT '按数据类型查询索引',
    INDEX idx_enabled_priority (is_enabled, priority DESC) COMMENT '按启用状态+优先级查询索引'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='脱敏规则主表';

-- ------------------------------------------------------------
-- 2. 规则作用域表
--    定义每条规则的作用范围（全局/应用/包名/Logger/环境）
--    一条规则可对应多个作用域（1:N 关系）
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS masking_rule_scope (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '主键 ID',
    rule_id         BIGINT        NOT NULL COMMENT '关联规则 ID（外键）',
    scope_type      VARCHAR(30)   NOT NULL COMMENT '作用域类型: GLOBAL/APP/PACKAGE/LOGGER/MARKER/ENV',
    app_name        VARCHAR(100)  DEFAULT NULL COMMENT '应用名称（scope_type=APP 时生效）',
    package_pattern VARCHAR(200)  DEFAULT NULL COMMENT '包名匹配模式（scope_type=PACKAGE 时生效，支持通配符）',
    logger_name     VARCHAR(200)  DEFAULT NULL COMMENT 'Logger 名称（scope_type=LOGGER 时生效）',
    marker_name     VARCHAR(100)  DEFAULT NULL COMMENT 'Marker 名称（scope_type=MARKER 时生效）',
    env             VARCHAR(20)   DEFAULT NULL COMMENT '环境标识（scope_type=ENV 时生效）: dev/staging/prod',
    is_active       TINYINT(1)    NOT NULL DEFAULT 1 COMMENT '是否激活: 1=激活, 0=停用',
    created_at      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    INDEX idx_rule_id (rule_id) COMMENT '按规则 ID 查询索引',
    INDEX idx_scope (scope_type, app_name, env) COMMENT '按作用域查询索引',
    CONSTRAINT fk_scope_rule FOREIGN KEY (rule_id)
        REFERENCES masking_rule(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='规则作用域表';

-- ------------------------------------------------------------
-- 3. 脱敏审计日志表（按月分区，自动维护）
--    预估数据量: ~5000 万条/天（50K QPS × 86400s）
--    存储容量: 单条约 200 字节，日增 ~10GB
--    分区策略: 按月 RANGE 分区，保留 6 个月（由 V3 迁移脚本创建 Event 自动维护）
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGINT AUTO_INCREMENT COMMENT '自增 ID（与 created_at 组成复合主键）',
    trace_id        VARCHAR(64)   NOT NULL COMMENT '分布式链路追踪 ID（用于跨服务关联）',
    app_name        VARCHAR(100)  NOT NULL COMMENT '应用名称（标识来源服务）',
    rule_id         BIGINT        DEFAULT NULL COMMENT '命中的规则 ID（未命中时为 NULL）',
    rule_name       VARCHAR(100)  DEFAULT NULL COMMENT '命中的规则名称（冗余字段，便于查询）',
    data_type       VARCHAR(50)   NOT NULL COMMENT '敏感数据类型',
    action          VARCHAR(30)   NOT NULL COMMENT '脱敏动作: MASKED/HASHED/DISCARDED/DEGRADED',
    hit_count       INT           NOT NULL DEFAULT 1 COMMENT '命中次数（单条日志可能命中多次）',
    is_success      TINYINT(1)    NOT NULL DEFAULT 1 COMMENT '是否脱敏成功: 1=成功, 0=失败',
    error_message   VARCHAR(500)  DEFAULT NULL COMMENT '错误信息（is_success=0 时记录）',
    extra_info      JSON          DEFAULT NULL COMMENT '扩展信息（JSON，如耗时、匹配位置等）',
    created_at      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间（分区键）',
    PRIMARY KEY (id, created_at) COMMENT '复合主键（支持按时间分区）',
    INDEX idx_trace_id (trace_id) COMMENT '按 traceId 查询索引',
    INDEX idx_app_data_type (app_name, data_type) COMMENT '按应用+数据类型查询索引',
    INDEX idx_created_at (created_at) COMMENT '按时间查询索引'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='脱敏审计日志表（按月分区）'
  PARTITION BY RANGE (TO_DAYS(created_at)) (
    PARTITION p_future VALUES LESS THAN MAXVALUE
  );