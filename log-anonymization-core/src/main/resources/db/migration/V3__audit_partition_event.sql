-- ============================================================
-- Flyway 迁移: V3__audit_partition_event.sql
-- 描述: 创建 MySQL Event 实现审计日志表按月自动分区与清理
-- 设计依据: 执行计划-优化版.md §9.2 auto_partition_audit_log
-- 运行前提: MySQL Event Scheduler 已启用 (SET GLOBAL event_scheduler = ON)
-- 分区策略:
--   - 每月 1 号创建下下个月的分区（提前 1 个月准备）
--   - 自动清理 6 个月前的分区（合规要求保留 6 个月）
-- ============================================================

USE log_anonymization;

-- 确保 Event Scheduler 已启用（需要 SUPER 权限）
SET GLOBAL event_scheduler = ON;

DELIMITER $$

-- 删除已存在的同名 Event（幂等性）
DROP EVENT IF EXISTS auto_partition_audit_log$$

-- 创建按月自动分区 Event
CREATE EVENT auto_partition_audit_log
ON SCHEDULE EVERY 1 MONTH
STARTS '2026-01-01 00:00:00'
COMMENT '审计日志表按月自动分区与清理（每月执行一次）'
DO
BEGIN
    -- ============================================================
    -- 步骤 1: 创建下下个月的分区
    -- 策略: 将 p_future 分区 REORGANIZE 为 [新月分区, p_future]
    -- ============================================================
    SET @next_month = DATE_FORMAT(DATE_ADD(NOW(), INTERVAL 2 MONTH), '%Y%m');
    SET @partition_name = CONCAT('p', @next_month);
    SET @partition_date = DATE_FORMAT(DATE_ADD(NOW(), INTERVAL 3 MONTH), '%Y-%m-01');
    SET @sql = CONCAT(
        'ALTER TABLE audit_log REORGANIZE PARTITION p_future INTO (',
        'PARTITION ', @partition_name, ' VALUES LESS THAN (TO_DAYS(''', @partition_date, ''')),',
        'PARTITION p_future VALUES LESS THAN MAXVALUE)'
    );
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;

    -- ============================================================
    -- 步骤 2: 清理 6 个月前的分区（合规要求保留 6 个月审计数据）
    -- 策略: 直接 DROP 7 个月前的分区（多保留 1 个月作为缓冲）
    -- ============================================================
    SET @old_partition = CONCAT('p', DATE_FORMAT(DATE_SUB(NOW(), INTERVAL 7 MONTH), '%Y%m'));
    SET @drop_sql = CONCAT('ALTER TABLE audit_log DROP PARTITION IF EXISTS ', @old_partition);
    PREPARE drop_stmt FROM @drop_sql;
    EXECUTE drop_stmt;
    DEALLOCATE PREPARE drop_stmt;
END$$

DELIMITER ;