-- =====================================================================
-- z-biz-security 数据安全域编排层 —— DDL（**幂等**，可重复执行）
--
-- 目标库：生产 `oc` 库（与 z-biz / z-trade 共用单库）
-- 字符集：utf8mb4（执行前确认）
--
-- ⚠️ 本脚本**不含** CREATE INDEX（MySQL 8.0 无 CREATE INDEX IF NOT EXISTS
--    ⇒ 会破坏幂等）。二级索引需求另开 _doc/002_deploy/init/00X_*.sql 并**只执行一次**。
-- =====================================================================

CREATE TABLE IF NOT EXISTS z_biz_security_policy (
    id                 BIGINT       NOT NULL AUTO_INCREMENT,
    policy_id          VARCHAR(64)  NOT NULL COMMENT '策略 ID（同一策略的多版本共享）',
    scene              VARCHAR(64)  NOT NULL COMMENT '业务场景码（如 CONTRACT_EXPORT）',
    revision           INT          NOT NULL COMMENT '版本号（从 1 递增，只增不减）',
    status             VARCHAR(16)  NOT NULL COMMENT '状态：DRAFT/PUBLISHED/SUPERSEDED/DISABLED',
    stages             VARCHAR(256) NOT NULL DEFAULT '' COMMENT '阶段序列（逗号分隔，顺序即执行顺序）',
    watermark_type     VARCHAR(32)  NOT NULL DEFAULT 'VISIBLE_TEXT' COMMENT '水印类型',
    block_threshold    VARCHAR(8)   DEFAULT NULL COMMENT '拦截阈值（L1-L4；NULL = 不拦）',
    mask_policy_set_id VARCHAR(64)  DEFAULT NULL COMMENT '脱敏策略集 ID',
    enabled            TINYINT      NOT NULL DEFAULT 1 COMMENT '是否启用',
    remark             VARCHAR(512) DEFAULT NULL COMMENT '备注',
    change_reason      VARCHAR(512) DEFAULT NULL COMMENT '变更原因（合规要求：为什么改）',
    operator_id        VARCHAR(64)  DEFAULT NULL COMMENT '操作人（合规要求：谁改的）',
    created_at         BIGINT       NOT NULL COMMENT '创建时刻（epoch 毫秒）',
    CONSTRAINT pk_z_biz_security_policy PRIMARY KEY (id)
);

-- ★ 同一策略的版本号唯一 ⇒ 重复发布同一版本号会被数据库挡住。
-- ★ 同一场景**只允许一版**处于 PUBLISHED —— 由应用层保证（发布时先把旧的降级）。
--   ⚠️ MySQL 唯一索引里 NULL 与 NULL **不相等** ⇒ 用普通索引 + 应用层约束，
--   不用带 NULL 列的唯一索引。
