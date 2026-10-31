package com.zifang.z.biz.security.core.service;

import com.zifang.z.audit.core.domain.AuditAction;
import com.zifang.z.audit.core.domain.AuditEvent;
import com.zifang.z.audit.core.domain.AuditResult;
import com.zifang.z.audit.core.service.AuditService;
import com.zifang.z.biz.security.core.domain.SecurityPolicy;
import com.zifang.z.biz.security.core.domain.SecurityResult;
import com.zifang.z.biz.security.core.domain.SecurityStage;
import com.zifang.z.mask.core.service.MaskResult;
import com.zifang.z.mask.core.service.MaskService;
import com.zifang.z.sense.core.domain.SenseResult;
import com.zifang.z.sense.core.domain.SensitiveLevel;
import com.zifang.z.sense.core.service.SenseService;
import com.zifang.z.watermark.core.domain.WatermarkPayload;
import com.zifang.z.watermark.core.service.WatermarkService;

import java.util.UUID;

/**
 * 安全流水线 —— **编排层的核心**。
 *
 * <p>把四个能力仓串成一条流水线：
 * <pre>
 *   文本 ──SENSE────▶ 命中列表（位置 + 分级）
 *          │
 *          ├─▶ 拦截判定：命中级别 ≥ 策略阈值 ⇒ BLOCKED（**直接返回，不出域**）
 *          │
 *          ├─▶ MASK────▶ 脱敏后文本（按命中位置替换）
 *          │
 *          ├─▶ WATERMARK▶ 打好溯源水印的文本
 *          │
 *          └─▶ AUDIT────▶ 审计留痕（这次处理发生了什么）
 * </pre>
 *
 * <p><b>★ 编排层只识别一次（M2 落地）</b>：SENSE 阶段跑一次识别拿到分级做<b>拦截判定</b>，
 * MASK 阶段把**同一份命中列表**交给 z-mask 的「按命中脱敏」重载 ⇒ **全文只扫一遍**。
 *
 * <p><b>为什么必须只识别一次</b>：M1 口径下 MASK 阶段会再跑一次识别，
 * 看似「口径一致、无害」，实则有两个真问题：
 * <ol>
 *   <li><b>白扫两遍</b>：识别是全文 × 规则集线性扫描，规则集上量后是实打实的双倍开销；</li>
 *   <li><b>★ 可能打架</b>：两次识别之间若规则集热更（识别实现被换），
 *       拦截判定用的分级与脱敏用的分级可能来自**不同规则集**
 *       ⇒ 「判了不拦，却按另一套规则脱了」⇒ 口径失真。</li>
 * </ol>
 * 改法：MASK 阶段走 {@code maskService.mask(text, senseResult)} 重载，
 * **不重扫**。命中列表契约破坏（文本长度对不上）时 z-mask 会**退回自识别**兜底。
 *
 * <p><b>各段失败不拖垮整条链</b>：单段异常 ⇒ 该段降级（脱敏失败 ⇒ 原样返回；
 * 水印失败 ⇒ 不加水印；审计失败 ⇒ 忽略），但**拦截判定永远先做**——
 * 判定本身不依赖任何下游。
 *
 * <p><b>线程安全</b>：本类无可变状态（依赖都是入参构造的只读服务）⇒ 可并发调用。
 *
 * @author zifang
 */
public class SecurityPipeline {

    /** 识别服务。 */
    private final SenseService senseService;
    /** 脱敏服务。 */
    private final MaskService maskService;
    /** 水印服务。 */
    private final WatermarkService watermarkService;
    /** 审计服务（可空 ⇒ 不审计）。 */
    private final AuditService auditService;

    /**
     * 构造。
     *
     * @param senseService     识别服务
     * @param maskService      脱敏服务
     * @param watermarkService 水印服务
     * @param auditService     审计服务（可空）
     */
    public SecurityPipeline(SenseService senseService, MaskService maskService,
                            WatermarkService watermarkService, AuditService auditService) {
        this.senseService = senseService;
        this.maskService = maskService;
        this.watermarkService = watermarkService;
        this.auditService = auditService;
    }

    /**
     * 跑一条流水线。
     *
     * @param text        待处理文本
     * @param policy      策略
     * @param payload     水印载荷（跑 WATERMARK 阶段时用；可空 ⇒ 不打水印）
     * @param operatorId  操作人（审计用）
     * @return 处理结果
     */
    public SecurityResult run(String text, SecurityPolicy policy, WatermarkPayload payload,
                              String operatorId) {
        long start = System.currentTimeMillis();
        SecurityResult result = new SecurityResult();
        result.setTraceId(UUID.randomUUID().toString().replace("-", ""));

        if (text == null) {
            result.setContent("");
            result.setStatus(SecurityResult.STATUS_PASS);
            result.setElapsedMillis(System.currentTimeMillis() - start);
            return result;
        }
        if (policy == null || !policy.isEnabled()) {
            result.setContent(text);
            result.setStatus(SecurityResult.STATUS_PASS);
            result.setElapsedMillis(System.currentTimeMillis() - start);
            return result;
        }

        String current = text;

        // ---- 阶段 1：识别 ----
        SenseResult sense = null;
        if (policy.runs(SecurityStage.SENSE)) {
            try {
                sense = senseService.detect(current);
                result.setSenseResult(sense);
                if (sense.getMaxLevel() != null) {
                    result.setMaxLevel(sense.getMaxLevel().name());
                }
            } catch (RuntimeException e) {
                sense = null;
            }
        }

        // ---- 阶段 1.5：拦截判定（**必须在脱敏前**）----
        if (sense != null && shouldBlock(sense, policy)) {
            result.setStatus(SecurityResult.STATUS_BLOCKED);
            result.setBlockReason("命中级别 " + sense.getMaxLevel().name()
                    + " ≥ 阈值 " + policy.getBlockThreshold() + "，已拦截");
            audit(result, policy, operatorId, AuditResult.DENIED, "命中敏感数据被拦截");
            result.setElapsedMillis(System.currentTimeMillis() - start);
            return result;
        }

        // ---- 阶段 2：脱敏 ----
        // ★ 复用 SENSE 阶段的命中列表（不重扫）⇒ 全文只识别一次。
        //    SENSE 没跑 / 跑失败 ⇒ 退回自识别（此时没有可复用的命中）。
        int maskedCount = 0;
        if (policy.runs(SecurityStage.MASK)) {
            try {
                MaskResult masked = (sense != null)
                        ? maskService.mask(current, sense)
                        : maskService.mask(current);
                if (masked != null) {
                    current = masked.getMaskedText();
                    maskedCount = masked.getItems() == null ? 0 : masked.getItems().size();
                }
            } catch (RuntimeException e) {
                // 脱敏失败 ⇒ 原样返回（**不返回半脱敏的内容**）
            }
        }
        result.setMaskedCount(maskedCount);
        if (maskedCount > 0) {
            result.setStatus(SecurityResult.STATUS_MASKED);
        }

        // ---- 阶段 3：水印 ----
        if (policy.runs(SecurityStage.WATERMARK) && payload != null) {
            try {
                Object watermarked = watermarkService.embed(policy.getWatermarkType(), current, payload);
                if (watermarked != null) {
                    current = String.valueOf(watermarked);
                    result.setWatermarkPayload(payload);
                }
            } catch (RuntimeException e) {
                // 水印失败 ⇒ 不加水印（内容仍可用）
            }
        }

        result.setContent(current);

        // ---- 阶段 4：审计 ----
        if (policy.runs(SecurityStage.AUDIT)) {
            audit(result, policy, operatorId,
                    result.isBlocked() ? AuditResult.DENIED : AuditResult.SUCCESS,
                    "处理完成，脱敏 " + maskedCount + " 处");
        }

        result.setElapsedMillis(System.currentTimeMillis() - start);
        return result;
    }

    /**
     * 便捷跑法（不带水印载荷）。
     *
     * @param text   待处理文本
     * @param policy 策略
     * @return 处理结果
     */
    public SecurityResult run(String text, SecurityPolicy policy) {
        return run(text, policy, null, null);
    }

    /**
     * 拦截判定：命中最高级别 ≥ 策略阈值 ⇒ 拦。
     *
     * @param sense  识别结果
     * @param policy 策略
     * @return true = 拦
     */
    private static boolean shouldBlock(SenseResult sense, SecurityPolicy policy) {
        SensitiveLevel threshold = SensitiveLevel.fromCode(policy.getBlockThreshold());
        if (threshold == null) {
            return false;
        }
        SensitiveLevel max = sense.getMaxLevel();
        return max != null && max.atLeast(threshold);
    }

    /**
     * 审计留痕（**失败不外抛**）。
     *
     * @param result     结果
     * @param policy     策略
     * @param operatorId 操作人
     * @param auditResult 结果
     * @param detail     说明
     */
    private void audit(SecurityResult result, SecurityPolicy policy, String operatorId,
                       AuditResult auditResult, String detail) {
        if (auditService == null) {
            return;
        }
        try {
            AuditEvent event = new AuditEvent();
            event.setTraceId(result.getTraceId());
            event.setOperatorId(operatorId);
            event.setAction(policy.runs(SecurityStage.WATERMARK) ? AuditAction.WATERMARK : AuditAction.MASK);
            event.setResult(auditResult);
            event.setTargetType(policy.getScene());
            event.setTargetId(policy.getPolicyId());
            event.setDetail(detail);
            auditService.record(event);
        } catch (RuntimeException e) {
            // 审计失败不影响主链路
        }
    }
}
