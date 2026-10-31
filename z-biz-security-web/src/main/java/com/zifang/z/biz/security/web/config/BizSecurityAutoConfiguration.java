package com.zifang.z.biz.security.web.config;

import com.zifang.z.audit.core.service.AuditService;
import com.zifang.z.biz.security.core.mapper.SecurityPolicyMapper;
import com.zifang.z.biz.security.core.service.PersistentPolicyStore;
import com.zifang.z.biz.security.core.service.PolicyLedgerService;
import com.zifang.z.biz.security.core.service.SecurityPipeline;
import com.zifang.z.biz.security.core.service.SecurityPolicyRegistry;
import com.zifang.z.biz.security.core.support.BuiltinSecurityPolicies;
import com.zifang.z.mask.core.service.MaskService;
import com.zifang.z.mask.core.support.DefaultPolicies;
import com.zifang.z.sense.core.service.SenseService;
import com.zifang.z.watermark.core.service.WatermarkService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

/**
 * z-biz-security 自动装配。
 *
 * <p>宿主引用本仓时，只要把 {@code z-biz-security-web} 放进 classpath，
 * {@code META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports}
 * 会把本装配挂上 ⇒ 数据源 + 领域服务齐备。
 *
 * <p>⚠️ 本装配**不扫描**包树（无 {@code @ComponentScan}）—— 跨域交互按组织口径走 HTTP 边界，
 * 不把别人的 jar 拖进本仓上下文。
 *
 * <p><b>装配口径</b>：本域是<b>编排层</b>，依赖四个能力仓的 core：
 * <pre>
 *   z-sense-core     ──▶ SenseService   （识别）
 *   z-mask-core      ──▶ MaskService    （脱敏）
 *   z-watermark-core ──▶ WatermarkService（水印）
 *   z-audit-core     ──▶ AuditService   （审计）
 * </pre>
 * 全部 {@code @ConditionalOnMissingBean} ⇒ 宿主自己装配了同类型 bean 时本仓让位。
 *
 * @author zifang
 */
@AutoConfiguration
@Import(BizSecurityModuleDataSource.class)
public class BizSecurityAutoConfiguration {

    /**
     * 敏感识别服务。
     *
     * @return 识别服务
     */
    @Bean
    @ConditionalOnMissingBean
    public SenseService senseService() {
        return new SenseService();
    }

    /**
     * 脱敏服务（默认策略集）。
     *
     * @param senseService 识别服务
     * @return 脱敏服务
     */
    @Bean
    @ConditionalOnMissingBean
    public MaskService maskService(SenseService senseService) {
        return new MaskService(senseService, DefaultPolicies.policies());
    }

    /**
     * 水印服务。
     *
     * @return 水印服务
     */
    @Bean
    @ConditionalOnMissingBean
    public WatermarkService watermarkService() {
        return new WatermarkService();
    }

    /**
     * 审计服务（**无持久化** ⇒ 只算链不留库；宿主可换成落库版）。
     *
     * @return 审计服务
     */
    @Bean
    @ConditionalOnMissingBean
    public AuditService auditService() {
        return new AuditService();
    }

    /**
     * 策略注册表（**内置场景集齐 5 个**）。
     *
     * @return 策略注册表
     */
    @Bean
    @ConditionalOnMissingBean
    public SecurityPolicyRegistry securityPolicyRegistry() {
        SecurityPolicyRegistry registry =
                new SecurityPolicyRegistry(SecurityPolicyRegistry.builtinDefault());
        for (com.zifang.z.biz.security.core.domain.SecurityPolicy policy
                : BuiltinSecurityPolicies.all()) {
            registry.register(policy);
        }
        return registry;
    }

    /**
     * 策略台账存储（**落库版**）。
     *
     * <p>⚠️ 直接注入 {@code SecurityPolicyMapper}（不用 {@code @ConditionalOnBean}）——
     * 后者评估时机早于 {@code @MapperScan} 注册 ⇒ 条件恒不成立 ⇒ 服务静默缺失。
     *
     * @param mapper 策略 Mapper
     * @return 台账存储
     */
    @Bean
    @ConditionalOnMissingBean
    public PersistentPolicyStore persistentPolicyStore(SecurityPolicyMapper mapper) {
        return new PersistentPolicyStore(mapper);
    }

    /**
     * 策略台账服务（**发布 / 回滚 / 停用 / 热改**）。
     *
     * @param store 台账存储
     * @return 台账服务
     */
    @Bean
    @ConditionalOnMissingBean
    public PolicyLedgerService policyLedgerService(PersistentPolicyStore store) {
        return new PolicyLedgerService(store);
    }

    /**
     * ★ 启动装载：从台账读生效策略（**台账为空 ⇒ 播种内置策略**）。
     *
     * <p>做这件事的原因是：**不装载的话，台账里改的策略重启就没了**
     * ⇒ 热改只活到下次重启 ⇒ 等于「改了白改」。
     *
     * <p><b>⚠️ 装载失败不阻断启动</b>：台账读不出来（表没建 / 库连不上）
     * ⇒ 保留内置策略继续跑 ⇒ 安全防护不能因为台账故障就整个瘫掉。
     *
     * @param registry 策略注册表
     * @param ledger   策略台账服务
     * @return 装载器（启动后执行一次）
     */
    @Bean
    @ConditionalOnMissingBean
    public PolicyBootstrap policyBootstrap(SecurityPolicyRegistry registry,
                                           PolicyLedgerService ledger) {
        return new PolicyBootstrap(registry, ledger);
    }

    /**
     * 安全流水线（编排层主入口）。
     *
     * @param senseService     识别服务
     * @param maskService      脱敏服务
     * @param watermarkService 水印服务
     * @param auditService     审计服务
     * @return 流水线
     */
    @Bean
    @ConditionalOnMissingBean
    public SecurityPipeline securityPipeline(SenseService senseService,
                                             MaskService maskService,
                                             WatermarkService watermarkService,
                                             AuditService auditService) {
        return new SecurityPipeline(senseService, maskService, watermarkService, auditService);
    }

    /**
     * 本域健康检查（探活用）。
     *
     * @return 健康标识
     */
    @Bean
    @ConditionalOnMissingBean
    public BizSecurityHealthIndicator bizSecurityHealthIndicator() {
        return new BizSecurityHealthIndicator("z-biz-security");
    }
}
