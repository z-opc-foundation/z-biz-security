# z-biz-security

> **数据安全域编排层** —— 场景 → 策略 → **识别 → 脱敏 → 水印 → 审计** 四段流水线。
> 边界一句话：**只做编排与拦截判定，不自己实现四个引擎的算法。**

安全线四层能力栈的**编排层**（业务方只报场景码）。同族：`z-sense` · `z-mask` · `z-watermark` · `z-audit`。

立项文档：lead `002_项目需求/001_特性需求/015_z-biz-security_数据安全线`。

## 📋 基本信息

| 项 | 值 |
|---|---|
| 层 | **L1 业务编排仓**（`groupId=com.zifang`，内部件口径，同 z-biz） |
| 坐标 | `com.zifang:z-biz-security`，版本 `1.0.0` |
| parent | `io.github.yuku123:z-boot-parent:1.2.0`（Java 17 / Spring Boot 3.3.13 火车） |
| 包名 | `com.zifang.z.biz.security.core.*` |
| 依赖 | `z-sense-core` · `z-mask-core` · `z-watermark-core` · `z-audit-core`（**只依赖 core，不拖 web / starter 进本 JVM**） |
| 端口 | 8098 |
| 发布 | **不发 Maven Central**（`maven.deploy.skip=true`，同 z-biz） |
| 模块 | `z-biz-security-core` · `z-biz-security-web` |

## 🎯 能力清单

| 能力 | 状态 | 代码位置 |
|---|---|---|
| 安全策略模型（场景 / 阶段序列 / 水印类型 / 阈值） | ✅ | `domain/SecurityPolicy` |
| 阶段枚举（SENSE / MASK / WATERMARK / AUDIT） | ✅ | `domain/SecurityStage` |
| 策略注册表（场景 → 策略 + 兜底） | ✅ | `service/SecurityPolicyRegistry` |
| 内置场景策略（5 个） | ✅ | `support/BuiltinSecurityPolicies` |
| 四段流水线编排 | ✅ | `service/SecurityPipeline` |
| **拦截判定**（命中级别 ≥ 阈值 ⇒ 拦，不出域） | ✅ | `service/SecurityPipeline#shouldBlock` |
| 流水线结果模型 | ✅ | `domain/SecurityResult` |
| REST 端点（跑流水线 / 查策略 / 列场景） | ✅ | `web/api/SecurityPipelineController` |
| 策略台账化（DB + 热改 + 审批） | ❌ M2 | 当前策略在代码里 |
| **识别一次脱敏一次**（按命中列表脱敏的重载） | ✅ M2 | MASK 阶段复用 SENSE 的命中列表（`maskService.mask(text, sense)`） |
| 域内 DDL | — | M1 编排层**无自有表**（策略台账化时才需要） |

## 🔑 核心口径

### 流水线顺序（拦截判定必须在脱敏之前）

```
文本 ──SENSE────▶ 命中列表（位置 + 分级）
       │
       ├─▶ 拦截判定：命中级别 ≥ 策略阈值 ⇒ BLOCKED（**直接返回，不出域**）
       │
       ├─▶ MASK────▶ 脱敏后文本（按命中位置替换）
       │
       ├─▶ WATERMARK▶ 打好溯源水印的文本
       │
       └─▶ AUDIT────▶ 审计留痕（这次处理发生了什么）
```

> ⚠ **拦截判定必须在脱敏前**：拦截的目的是「不让出域」，
> 如果先脱敏再判定，被拦的内容虽然没返回，但也已经算过脱敏了 —— 语义混乱。
>
> 判定本身**不依赖任何下游** ⇒ 即使脱敏 / 水印 / 审计全挂，拦截依然有效。

### 阈值语义：null = 不拦

| 写法 | 含义 |
|---|---|
| `blockThreshold = null` | **永不拦截**（只脱敏） |
| `blockThreshold = "L3"` | 命中 L3 / L4 ⇒ 拦 |
| `blockThreshold = "L4"` | 只有 L4 ⇒ 拦 |

> ⚠ **没有 L5 这一级**（分只有 L1–L4）。「不拦」要写 `null`，别写 `"L5"` ——
> 写 `"L5"` 解析出来是 null，结果虽一样，但读代码的人会以为存在 L5。

### 引擎实际分级（对齐 z-sense）

| 数据类型 | 级别 |
|---|---|
| 详细地址、中文姓名 | L2 内部 |
| **身份证、手机号、邮箱** | **L3 敏感** |
| **银行卡、凭据（密钥 / token）** | **L4 核心** |

⇒ 内置场景策略统一按 **L3 起拦**（个人敏感信息不出域）。

### 各段失败不拖垮整条链

| 段失败 | 降级行为 |
|---|---|
| 识别失败 | 无识别结果 ⇒ 不拦（**但**：识别挂了就等于没防护，见下） |
| 脱敏失败 | **原样返回**（不返回半脱敏的内容） |
| 水印失败 | 不加水印（内容仍可用） |
| 审计失败 | 忽略（审计是辅链路） |

> ⚠ **识别失败 ⇒ 不拦**是个已知风险：识别引擎挂了等于防护失效。
> 生产上应配「识别不可用 ⇒ fail-close（拒绝出域）」的开关。**M1 未做，记在这里。**

### ★ 编排层只识别一次（M2 落地）

SENSE 阶段跑一次识别拿到分级做**拦截判定**，MASK 阶段把**同一份命中列表**交给
z-mask 的「按命中脱敏」重载 ⇒ **全文只扫一遍**。

```java
MaskResult masked = (sense != null)
        ? maskService.mask(current, sense)   // ★ 复用命中，不重扫
        : maskService.mask(current);          // 没跑 SENSE ⇒ 退回自识别
```

**为什么必须只识别一次**（M1 口径下 MASK 会再扫一遍，看似无害，实则有两个真问题）：

| 问题 | 说明 |
|---|---|
| **白扫两遍** | 识别是「全文 × 规则集」线性扫描，规则集上量后是双倍开销 |
| **★ 可能打架** | 两次识别之间若规则集热更，拦截判定用的分级与脱敏用的分级可能来自**不同规则集** ⇒「判了不拦，却按另一套规则脱了」⇒ 口径失真 |

> ⚠ **「真只识别一次」必须用计数识别器验**：光断言「脱出来一样」会被
> 「偷偷识别了第二次但结果碰巧相同」蒙混过去 ⇒ 数调用次数才是唯一可靠判据。
> 已写进 `SecurityPipelineSingleSenseTest`（5 例）。

## 🎯 内置场景策略（5 个）

| 场景码 | 流水线 | 水印 | 阈值 | 意图 |
|---|---|---|---|---|
| `CONTRACT_VIEW` | 识别+脱敏 | 无 | **不拦** | 内部查看：脱敏即可 |
| `CONTRACT_EXPORT` | 全四段 | 显式文字 | L3 | 导出外发：可溯源 + 个人敏感信息不出域 |
| `INTERNAL_REPORT` | 全四段 | 盲水印 | L3 | 正文不留水印文字，但必须能反查 |
| `PUBLIC_SHARE` | 全四段 | 显式文字 | L3 | 对外分享：显式威慑 |
| `IMAGE_ASSET` | 全四段 | 图片隐写 | L3 | 图片资产：肉眼不可见地溯源 |

未登记的场景 ⇒ 走**兜底策略**（全流水线 + L4 阈值），**保证「没配也能跑」而不是直接失败**。

## 📡 REST 端点

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/z-team/api/biz/security/process` | 跑一条流水线（按场景码） |
| GET | `/z-team/api/biz/security/policies?scene=...` | 查某场景的策略 |
| GET | `/z-team/api/biz/security/scenes` | 列全部已登记场景 |
| GET | `/api/biz/security/health` | 健康检查（**无 /z-team 前缀**） |

**业务方怎么用**：只报场景码 + 内容，不自己拼脱敏策略。

```http
POST /z-team/api/biz/security/process
{"scene":"CONTRACT_EXPORT","text":"...","operatorId":"op-1","tenantId":"t-9",
 "bizNo":"B-1","traceId":"trace-1","timestamp":1767225600000}
```

- 命中级别 ≥ 阈值 ⇒ **HTTP 403** + `status=BLOCKED`（业务方据此拒绝出域）
- 否则 HTTP 200 + `status=MASKED` / `PASS` + 处理后内容

## 🏗️ 项目结构

```
z-biz-security/
├── pom.xml
├── z-biz-security-core/
│   └── src/main/java/com/zifang/z/biz/security/core/
│       ├── domain/    SecurityPolicy · SecurityStage · SecurityResult
│       ├── service/   SecurityPipeline（编排）· SecurityPolicyRegistry
│       └── support/   BuiltinSecurityPolicies（5 个内置场景）
└── z-biz-security-web/
    └── src/main/java/com/zifang/z/biz/security/web/
        ├── config/    BizSecurityAutoConfiguration · BizSecurityModuleDataSource · BizSecurityHealthIndicator
        └── api/       SecurityPipelineController · BizSecurityHealthController · ZBizSecurityWebApplication
```

## 🧪 测试

```bash
export JAVA_HOME=/Users/zifang/Library/Java/JavaVirtualMachines/corretto-17.0.19/Contents/Home
mvn -f z-biz-security-core/pom.xml test    # 26 例
mvn -f z-biz-security-web/pom.xml test     # 8 例（H2 + 真 HTTP）
```

**core 26 例**（21 + 5）：识别+脱敏、普通文本零改动、null 安全、禁用策略透传、
拦截（≥ 阈值）、**阈值区分 L3/L4**、null 阈值永不拦、拦截不外泄原文、
水印阶段生效/不生效、先脱敏后水印、审计留痕/不审计、拦截也留痕（DENIED）、
策略注册表（按场景 / 兜底）、内置 5 场景、查看场景不拦、阶段解析、默认阶段顺序、结果视图；
**「只识别一次」5 例**：全文只识别一次（计数验）、只跑 SENSE 也只一次、
只跑 MASK ⇒ 退回自识别一次（不是零次）、**规则中途变化 ⇒ 拦截与脱敏仍同源**、
拦截时命中数一致。

**web 8 例**：查看场景只脱敏、导出场景脱敏+水印、导出场景 L3 ⇒ **403**、
导出场景 L4 ⇒ 403、未登记场景走兜底、策略查询端点、场景列表端点、健康检查可路由。

## 📌 踩坑留档

| 坑 | 现象 | 修法 |
|---|---|---|
| **测试数据校验位不对** | 身份证 `11010119900307123X` 校验位不过 ⇒ 引擎不命中 ⇒ 用例假红 | 换成 z-sense 里已验证的 `110101199003078515` |
| **分级假设错** | 以为身份证是 L4，实际引擎口径是 **L3**（银行卡/凭据才是 L4） | 改测试阈值并**同步改内置策略**（导出场景改 L3 起拦） |
| **骨架生成器包名笔误** | `com.zifang.z.biz/security.web.api`（斜杠混进包名）⇒ 编译期 `';' expected` | 全五仓扫 `com\.zifang\.z\.[a-z-]+/` 批量修 |
| **测试断言写歪** | 期望 `status=PASS` 但实际 `MASKED`（有脱敏就是 MASKED）；导出场景用身份证 ⇒ 被 L3 阈值拦 ⇒ 403 | 改期望值；改用 L2 地址验证「脱敏+水印」两件事同时生效 |
| **`SensitiveDetector` 不是函数式接口** | 有 `detect` + `name` 两个方法 ⇒ 不能用 lambda 构造「坏识别器」 | 写匿名内部类实现两个方法 |
| **重叠消解口径与 z-sense 不一致** | z-sense 是「级别高者**替换**旧命中」，自己实现成「先占位者一律留」⇒ 上游已消解的命中被再消一次可能消出不同结果 ⇒ 错位遮蔽 | 与 `SenseResult#addHit` **逐条比对同算法**，并写单测钉住 |
