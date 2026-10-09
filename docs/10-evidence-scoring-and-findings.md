
[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# 10 — 證據分級、評分、優先序與 Finding 格式

> 技術嚴重度、處置優先序、證據可信度、驗證狀態、測試覆蓋率**分開呈現**，不合成一個模糊的安全總分。本文件對應 `vibesec.yaml` 的 `scoring.*` 與 `schemas/finding.schema.json`、`schemas/gate-result.schema.json`。

## 1. 證據等級 E0–E3

這是本框架的**內部**證據分級，不是外部認證標準。它回答「證據有多可信」，不回答「有多嚴重」。

| 等級 | 定義 | 可支持的結論 | 典型來源 |
|---|---|---|---|
| **E3 已確認** | 固定版本（commit / digest）上可重現，或有足以確認的程式／設定／架構證據，且**經人工核對** | 問題成立，可進入正式修復決策；可標 `validation_status: confirmed` | G5 雙帳號 BOLA 實測 HTTP 交換；gitleaks 命中且服務商驗證金鑰有效；人工重現的 SQLi |
| **E2 有直接支持** | 有具體位置、適用版本與合理攻擊路徑，但部分部署或執行前提未確認 | 優先驗證，保留成立條件；不得表述為「已確認漏洞」 | Semgrep 跨檔污點路徑完整；grype 命中且版本在受影響範圍且程式有 import；兩個 family 的 reviewer 一致 `confirm` 並引用同一路徑 |
| **E1 候選線索** | 工具告警、公告匹配或模型懷疑，尚未確認適用性 | 待查；可進入分流佇列 | 單檔 Semgrep 規則命中；SCA 比對到 CVE 但未查可達性；單一 reviewer `confirm` |
| **E0 無支持推測** | 無可追溯證據或僅泛稱最佳實務 | 不計入已確認弱點；保留並記錄待釐清原因 | reviewer 說「通常這類程式會有問題」但無 file:line；缺 CSP 但未找到 XSS |

升級規則：E1 → E2 需要可引用的直接證據（路徑、版本、HTTP 交換）；E2 → E3 需要**重現或人工核對**。多模型一致最多只能到 E2。模型自評信心（「95%」）不影響 E 等級。

## 2. validation_status

| 值 | 意義 | 誰能設定 |
|---|---|---|
| `pending` | 待驗證（預設） | harness |
| `confirmed` | 已確認成立 | 僅在 E3 時由人工裁決或可重現測試設定；確定性高的規則（硬編碼金鑰經 API 驗證、JWT alg:none 實測成功）可由 harness 自動設定並附 `evidence_refs` |
| `refuted` | 已反駁（誤報或不適用） | 人工裁決；或 G5 實測明確否定（例如 B token 存取 A 資源回 403，且 reviewer 無異議） |

`validation_status` 與 `evidence_grade` 分開：E2 + pending 是常態；E3 + refuted 也合法（有充分證據證明不成立）。無法確認時維持 `pending`，**不自動結案**。

## 3. 每件發現必須記錄的項目

| 項目 | 對應欄位 |
|---|---|
| 原始來源（工具 / 公告 / 模型 / 人工） | `sources.tool`、`evidence_refs[].kind` |
| 發布 / 查詢時間 | `sources.advisory_published`、`sources.queried_at`、`epss_date`、`kev_date` |
| 適用版本 | `location.version`（套件）或 `sources.tool_version` |
| 程式 commit | `location.commit` |
| 設定或產物 digest | `evidence_refs[].digest` |
| 工具及規則版本 | `sources.tool_version`、`sources.rule_version` |
| 模型及提示版本 | `review.opinions[].model`、`review.opinions[].prompt_version` |
| 測試前提 | `notes`（例如「需 B 帳號為同租戶一般使用者」） |
| 預期與實際結果 | `evidence_refs[].note`（`http_exchange` 類寫「expected 403, got 200」） |
| 支持證據 | `evidence_refs[]`（tool_output / code_excerpt / http_exchange / advisory / sbom / trace） |
| 反證 | `evidence_refs[]` 加 `note: "counter-evidence: ..."`；reviewer `refute` 意見 |
| 缺漏 | `notes`（「未確認是否部署於公開網段」） |
| 人工裁決依據 | `review.human_decision`（摘要）與 `review.ruling_ref`（指向 `rulings/<id>.yaml`，格式見 docs/09 §12） |

**同一公告多站轉載只算一個來源**：`sources.advisory_url` 填官方（NVD / GHSA / 供應商 advisory）；轉載不加入 `evidence_refs`，不因此提升 E 等級。官方公告確認漏洞範圍；本系統程式與部署證據確認適用性。

## 4. 評分維度

| 維度 | 採用方式 | 欄位 |
|---|---|---|
| 技術嚴重度 | CVSS v4.0，保存完整向量與每項判定依據，由確定性計算器計分（`scoring.cvss_version: "4.0"`）；工具只給 v3.1 時照記 `cvss_version: "3.1"`，不換算 | `severity`、`cvss_version`、`cvss_vector`、`cvss_score` |
| 企業情境 | 已知時補 Threat（E）/ Environmental（CR/IR/AR、Modified Base）指標，寫入同一向量；未知前提在 `notes` 明列 | `cvss_vector`（含 `/E:`、`/CR:` 等段）、`notes` |
| 外部利用訊號 | 有 CVE 時記 EPSS 機率與查詢日、KEV 狀態與日期（`record_epss`、`record_kev`）；無 CVE 全填 `null` | `epss`、`epss_date`、`kev`、`kev_date` |
| 證據可信度 | E0–E3；低可信度不把高衝擊問題自動降為低風險 | `evidence_grade` |
| 架構／控制缺口 | 無法合理套用 CVSS 時，記錄攻擊情境、影響與缺失控制，`severity` 可填工具 / reviewer 給的定性值或 `null`，`cvss_*` 全 `null`，**不硬編分數** | `location.kind: architecture`、`description`、進 `risk_register.json` |

**明文禁止**（`scoring.combine_scores: false`）：不做 `CVSS × EPSS × 模型信心` 或任何自訂乘法、加權平均、「風險總分」。CVSS 描述嚴重度；EPSS 是已公布 CVE 未來 30 天遭利用的估計機率；KEV 是已知遭利用名單。三者分工不同，各自呈現；優先序用 §5 的**查表**決定，而非算式。

## 5. 優先序 P0–P3 與 SLA

| 優先序 | 定義 | 修復 SLA（`priority_sla_days`） | 分流 SLA |
|---|---|---|---|
| **P0 立即處置** | 已發生入侵／外洩，或正式環境有效高權限祕密暴露 | 0 天：立即交人工事件處理 | 立即 |
| **P1 優先修復** | 已確認 Critical／High；適用且暴露的 KEV；重大影響的授權或發布信任邊界失守 | 7 天修復或完成有期限的補償控制；1 工作日內分派 | 潛在 P0/P1 的 E1/E2 案件 1 工作日內人工分流 |
| **P2 排程修復** | 已確認 Medium | 30 天 | 其餘待驗證案件 5 工作日內分流 |
| **P3 例行改善** | 已確認 Low／強化項 | 90 天內檢視處置 | 5 工作日 |

`due_date = created_at + priority_sla_days[priority]`。`pending` 的發現 `priority` 填「候選值」並在 `notes` 標 `candidate`；`refuted` 的 `priority: null`。公司既有更嚴格規則優先。

### 確定性查表

輸入：`validation_status`、`severity`（CVSS 推導或工具提供）、`kev`、`exposure`（來自威脅模型 `system.exposure`：`public` / `partner` / `internal`；無威脅模型視為 `public`）、`secret_live`（G2 專用：金鑰經服務商 API 驗證仍有效且屬正式環境）。

| 條件（由上往下第一個符合） | priority |
|---|---|
| `secret_live = true` 且範圍為正式環境高權限 | P0 |
| 已確認入侵跡象（人工標記） | P0 |
| `kev = true` 且 `exposure ∈ {public, partner}` | P1 |
| `validation_status = confirmed` 且 `severity ∈ {critical, high}` | P1 |
| 授權類（BOLA/IDOR、跨租戶、單層 middleware 繞過）或發布信任類（幻覺套件、冷卻期違規、postinstall 外連）`confirmed` | P1 |
| `validation_status = pending` 且 `severity ∈ {critical, high}` 或 `kev = true` | P1（候選，1 工作日分流） |
| `validation_status = confirmed` 且 `severity = medium` | P2 |
| `validation_status = pending` 且 `severity = medium` | P2（候選） |
| `severity ∈ {low, info}` 或架構強化項 | P3 |
| `validation_status = refuted` | `null` |

查表不含 `evidence_grade`：E1 的 critical 仍是 P1 候選（進快速分流），這就是「低可信度不自動降級」的落實。

## 6. Finding JSON 逐欄說明

對照 `schemas/finding.schema.json`（`additionalProperties: false`，所有 `required` 欄位必須出現，不適用填 `null`）：

```json
{
  "id": "VS-20261003-9f3a1c2e",            // VS-YYYYMMDD-<8 hex>；hex = sha256(rule_id+path+line+commit)[:8]
  "gate": "G5",                             // G0–G6
  "rule_id": "vibesec.g5.bola-cross-account", // vibesec 規則或 "<tool>:<原規則>"（gitleaks:、semgrep:、trivy:…）
  "title": "B 帳號可讀取 A 帳號訂單",
  "description": "GET /orders/{id} 未綁定 owner_id；以 B token 取得 A 的訂單 1001。",
  "control_id": "ASVS5-V8.2",               // 僅 catalogs 內存在者；查不到 null
  "cwe": "CWE-639",                         // 僅 catalogs 內存在者
  "cve": null,                              // 自寫程式無 CVE
  "severity": "high",
  "cvss_version": "4.0",
  "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
  "cvss_score": 7.1,                        // 由確定性計算器算出，不手填
  "epss": null, "epss_date": null,          // 無 CVE → 不適用
  "kev": null, "kev_date": null,
  "evidence_grade": "E3",                   // 雙帳號實測可重現
  "validation_status": "confirmed",
  "policy_tier": "blocking",                // 來自 blocking-policy.yaml
  "priority": "P1",
  "owner": "team-orders",
  "due_date": "2026-10-10",                 // created_at + 7
  "location": { "kind": "http", "path": "/orders/{id}", "start_line": null, "end_line": null,
                "package": null, "version": null, "url": "https://staging.example/orders/1001",
                "commit": "a1b2c3d" },
  "evidence_refs": [
    { "kind": "http_exchange", "ref": "reports/raw/G5/api-probes/bola-1001.json",
      "digest": "sha256:…", "note": "expected 403, got 200 with A's order body" },
    { "kind": "model_review", "ref": "reports/raw/review/VS-20261003-9f3a1c2e/identity-authz-r1.json",
      "digest": null, "note": "2 families confirm; cites app/routers/orders.py:42" }
  ],
  "review": {
    "opinions": [
      { "role": "identity-authz", "provider": "anthropic-cloud", "family": "anthropic",
        "model": "claude-sonnet-5-5", "prompt_version": "identity-authz@2026-10-03.1",
        "round": 1, "verdict": "confirm", "rationale": "orders.py:42 無 owner 過濾…", "minority": false },
      { "role": "identity-authz", "provider": "openai-cloud", "family": "openai",
        "model": "gpt-5", "prompt_version": "identity-authz@2026-10-03.1",
        "round": 1, "verdict": "confirm", "rationale": "…", "minority": false }
    ],
    "requires_human": false,
    "human_decision": "2026-10-03 appsec-lead: confirmed via manual replay"
  },
  "retest_result": "not_retested",
  "sources": { "tool": "api-probes", "tool_version": "0.3.0", "rule_version": "2026-09",
               "advisory_url": null, "advisory_published": null, "queried_at": "2026-10-03T06:12:00Z" },
  "created_at": "2026-10-03T06:12:31Z",
  "notes": "前提：A、B 為同租戶一般使用者。"
}
```

套件類範例差異：`location.kind: dependency`，`package` / `version` 必填，`cve` 必填，`epss` / `kev` 查詢後填值（例 `"epss": 0.0312, "epss_date": "2026-10-03", "kev": false, "kev_date": "2026-10-03"`），`sources.advisory_url` 指 NVD / GHSA 官方頁。

祕密類範例差異：`title` 與 `description` 只保留遮罩（`sk-ab…9f3Q`）與 sha256 指紋；`evidence_refs[].ref` 指向 gitleaks 原生輸出，原始值不得進任何報告。

## 7. SARIF 2.1.0 對映

只有 `location.kind ∈ {code, dependency, config}` 的發現匯出 SARIF；每個工具一個 `run`。

| Finding 欄位 | SARIF 位置 |
|---|---|
| `rule_id` | `result.ruleId`；`run.tool.driver.rules[].id` |
| `title` | `rules[].shortDescription.text` |
| `description` | `result.message.text` |
| `severity` | `result.level`（critical/high → `error`，medium → `warning`，low/info → `note`）；原值放 `result.properties.vibesec/severity` |
| `cvss_score` | `rules[].properties.security-severity`（GitHub 用此排序） |
| `cwe` | `rules[].properties.tags: ["external/cwe/cwe-89"]`；`rules[].relationships[]` 指向 CWE taxonomy |
| `location.path / start_line / end_line` | `result.locations[0].physicalLocation.artifactLocation.uri` / `region.startLine` / `region.endLine` |
| `location.package / version` | `result.locations[0].logicalLocations[0].fullyQualifiedName`（`pkg:npm/axois@1.0.0` purl） |
| `id` | `result.fingerprints["vibesec/id"]`；`partialFingerprints["vibesec/stable"]` = sha256(rule_id+path) |
| `evidence_grade`, `validation_status`, `policy_tier`, `priority`, `control_id`, `cve`, `epss`, `epss_date`, `kev`, `kev_date`, `cvss_vector`, `gate` | `result.properties.vibesec/<欄位名>` |
| `evidence_refs[]` | `result.relatedLocations[]`（code_excerpt）與 `result.attachments[]`（tool_output、http_exchange） |
| `sources.tool / tool_version` | `run.tool.driver.name / version` |
| `sources.rule_version` | `rules[].properties.vibesec/rule_version` |
| `review.opinions[]` | 不進 SARIF（只在 findings.json） |
| `location.commit` | `run.versionControlProvenance[0].revisionId` |

## 8. Risk Register

`reports/risk_register.json` 收 `location.kind ∈ {architecture, prompt}` 的發現，加上 G0 威脅模型中 `status: open` 的 threats：

```json
{
  "generated_at": "…", "project": "…", "commit": "…", "risk_tier": "L2",
  "risks": [
    { "finding_id": "VS-…", "gate": "G4", "control_id": "VS-G4-AGENT-TOOL-ALLOWLIST",
      "scenario": "通用客服 Agent 可呼叫 execute_sql", "impact": "任意讀寫正式 DB",
      "missing_control": "工具 allow-list + HITL", "maestro_layer": 3,
      "evidence_grade": "E2", "validation_status": "pending", "priority": "P1",
      "owner": "…", "due_date": "…", "status": "open",
      "trifecta": { "private_data": true, "untrusted_content": true, "external_comms": true, "leg_cut": null } }
  ],
  "threat_model_open_threats": [ { "id": "T-03", "category": "MAESTRO-L3", "gate": "G4", "status": "open" } ]
}
```

架構風險沒有 CVSS，欄位以情境 / 影響 / 缺失控制呈現；`priority` 仍走 §5 查表（授權 / 發布信任類 confirmed → P1）。

## 9. 控制覆蓋狀態與覆蓋率

每道閘門的 gate result `coverage[]` 對適用控制逐一標狀態：

| state | 意義 |
|---|---|
| `pass` | 已測且無發現 |
| `fail` | 已測且有 `validation_status != refuted` 的發現 |
| `pending` | 已測但結論待驗證（如審查 family 不足、E1 待分流） |
| `untested` | 本次未測（工具缺席、逾時、缺 token、diff 範圍外） |
| `not_applicable` | 依設計不適用，**必附 `reason`**（schema 強制） |

```
coverage_ratio = (pass + fail) / (pass + fail + pending + untested)
```

分母排除 `not_applicable`；分子只算「已完成測試」。`summary.md` 同時列出各領域（docs/09 §8 的 14 領域）結果，避免大量低風險 pass 掩蓋關鍵授權 fail。閘門 `status` 推導：任一 `fail` → `fail`；無 fail 但有 `untested`/`pending` 且原因屬 docs/08 §7 → `incomplete`；全 pass（或 pass + not_applicable）→ `pass`。

## 10. 重測規則

- 修復驗證使用**新版本**（新 commit / digest），重跑原失敗案例與相關安全對照案例；`retest_result` 設 `fixed` / `still_present` / `regressed`。
- `fixed` 需同等級證據：E3 的發現要再次實測回 403 或重現失敗；不得只因程式被改動就標 fixed。
- `regressed`：先前 `fixed` 的發現在後續版本再度出現（以 `partialFingerprints["vibesec/stable"]` 比對）→ 自動升回原 priority，`notes` 記回歸 commit。
- 重測前 `retest_result: not_retested`；`refuted` 的發現不重測（`null`）。
- 重測結果寫回同一 `id`，不另開新 finding；歷史保留在 `evidence_refs[]`。


---

<a id="english"></a>

# 10 — Evidence, Scoring, Priority, and Finding Format

Keep technical severity, response priority, evidence strength, validation, and coverage separate. Do not collapse them into a vague security score. Configuration: `scoring.*`; schemas: finding and gate-result.

## 1. Internal evidence grades

| Grade | Meaning | Supported conclusion / examples |
|---|---|---|
| E3 confirmed | Reproducible on a fixed commit/digest or sufficient code/config/architecture evidence with human verification | Formal remediation; two-account HTTP proof, verified active secret, manually reproduced SQLi |
| E2 directly supported | Specific location/version/plausible path, but some deployment/runtime assumptions remain | Prioritize verification, do not call confirmed; full taint path, affected imported dependency, two-family evidence-backed agreement |
| E1 candidate | Tool/advisory/model signal without applicability confirmation | Triage; single-file alert, unmatched reachability, single reviewer suspicion |
| E0 unsupported hypothesis | No traceable support or generic best practice | Not a confirmed weakness; retain clarification needs |

E1→E2 requires direct cited evidence; E2→E3 requires reproduction/human verification. Model agreement alone reaches at most E2. Confidence percentages have no effect. This is an internal scale, not certification.

## 2. Validation status

`pending` is default; `confirmed` requires E3 and adjudication/reproducible evidence (high-certainty tests may set it with references); `refuted` requires human adjudication or explicit disproof without unresolved reviewer objection. E2+pending is normal; E3+refuted is valid when strong evidence disproves a claim. Uncertainty remains pending, never auto-closed.

## 3. Required provenance

Record source tool/evidence kind; publication/query dates; affected package/tool versions; code commit; artifact digest; tool/rule versions; model/prompt versions; test preconditions; expected/actual results; support; counterevidence; missing assumptions; and human decision/ruling reference. Use canonical vendor/NVD/GHSA advisories. Multiple reposts of one advisory count as one source; advisory scope and actual local applicability require different evidence.

## 4. Scoring dimensions

- **Technical severity:** store complete CVSS v4.0 vector and metric rationale, calculate deterministically. Preserve native v3.1 when supplied; do not invent a conversion.
- **Enterprise context:** add known Threat/Environmental metrics (E, CR/IR/AR, modified base) to the vector; disclose unknowns.
- **External signals:** CVE-linked EPSS probability/query date and KEV status/date. Without a CVE, use null.
- **Evidence strength:** E0–E3; weak evidence does not automatically make a potentially severe issue low risk.
- **Architecture:** describe scenario, impact, missing control; qualitative severity or null, CVSS null when unsuitable; use the risk register.

`combine_scores: false`: no CVSS×EPSS×confidence, weighted average, or custom total. CVSS measures severity, EPSS estimates published-CVE exploitation in the next 30 days, KEV records known exploitation. Priority is a policy lookup.

## 5. P0–P3 and SLAs

| Priority | Meaning | Remediation / triage |
|---|---|---|
| P0 | Active compromise/leak or live privileged production secret | Immediate human incident response; zero days |
| P1 | Confirmed high/critical, applicable exposed KEV, major authorization/release trust failure | Fix or time-limited compensating control within seven days; assign/triage within one business day |
| P2 | Confirmed medium | Fix within 30 days; other pending triage within five business days |
| P3 | Low/hardening | Review/action within 90 days; triage within five business days |

Due date = creation time + configured SLA. Pending priority is a candidate and labeled so; refuted findings have null priority. Stricter company rules prevail.

Lookup inputs: validation, severity, KEV, exposure (public/partner/internal; missing model defaults conservatively to public), verified live privileged production secret, and human-confirmed compromise. Refuted findings are excluded. Otherwise prioritize live secrets/compromise P0; exposed KEV, confirmed high/critical, confirmed authorization/release-trust flaws P1; pending high/critical/KEV P1 candidate; medium P2/candidate; low/info/hardening P3. Evidence grade is not a downgrade factor: an E1 critical candidate still needs rapid triage.

## 6. Finding fields

`schemas/finding.schema.json` rejects additional fields; include required fields and nulls where appropriate. The annotated example above illustrates:

- `id`: `VS-YYYYMMDD-<8 hex>` based on rule/path/line/commit; `gate`: G0–G6; `rule_id`: VibeSec or prefixed native rule.
- `title`/`description`: concrete issue and scenario; catalog-only control/CWE, optional CVE.
- Separate severity/CVSS/EPSS/KEV, evidence/validation, trusted `policy_tier`, priority/owner/due date.
- `location`: kind, path/lines, package/version, URL, commit.
- `evidence_refs`: kind, path/URL, digest, expected-versus-actual note; model reviews are distinct from HTTP/code evidence.
- `review`: all role/provider/family/model/prompt-version/round/verdict/rationale/minority opinions, human-required status, decision and ruling reference.
- `retest_result`, source/tool/rule/advisory/query provenance, creation time, preconditions/limitations.

The example describes account B reading A's order 1001 at `/orders/{id}`, missing owner filtering, high severity, E3/confirmed, blocking/P1, team-orders owner and seven-day due date. Its vector is `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`, score 7.1, with null CVE/EPSS/KEV. Opinions cite the order route; manual replay supports confirmation. Treat sample values as examples, not actual findings.

Dependency findings use kind dependency with package/version, the actual advisory CVE when available, queried signals/dates, and an official advisory URL. Secret findings include only masks/fingerprints; raw credentials must never enter reports.

## 7. SARIF 2.1.0 mapping

Export code/dependency/config findings, one run per tool:

| Finding | SARIF |
|---|---|
| rule_id | result.ruleId and driver.rules[].id |
| title / description | shortDescription.text / result.message.text |
| severity | critical/high→error, medium→warning, low/info→note; preserve original property |
| cvss_score | rule properties.security-severity |
| cwe | external/cwe tags and taxonomy relationships |
| path/start/end line | physicalLocation URI and region |
| package/version | logical fullyQualifiedName as purl |
| id | fingerprints[vibesec/id]; stable partial fingerprint = hash(rule_id+path) |
| evidence grade, validation, tier, priority, controls/CVE/signals/vector/gate | result.properties `vibesec/<field>` |
| evidence references | related locations for code, attachments for native/HTTP artifacts |
| source tool/version/rule version | driver fields and rule property |
| review opinions | findings.json only |
| commit | versionControlProvenance revisionId |

## 8. Risk register

Store architecture/prompt findings and open modeled threats in `reports/risk_register.json`, with generation time/project/commit/tier; each risk's finding/gate/control, attack scenario, impact, missing control, MAESTRO layer, evidence/validation/priority, owner/due date/status, and trifecta state. Example: a generic support agent can execute arbitrary production SQL without an allowlist/HITL. Architectural risks use scenario-based explanation, not fabricated CVSS; priority still follows the policy lookup.

## 9. Coverage

Per-control states: pass (tested/no finding), fail (tested/active finding), pending (unresolved conclusion), untested (missing tool/time/token/outside diff), not_applicable (design-based reason required).

```text
coverage_ratio = (pass + fail) / (pass + fail + pending + untested)
```

Exclude not-applicable controls from the denominator. Report all 14 domains separately so easy passes cannot hide authorization failures. Coverage failure and gate blocking are distinct: final gate status also applies policy tiers and required-tool completeness. Do not infer security from a high aggregate percentage.

## 10. Retesting

Use a new commit/digest, rerun the original failing case and safe controls, and record fixed/still_present/regressed. Fixed requires equivalent-strength evidence, not merely changed code. Match stable rule/path fingerprints to detect regressions, restore the original priority, and note the regression commit. Before retesting use not_retested; refuted findings use null. Update the same finding ID and append historical evidence rather than creating a replacement finding.
