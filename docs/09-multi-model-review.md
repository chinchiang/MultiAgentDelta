
[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# 09 — 多模型審查：Provider 抽象、四個角色、輪次規則與 14 領域覆蓋矩陣

> 傳統資安控制是審查主體；多模型是提升覆蓋率、降低共同盲點的手段，不是裁判。本文件定義 harness agent 把發現送審時的 provider 介面、角色分工、輪次協定、資料駐留與失敗處理。對應 `vibesec.yaml` 的 `review.*` 區塊與 `config/providers.yaml`。

## 1. Provider 抽象

所有模型呼叫都經過同一個介面，harness 與 reviewer 角色不知道背後是哪家：

```python
def complete(messages: list[Message], json_schema: dict, temperature: float = 0) -> dict:
    """回傳符合 json_schema 的 dict；不符合 → raise SchemaViolation，計為 provider error。"""
```

- `messages`：`[{"role": "system", "content": <角色提示>}, {"role": "user", "content": <審查包>}]`。
- `json_schema`：角色輸出契約（§3）；provider 若支援 JSON mode / structured output 就啟用，不支援則在回應後以 schema 驗證，驗證失敗重試一次後記 error。`scripts/review_provider.py` 依審查包判斷契約：`output` 要 `{"opinions", "general"}` 者為 G4 審查摘要，否則為 §3 的單一 opinion；回應不是 JSON 或不符契約時重試一次，再不符記 `error`，不替模型改寫格式。重試時在原審查包後附上「上一次哪裡不符、應回什麼形狀」；temperature 0 下送出同一份內容只會得到同一個回應，不附說明的重試沒有意義。被拒絕的回應原樣保存在輸出的 `rejected_attempts`（不採用，只供稽核）。
- `temperature` 固定 `0`，讓同一 `prompt_version` 下的輸出可比較。

五個 `family`：`anthropic`、`openai`、`google`（Gemini）、`glm`、`deepseek`（`schemas/finding.schema.json` 另允許 `fake` 供 evals 用）。`family` 是「同一基礎模型血統」的標籤；同一 family 的兩個 provider（例如雲端 OpenAI 與地端 vLLM 跑的 OpenAI 系開源模型）**不算**兩個 family。

`config/providers.yaml` 每個 provider 的欄位：

| 欄位 | 用途 |
|---|---|
| `family` | 計算「至少兩個 family」時的鍵 |
| `kind` | `anthropic`（Messages API）或 `openai_compatible`（Chat Completions 相容端點） |
| `base_url` | 端點；地端 provider 指向內網 |
| `api_key_env` | 金鑰環境變數名；harness 只讀環境變數，不接受明文 |
| `model` | 預設模型；標 `確認可用版本` 者啟動前要盤點 |
| `timeout_seconds` / `max_tokens` / `temperature` / `json_mode` | 呼叫參數 |
| `allowed_data_classes` | 可接收的資料分級（`public / internal / confidential / pii`），見 docs/08 §12 |
| `enabled` | 停用但保留設定 |

`rotation:` 區塊定義角色 → 偏好 family 順序、`high_risk_min_families: 2`、fallback 順序。

## 2. 四個審查角色

角色依專案適用性啟用（`review.roles`），不等於每個發現都要四個角色、也不等於每個角色都要四個模型。

| 角色 | 範圍（對應 §6 領域） | 輸入 | 可以下的結論 | 不可以下的結論 |
|---|---|---|---|---|
| `architecture` | 應用架構、資料可信度與完整性、AI/Agent 安全（架構面）、Insecure error handling（fail-open） | 威脅模型、DFD、元件清單、G4 靜態檢查結果、相關檔案 | 攻擊路徑是否成立、控制缺口在哪、是否為「程式缺陷」或「縱深防禦缺口」 | 不得給 CVSS 分數（架構缺口不硬編分數）；不得宣稱「無其他風險」 |
| `appsec` | 一般安全弱點、XSS、CSP、Input validation、Insecure error handling（洩漏） | Semgrep / CodeQL 告警、ZAP 結果、程式片段（source→sink 路徑） | 告警是否為真（confirm/refute）、提議 CWE 與 CVSS 向量（待人工確認） | 不得以「有 CSP」反駁 XSS；不得以「缺 CSP」宣稱可利用 XSS |
| `identity-authz` | Authentication、Authorization、Secret exposure（憑證生命週期）、AI/Agent 安全（工具越權、HITL） | 路由與 middleware、owner_binding 檢查結果、RLS 設定、G5 雙帳號結果、Agent tool allow-list | BOLA/IDOR 是否成立、授權是否只靠單層 middleware、工具是否過度暴露 | 不得以前端有隱藏按鈕當作授權存在；未有雙帳號實測前不得把 BOLA 標 E3 |
| `supplychain-cicd` | Dependency security、建置與發布供應鏈、GitHub Actions security | SBOM、grype/trivy 結果、lockfile diff、workflow 檔案、registry 查詢結果、冷卻期計算 | 套件是否幻覺 / 相似名、CVE 是否可達、workflow 是否存在「不可信輸入 → 高權限工作」路徑 | 不得只看到 `pull_request_target` 就判漏洞；不得以 SBOM / 簽章存在宣稱無漏洞 |

## 3. 角色輸出 JSON

每次呼叫回傳一個 opinion，欄位對齊 `schemas/finding.schema.json` 的 `review.opinions[]`，再加上兩個「提議」欄位：

```json
{
  "role": "appsec",
  "provider": "anthropic-cloud",
  "family": "anthropic",
  "model": "claude-sonnet-5-5",
  "prompt_version": "appsec@2026-10-03.1",
  "round": 1,
  "verdict": "confirm | refute | uncertain",
  "rationale": "具體說明，必須引用 file:line 或 HTTP exchange",
  "cited_evidence": [
    {"kind": "code_excerpt", "ref": "app/routers/orders.py:42-47"},
    {"kind": "tool_output", "ref": "reports/raw/G3/semgrep.sarif#results[3]"}
  ],
  "proposed_control_id": "ASVS5-V1.2 | null",
  "proposed_cwe": "CWE-89 | null",
  "proposed_cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N | null",
  "defect_kind": "code_defect | defense_in_depth_gap | not_a_defect",
  "minority": false
}
```

規則：

- `proposed_control_id` / `proposed_cwe` **只能是 harness 隨審查包附上的 catalog 片段內的 ID**（`review.ids_from_catalogs_only: true`）。harness 收到不在 catalog 的 ID 一律改 `null` 並在 `notes` 記「reviewer proposed CWE-xxx not in catalog」。
- `cited_evidence` 為空時，`verdict` 只能是 `uncertain`。
- `verdict: confirm` 不會自動把 finding 設為 `confirmed`；它只是意見。`validation_status` 由 harness 依 docs/10 §2 規則與人工裁決決定。
- 模型輸出的任何「信心百分比」欄位會被丟棄，不寫入 finding（§8）。
- `cited_evidence`、`proposed_*`、`defect_kind` 寫入 `evidence_refs[]`（kind `model_review`）與 `notes`，`review.opinions[]` 只保留 schema 定義的欄位。

## 4. 輪次協定

```
Round 1（獨立）     每個啟用角色 × 每個指派 provider 各呼叫一次；
                    審查包內容相同，但不含任何其他模型的意見。
      │
      ▼  harness 比對 verdict
  全部一致 ───────────────────────────────▶ 結束，寫入 opinions[]
  有分歧或任一 uncertain
      │
      ▼
Round 2（交叉質疑 1） 每個 provider 收到其他 provider 的 rationale 與 cited_evidence（匿名化，只標 family），
                    被要求「反駁或接受，並指出對方未引用的證據」。
      │
      ▼
  一致 ──▶ 結束
  仍分歧
      │
      ▼
Round 3（交叉質疑 2） 同上，最後一輪。
      │
      ▼
  仍分歧 ──▶ requires_human: true；所有意見保留，少數方 minority: true
```

硬規則（來自 CLAUDE.md 第 6 條與 `vibesec.yaml review.*`）：

1. **第一輪不交換**（`round1_independent: true`）：審查包不含任何模型意見、也不含工具以外的「初步結論」。確保共同盲點可被量測。
2. **最多兩輪交叉**（`max_cross_rounds: 2`），`round` 欄位 1–3。
3. **保留少數意見**（`keep_minority_opinions: true`）：最終輪與多數不同者 `minority: true`，不刪除、不覆寫；`summary.md` 的 requires_human 區塊列出。
4. **不多數決**（`majority_vote: false`）：三個 confirm 一個 refute，finding 仍是 `pending` + `requires_human: true`。多數決會讓同質模型的共同錯誤變成「共識」。
5. **一致也不等於確認**：全員 `confirm` 只能把 finding 從 E1 升到 E2（有直接支持）；要到 E3 需可重現測試或人工核對（docs/10 §1）。
6. **uncertain 是合法答案**：角色提示明確鼓勵「不確定就說不確定」；`uncertain` 不計入任何一方。

## 5. 高風險控制與 family 門檻

`review.min_families_for_high_risk: 2`。以下任一成立即為**高風險**，必須有至少兩個不同 family 的 round-1 意見才可離開 `pending`：

- `policy_tier: blocking` 的發現（含 `tier_overrides` 升級後）。
- 依 docs/10 §5 查表為 P0 / P1 候選者（例如 severity critical/high、KEV 命中、公開暴露）。
- 所有 Authorization 類控制（BOLA/IDOR、跨租戶、單層 middleware、RLS、Agent 工具越權）。
- 供應鏈「發布信任」類控制（registry 信任、產物簽章、provenance、Actions 高權限工作、幻覺 / 冷卻期套件）。

非高風險發現可只用一個 family，但角色提示相同、`prompt_version` 照記。

## 6. 輪替與成本政策

- 角色 → 偏好 family 在 `providers.yaml rotation.roles` 定義（例如 `appsec: [anthropic, openai]`、`supplychain-cicd: [openai, deepseek]`）。第一個可用且資料分級允許者為主、第二個為第二 family。
- 每個發現的審查呼叫上限：`角色數 × 2 family × 3 round`。超過 `review.budget`（若設定）→ 剩餘發現 `pending`，`notes` 記 `review budget exhausted`，**不得**為省錢改用單 family 放行高風險控制。
- 審查包只送 diff 周邊 ±40 行與被引用的檔案，不送整個 repo；G4 架構審查送威脅模型與元件清單。由 `scripts/review_packet.py` 從受測 commit 產生：full 範圍附威脅模型全文與其以 `path:line` 引用的檔案，diff 範圍附每個變更 hunk 前後 40 行；內容先經 gitleaks 掃描並遮罩命中字串，gitleaks 缺席或超過大小上限就不產生（不截斷）。
- 同一 `rule_id + path` 在 30 天內已有 E3 人工裁決 → 不重送，沿用舊裁決並標 `retest_result`。
- 地端 provider 不計 token 成本但計時間；`timeout_seconds` 到期即 error。

## 7. Prompt 版本

每個角色提示檔（`config/harness/roles/<role>.md`）頂端有 `prompt_version: <role>@<YYYY-MM-DD>.<n>`。harness 呼叫時把它寫入 opinion 的 `prompt_version`。evals（`docs/12`）比較不同版本的召回 / 精確率時以此分組；held-out 案例不得用於調整提示。提示變更走 PR，與政策變更一樣由人類決定。

## 8. 14 領域覆蓋矩陣與角色歸屬

| # | 審查領域 | 必查內容 | 驗證方式 | 主責角色 | 主要閘門 |
|---|---|---|---|---|---|
| 1 | Application architecture | 資料流、信任邊界、攻擊面、租戶隔離、服務權限、敏感資料生命週期、故障時安全性、復原能力 | 對照架構文件、實際程式與部署設定，建立攻擊路徑及控制缺口 | architecture | G0、G4 |
| 2 | 一般安全弱點 | SQL／NoSQL／命令／範本注入、SSRF、路徑穿越、不安全反序列化、檔案上傳、CSRF、業務邏輯與競態 | 靜態分析、資料流追蹤、隔離環境的負面測試 | appsec | G3、G5 |
| 3 | XSS | Reflected、Stored、DOM XSS；輸出情境編碼、危險 DOM 操作、富文字清理 | 追查輸入至輸出位置，使用瀏覽器確認執行行為與防護 | appsec | G3、G5、G6 |
| 4 | CSP | 實際回應標頭、Enforce／Report-Only、nonce／hash、寬鬆來源、危險指令、頁面覆蓋 | 檢查有效政策及瀏覽器行為，確認阻擋效果和功能相容性 | appsec | G5 |
| 5 | Authentication | 密碼儲存、MFA、登入節流、帳號復原、Session、Cookie、JWT、OAuth／OIDC、登出撤銷 | 帳號生命週期測試、失效 Token、Session 固定與撤銷測試 | identity-authz | G3、G5 |
| 6 | Authorization | 物件、功能、欄位層級授權；IDOR／BOLA；水平／垂直越權；跨租戶存取 | 建立角色×資源×操作矩陣，以兩個租戶及不同角色測試 | identity-authz | G4、G5 |
| 7 | Dependency security | 直接及間接依賴、實際版本、lockfile、已知漏洞、停止維護、惡意套件及套件來源 | 套件組成分析、SBOM、公告比對、適用性與可達性確認 | supplychain-cicd | G1 |
| 8 | 建置與發布供應鏈 | Registry 信任、依賴混淆、安裝腳本、基底映像、建置隔離、產物簽章、來源證明、發布權限 | 核對來源、版本／digest、建置紀錄、簽署身分及產物一致性 | supplychain-cicd | G1、G3 |
| 9 | GitHub Actions security | Token 最小權限、第三方 Action 固定完整 SHA、不可信 PR、腳本注入、OIDC、Runner 隔離、快取／產物污染、部署審批 | 分析 workflow 與呼叫鏈；以受控事件測試權限邊界 | supplychain-cicd | G3 |
| 10 | Secret exposure | 原始碼、Git 歷史、設定、日誌、建置產物、前端 bundle、容器層中的憑證 | 祕密掃描、來源追蹤及擁有者確認；報告只保留遮罩與指紋 | identity-authz | G2 |
| 11 | Input validation | 伺服器端型別、長度、範圍、正規化、重複參數、Mass Assignment、檔案及 URL 驗證 | 邊界值、畸形輸入、編碼變體、Schema 與業務約束測試 | appsec | G3、G5 |
| 12 | Insecure error handling | 堆疊／SQL／Token 洩漏、帳號枚舉、Fail-open、交易回復、日誌注入及敏感資料記錄 | 注入逾時、依賴故障及例外，檢查回應、權限與日誌 | appsec（洩漏）／architecture（fail-open） | G3、G5 |
| 13 | 資料可信度與完整性 | 外部輸入來源、Webhook 簽章、重放、資料竄改、匯入來源、下游過度信任 | 簽章與時間驗證、重放測試、資料來源和完整性追蹤 | architecture | G4、G5 |
| 14 | AI／Agent 安全 | Prompt injection、工具越權、RAG／記憶污染、敏感資料外傳、代理間信任傳遞 | 惡意文件與工具回應測試，驗證執行器強制權限 | architecture（信任傳遞）／identity-authz（工具越權） | G4、G6 |

未使用 GitHub 的專案：第 9 列記 `not_applicable`，理由寫明實際 CI 平台並改查該平台的對應控制。

## 9. 三個判定原則

1. **有 CSP 不代表沒有 XSS；缺少 CSP 也不直接等於可利用 XSS。** XSS 是程式缺陷（`defect_kind: code_defect`，查 source→sink），CSP 是縱深防禦（`defense_in_depth_gap`）。兩者各開一個 finding、各自評分；appsec 角色不得用其中一個反駁另一個。
2. **`pull_request_target` 不直接等於漏洞。** supplychain-cicd 必須追出完整路徑：不可信輸入（fork PR 的程式碼、PR 標題、issue 內容）→ 被 checkout 或插入 `run:` → 具 `secrets` 或 `contents: write` 權限的 job。缺任一環 → `uncertain` 或 `refute`，並列出缺的那一環。
3. **SBOM / 簽章 / provenance 不保證無漏洞。** SBOM 是元件清單，簽章與 provenance 是來源證據。supplychain-cicd 不得因「有 SBOM、有 cosign 簽章」就 `refute` 一個 CVE 發現；要看版本是否在受影響範圍、程式路徑是否可達。

## 10. 模型自評信心不是什麼

模型回答「95% 確定」**不是**：證據（不寫入 `evidence_refs`）、證據等級（不影響 E0–E3）、驗證狀態（不影響 pending/confirmed/refuted）、嚴重度（不影響 CVSS）、優先序（不影響 P0–P3）、也不是多數決的權重。harness 在解析 opinion 時直接丟棄任何 `confidence` 類欄位。能提升證據等級的只有：可引用的程式 / 設定 / HTTP 證據、可重現的測試、人工核對。

## 11. 失敗處理

| 情況 | 處置 |
|---|---|
| provider 連線失敗 / 5xx / timeout / schema 驗證兩次失敗 | 該 (role, provider, round) 的 opinion **缺席**；不補假意見，不由同 family 的另一 provider 冒充第二 family |
| 缺席後高風險控制的 family 數 < 2 | finding `validation_status: pending`、`requires_human: true`、`notes` 記 `only N family reachable`；該控制在 gate `coverage[]` 標 `pending`；閘門 `status: incomplete`，`status_reason` 寫明哪個 provider 失敗 |
| 缺席但 family 數仍 ≥ 2 | 正常結束輪次，`notes` 記缺席 |
| 資料分級無允許 provider | 同上 pending + incomplete；不得降級資料分類（docs/08 §12） |
| 模型回傳 catalog 外的 ID | 改 `null` + `notes`；不影響 verdict |
| 模型回傳 `confirm` 但 `cited_evidence` 為空 | 視為 `uncertain` |
| 審查預算用盡 | 剩餘高風險發現 `pending` + 閘門 `incomplete`；低風險發現保留工具結果、不送審，`notes` 記原因 |

任何情況下，審查失敗都不會把 finding 變成 `refuted`，也不會把閘門變成 `pass`。

## 12. 人工裁決（requires_human 的收斂）

分歧或 family 不足的發現停在 `pending` + `requires_human: true`，直到有人用**固定格式**裁決。格式見 `schemas/human-ruling.schema.json`，範例見 `docs/templates/human-ruling.example.yaml`，工具是 `scripts/ruling.py`。

**流程**

1. harness 產出 `reports/findings.json` 與 `summary.md` 的「需人工裁決」區塊。
2. `python3 scripts/ruling.py request <finding_id>` 產生一則可直接貼在 PR 的「請求裁決」留言：列出全部意見（含少數方）與裁決者要做的事。
3. 裁決者重放或人工核對證據，複製範例為 `rulings/<finding_id>.yaml` 填寫，**逐一回應每則少數意見**。
4. `python3 scripts/ruling.py check rulings/<finding_id>.yaml` 通過後開 PR，**由另一位人員審查**；PR 就是稽核軌跡（誰、何時、依據什麼）。
5. 合併後 harness 執行 `ruling.py apply`，把結果寫回 findings.json。

**規則（`ruling.py` 強制，違反即退出碼 1）**

| 規則 | 理由 |
|---|---|
| `decided_by.type` 必須是 `human`，handle／role 不得是模型或 bot | 模型不能裁決模型（CLAUDE.md #6） |
| `confirm` 的 basis 只能是 `reproduced` 或 `manual_review`，且附 ≥ 1 筆非 `model_review` 的證據 | 模型共識不是依據；一致最多 E2（§4 第 5 點） |
| 每則 `minority` 意見都必須在 `minority_acknowledged[]` 回應（`accepted`／`rejected` + 說明），也不能列出不存在的 | 少數意見不得被默默忽略 |
| `refute` 不得以 `insufficient_evidence` 為依據；證據不足請 `defer` | 沒證據不等於誤報 |
| `defer` 必填 `next_review_by`，結果維持 `pending` + `requires_human: true` | defer 不是通過；incomplete ≠ pass |
| 只有 `requires_human: true` 的 finding 可被裁決；同一 finding 不可重複 apply | 避免覆蓋既有裁決 |
| `apply` 只改 `validation_status`、`evidence_grade`（confirm → E3）、`review.requires_human`、`review.human_decision`、`review.ruling_ref`，並追加裁決證據 | 不改嚴重度、CVSS、policy_tier、priority，也不刪除或改寫任何模型意見 |

裁決不能降低 `policy_tier`。要把 blocking 降為 advisory 屬於政策變更，須由人類在獨立 PR 修改 `config/policy/blocking-policy.yaml`（CLAUDE.md #1）。



---

<a id="english"></a>

# 09 — Multi-Model Review: Providers, Roles, Rounds, and 14 Domains

Traditional security controls remain the basis of review. Model diversity aims to improve coverage and reduce shared blind spots; models are not final adjudicators. This protocol implements `review.*` and `config/providers.yaml`.

## 1. Provider interface

`complete(messages, json_schema, temperature=0) -> dict` must return schema-valid JSON or a provider error. Messages contain role system prompts and the user review packet. Use structured output when supported; otherwise validate afterward. `review_provider.py` selects a G4 `{opinions, general}` contract when requested, otherwise the single-opinion contract below. Retry invalid JSON/schema once with explicit correction feedback; never silently rewrite model output. Preserve rejected attempts for audit, masking credentials throughout. Temperature is fixed at zero for comparable prompt versions.

Families: anthropic, openai, google/Gemini, glm, deepseek; `fake` is evaluation-only. Two providers sharing a base-model lineage still count as one family, including cloud/local deployments.

Provider fields: family, API kind (Anthropic Messages or OpenAI-compatible Chat Completions), base URL, environment-key name, exact model, timeout/max tokens/temperature/JSON mode, allowed data classes, enabled flag. Inventory uncertain model versions before running. `rotation` sets role preferences, fallback order, and minimum two high-risk families.

## 2. Four roles

| Role | Inputs / scope | Permitted judgment / limits |
|---|---|---|
| architecture | Threat model, DFD, components, G4 evidence/code; trust, integrity, agent architecture, fail-open | Trace attack paths/control gaps and distinguish code flaws from missing defense layers. Do not invent CVSS or declare no other risks. |
| appsec | Semgrep/CodeQL/ZAP and source-to-sink excerpts; injection, XSS, CSP, validation, error leakage | Confirm/refute alerts and propose catalog CWE/CVSS vectors for human review. CSP neither disproves XSS nor proves exploitability by its absence. |
| identity-authz | Routes/middleware, owner filters, RLS, two-account evidence, tool lists; authentication/authorization/credential lifecycle/HITL | Evaluate BOLA/IDOR, tenant boundaries, middleware dependence, tool scope. UI hiding is not authorization; no E3 BOLA without dynamic proof. |
| supplychain-cicd | SBOM/scanners/locks/workflows/registry/cooldown | Evaluate hallucinations, CVE applicability, and untrusted-input-to-privileged-job paths. Event names alone do not prove flaws; SBOM/signatures do not prove absence of vulnerabilities. |

Enable roles according to scope; not every finding needs all roles or every model.

## 3. Opinion contract

Each response records `role`, `provider`, `family`, `model`, `prompt_version`, `round` (1–3), `verdict` (`confirm`, `refute`, `uncertain`), evidence-citing `rationale`, `cited_evidence`, proposed control/CWE/CVSS vector, `defect_kind` (`code_defect`, `defense_in_depth_gap`, `not_a_defect`), and `minority`.

- Proposed IDs must exist in supplied catalog excerpts; replace unknown IDs with null and note the rejection.
- No cited evidence means uncertain.
- A model's confirm is an opinion, not finding validation.
- Discard confidence percentages.
- Persist only schema-defined fields inside `review.opinions[]`; store proposals/citations/defect kind in model-review evidence/notes.

## 4. Rounds

1. **Independent first round:** each assigned role/provider receives the same facts, no other model opinions or non-tool preliminary conclusions.
2. If disagreement or uncertainty remains, **challenge round 1:** provide other rationales/citations, anonymized except family, and request evidence-based rebuttal/acceptance and overlooked evidence.
3. If still needed, **challenge round 2:** final round.

Stop early on agreement but retain every opinion. Final dissent is `minority: true`; do not delete/overwrite it. **Never majority-vote:** three confirms and one refutation still require human adjudication. Agreement supports at most E2 with direct evidence; E3 needs reproduction/human verification. Uncertain is legitimate and is not a vote for either side.

## 5. High-risk family threshold

At least two distinct families' first-round opinions are required for:

- Blocking findings, including tier overrides.
- P0/P1 candidates, high/critical severity, applicable KEV/high exposure.
- All authorization controls: BOLA/IDOR, tenant isolation, middleware, RLS, agent permissions.
- Release-trust controls: registries, signatures/provenance, privileged CI, hallucinated/young packages.

Lower-risk review may use one family with the same prompt/version discipline. Missing actual families leave high-risk review pending.

## 6. Rotation and cost

Use the first available, classification-eligible preferred family, then a distinct second. Maximum calls per finding: role count × two families × three rounds. Exhausted budget leaves remaining high-risk findings pending/incomplete; do not silently approve with one family.

`review_packet.py` builds packets from the tested commit: diff hunks ±40 lines and cited files; full architecture packets include the model and referenced path:line files. Scan/mask content with Gitleaks before sending. Missing Gitleaks or oversize content stops packet creation; do not truncate away context. Reuse an applicable E3 human ruling for the same rule/path within 30 days only with explicit retest tracking. Local providers still consume time; timeout remains error even without token billing.

## 7. Prompt versions

Each role file declares `prompt_version: <role>@<YYYY-MM-DD>.<n>`; record it in every opinion and group evaluation results by version. Do not tune on held-out cases. Prompt changes are reviewed through PRs under human governance.

## 8. Fourteen-domain coverage matrix

| Domain | Required review / verification | Owner / gates |
|---|---|---|
| Application architecture | Flows, boundaries, attack surface, tenants, privileges, sensitive-data lifecycle, fail safety/recovery; compare docs/code/deployment and trace attacks | architecture; G0/G4 |
| General weaknesses | SQL/NoSQL/command/template injection, SSRF, traversal, deserialization, uploads, CSRF, business logic/races; taint and isolated negative tests | appsec; G3/G5 |
| XSS | Reflected/stored/DOM, context encoding, unsafe DOM, rich-text sanitization; trace and verify browser execution | appsec; G3/G5/G6 |
| CSP | Actual headers, enforced/report-only, nonce/hash, broad sources/unsafe directives, page coverage; browser blocking and compatibility | appsec; G5 |
| Authentication | Passwords, MFA, throttling, recovery, sessions/cookies/JWT/OAuth/OIDC/logout; lifecycle, invalid tokens, fixation/revocation | identity-authz; G3/G5 |
| Authorization | Object/function/field scope, horizontal/vertical escalation, tenants; role×resource×operation matrix across two tenants/roles | identity-authz; G4/G5 |
| Dependencies | Direct/transitive actual versions, locks, CVEs, maintenance, malicious sources; SBOM/advisory/applicability/reachability | supplychain-cicd; G1 |
| Build/release supply chain | Registry trust/confusion, hooks, base images, build isolation, signatures/provenance/release privileges; identities/digests/artifact consistency | supplychain-cicd; G1/G3 |
| GitHub Actions | Least privilege, full SHA pins, untrusted PR/script injection, OIDC, runners, cache/artifacts, deployment approval; complete call-chain/event tests | supplychain-cicd; G3 |
| Secret exposure | Code/history/config/logs/artifacts/frontend bundles/container layers; scan/trace/owner verification, masked evidence only | identity-authz; G2 |
| Input validation | Server-side types/length/ranges/normalization/duplicate params/mass assignment/files/URLs; boundary/malformed/encoded/schema/business tests | appsec; G3/G5 |
| Error handling | Stack/SQL/token leakage, enumeration, fail-open, rollback, log injection; inject timeout/dependency/exception failures | appsec for leakage, architecture for fail-open; G3/G5 |
| Data trust/integrity | Webhook signatures/replay/tampering/import provenance/downstream trust; signatures/time/replay/source tracing | architecture; G4/G5 |
| AI/agent security | Prompt injection, tools, RAG/memory poisoning, exfiltration, inter-agent trust; malicious documents/tool responses and executor-enforced permissions | architecture/identity-authz; G4/G6 |

If GitHub is unused, mark its domain not applicable with the actual platform and inspect equivalent controls there.

## 9. Three judgment principles

Treat XSS code defects and CSP defense gaps separately. Trace `pull_request_target` from untrusted fork code/title/body through checkout/shell use to secrets/write privileges; a missing link means uncertain/refute with explanation. SBOMs enumerate components; signatures/provenance establish origin, not vulnerability absence—check affected versions and reachability.

## 10. Confidence is not evidence

“95% certain” affects neither evidence, grade, validation, severity, priority, nor voting weight. Discard confidence fields. Only traceable code/configuration/HTTP artifacts, reproducible tests, and human verification strengthen evidence.

## 11. Failure handling

Provider connection/5xx/timeout/two schema failures mean the opinion is absent, never fabricated or replaced by another same-family provider masquerading as diversity. Fewer than two high-risk families means pending, human required, pending coverage, incomplete gate, and named failure reasons. If enough families remain, complete with missing-provider notes. No eligible data destination has the same pending/incomplete outcome; never downgrade classification. Unknown IDs become null; unsupported confirms become uncertain. Budget exhaustion preserves low-risk tool findings and explains unreviewed work. Review failure never refutes a finding or passes a gate.

## 12. Human adjudication

Use `schemas/human-ruling.schema.json`, its template, and `scripts/ruling.py`:

1. Harness writes findings and the human-required summary.
2. `python3 scripts/ruling.py request <finding_id>` renders a request containing all opinions, including dissent.
3. A human replays/checks evidence, writes `rulings/<finding_id>.yaml`, and responds to every minority opinion.
4. Run `ruling.py check`, submit a PR, and obtain another person's review. The PR records who/when/why.
5. After merge, `ruling.py apply` updates findings.

Enforced rules (violation exits 1): human identity only; confirm requires reproduced/manual_review basis and at least one non-model evidence item; each and only actual minority opinion must be accepted/rejected with rationale; insufficient evidence means defer, not refute; defer requires `next_review_by` and retains pending/human-required; only unresolved human-required findings can be adjudicated, once. Apply changes validation, evidence grade (confirm→E3), human decision/ruling reference, and appends evidence. It never changes severity/CVSS/policy/priority or removes model opinions. Policy demotion requires a separate human policy PR.
