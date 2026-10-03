# 00 總覽 — Vibe Coding 六道資安閘門（G0–G6）

> 讀者：DevOps / 平台、AppSec / 治理、Red Team，以及驅動整條管線的 harness agent。
> 本文回答三件事：AI 生成程式碼為什麼壞、壞在哪一層、哪一道閘門負責擋。各閘門細節見 `docs/01`–`docs/07`。

## 1. 為什麼需要閘門：Vibe Coding 把三道把關壓成一道

傳統交付有「人類撰寫 → 同儕審查 → 測試」三道把關。Vibe Coding（開發者依賴 AI 產生程式碼並「全部接受」）把前兩道壓掉，只剩測試。Stanford Perry 等人（ACM CCS 2023）的受控實驗顯示：使用 AI 助手的受試者寫出**更不安全**的程式碼，卻**更相信**其安全。VulDetectBench 則指出 LLM 對「有沒有漏洞」的二元判斷約 80%，但定位根因的能力 **< 30%**。兩個數字合起來的結論是：

1. 測試必須變成 CI/CD 中**不可繞過**的閘門（CLAUDE.md 規則 1）。
2. AI 審查只能當**輔助分流層**，確定性工具與人工裁決才是主體（`docs/09-multi-model-review.md`）。

## 2. 四大病徵 → 閘門映射

| 病徵 | 數據與案例 | 根因（對抗成因） | 負責閘門 | 代表規則 / CWE |
|---|---|---|---|---|
| **幻覺套件（Slopsquatting）** | 研究量測 LLM 推薦套件的幻覺率約 19.7%–20%，且 58% 的幻覺名稱會**重複出現**，攻擊者可預先搶註；Nx s1ngularity 與 Shai-Hulud npm 蠕蟲在 postinstall 階段呼叫本機 Claude / Gemini CLI 搜刮憑證 | 訓練資料偏差 + 模型對 Registry 無即時認知 | **G1** | `vibesec.g1.hallucinated-package`（CWE-1357）、`vibesec.g1.postinstall-egress`（CWE-506） |
| **硬編碼金鑰** | 啟用 AI 助手的儲存庫金鑰外洩率高 40%，6.4% 含外洩金鑰；AI 直接寫死 `sk-...`、生成 `.env` 卻不加 `.gitignore` | 範例程式碼模式複製；上下文破碎（不知道專案有祕密管理） | **G2** | `vibesec.g2.hardcoded-secret`（CWE-798）、`vibesec.g2.env-not-ignored`（CWE-538） |
| **靜態注入漏洞** | AI 偏好字串拼接 SQL / Command / HTML；Veracode 量測 AI 對 XSS 的防禦率僅 14%；CWE-79 為 MITRE 2025 CWE Top 25 第 1 名 | 訓練資料偏差（拼接範例遠多於參數化）+ 上下文破碎（跨檔污點看不見） | **G3** | `vibesec.g3.sql-string-concat`（CWE-89）、`vibesec.g3.command-injection`（CWE-78）、`vibesec.g3.xss-innerhtml`（CWE-79） |
| **前端防禦假象** | 授權只做在前端 UI，後端 API 缺 Session 驗證與 BOLA / IDOR 防護；Base44 案例以 `app_id` 當校驗依據，任何人可註冊進私有應用；CVE-2025-29927 Next.js 以 `x-middleware-subrequest` 繞過單層 middleware 授權（CVSS 9.1） | Agent 過度代理（只為「畫面能動」最佳化）+ 上下文破碎 | **G4**（白箱）+ **G5**（黑箱實證） | `vibesec.g4.missing-owner-filter` / `vibesec.g5.bola-cross-account`（CWE-639）、`vibesec.g4.single-middleware-authz`（CWE-287） |
| （延伸）**Agent 過度代理** | Replit AI Agent 刪除正式資料庫並生成 4000 筆假資料掩蓋（OWASP LLM06 Excessive Agency）；Lethal Trifecta（Simon Willison）：私有資料 + 不受信任內容 + 對外通訊三者同時成立即可被用來外洩 | 設計期沒有盤點 Agent 能力 | **G0**（設計期）+ **G4** / **G6** | `VS-G0-LETHAL-TRIFECTA`、`vibesec.g4.agent-tool-overexposure`（CWE-250）、`vibesec.g6.indirect-prompt-injection`（CWE-1427） |

## 3. 雙軌管線架構

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 設計期（Design time）                                                        │
│  [ G0 威脅建模 ]  四問 → STRIDE / LINDDUN / MAESTRO → DFD + 信任邊界            │
│                   → Lethal Trifecta 檢驗 → risk_tier L1/L2/L3 → 寫入 vibesec.yaml │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │ 決定下方閘門的啟用與深度
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 白箱 PR 階段（每次 commit / PR；diff-aware；目標 < 5 分鐘）                      │
│                                                                              │
│  G1 相依性與供應鏈 ──► G2 機密與金鑰 ──► G3 SAST 與 IaC ──► G4 架構與存取控制審查   │
│  (order: first；        (gitleaks 全歷史      (Semgrep taint /     (owner binding / RLS /  │
│   postinstall 會在       + pre-commit         Checkov / Trivy)      Agent tool allow-list / │
│   安裝瞬間執行)          + push protection)                        LLM 輔助審查 handoff)     │
│                                                                              │
│  工作流：.github/workflows/pr-gates.yml；夜間全量：nightly-full.yml（CodeQL）      │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │ 部署到 staging（VIBESEC_TARGET_URL）
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 黑箱 staging 階段（上線前；由外而內）                                            │
│                                                                              │
│  G5 DAST 與 API ─────────────────────► G6 LLM / Agent 紅隊                      │
│  (ZAP baseline / api-scan、雙帳號 BOLA、   (promptfoo redteam、garak；            │
│   JWT alg:none / 混淆、SSRF 169.254.169.254、 直接 / 間接注入、System Prompt 提取、  │
│   設定外溢、rate limit)                     AI 輸出 XSS、Denial of Wallet)        │
│                                                                              │
│  工作流：.github/workflows/staging-blackbox.yml；只能打授權靶場（CLAUDE.md 規則 8） │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ harness agent 彙整（.claude/skills/vibesec-harness；docs/08）                    │
│  gate-result.json ×7 → 多模型審查（四角色、≥2 家族）→ E0–E3 證據分級               │
│  → CVSS v4.0 / EPSS / KEV 分欄 → P0–P3 → reports/vibesec.sarif + findings.json    │
│    + risk_register.json + summary.md → 上傳 GitHub Code Scanning                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

狀態語意（`schemas/gate-result.schema.json`）：`pass / fail / pending / untested / not_applicable / incomplete`。工具缺席、逾時、API 失敗、缺帳號、缺文件、環境無法啟動 → `incomplete` 並寫 `status_reason`，**永遠不等於 pass**（CLAUDE.md 規則 2）。

## 4. 白箱 ↔ 黑箱雙向映射

兩軌不是獨立的兩張清單，而是互相驗證的閉環：

| 方向 | 流程 | 例子 |
|---|---|---|
| **白箱 → 黑箱：靜態缺陷 → 驗證可利用性** | G3 / G4 的靜態發現先記 `evidence_grade: E1`（工具告警）或 E2（有具體位置與路徑），`validation_status: pending`；harness 把對應的 G5 / G6 探針排進 staging 階段；黑箱重現成功 → E3 / `confirmed`，失敗 → 保留 pending 或 `refuted` 並記錄反證 | G4 `vibesec.g4.missing-owner-filter`（E2）→ G5 雙帳號以 `VIBESEC_TOKEN_B` 讀 A 的資源 → 200 → `vibesec.g5.bola-cross-account`（E3） |
| | | G3 `vibesec.g3.imdsv1-allowed`（Terraform）→ G5 對 URL 匯入端點送 `http://169.254.169.254/latest/meta-data/` → 回傳角色名 → `vibesec.g5.ssrf-metadata`（E3） |
| | | G3 `vibesec.g3.xss-innerhtml`（污點來源為 LLM 輸出）→ G6 promptfoo 誘導模型輸出 `<script>` → 前端渲染 → `vibesec.g6.stored-xss-via-ai-output` |
| **黑箱 → 白箱：動態發現 → 回頭定位根因** | G5 / G6 的 HTTP 證據（`evidence_refs.kind: http_exchange`）附上端點與參數；harness 以路由反查原始碼（Semgrep `--include` 該檔、`git log -S` 參數名），把 finding.location 從 `kind: http` 補成 `kind: code` 的 SARIF 位置；若找不到根因，保持 `kind: http` 並在 notes 標 `root_cause: unknown`，不猜 | G6 `system_prompt_extraction` 回傳含 `sk-ant-...` → 回頭觸發 G2 針對 prompt 模板檔做 gitleaks → `vibesec.g2.hardcoded-llm-key`，撤銷輪替 |
| | | G5 `debug_stacktrace` 回應洩漏 `app/routers/todos.py:42` → 直接把 SARIF 位置指到該行，並查該檔的 G3 結果 |

這個閉環也是 PLAN.md 的「工具掃描 → 隔離驗證 → 評分 → 人工裁決 → 修復後重測」流程在閘門層的實作。

## 5. 三大落地工程原則

### 5.1 分層阻擋（Blocking vs Advisory）

| 層 | 定義 | 例子 | 在 shadow / enforce 的行為 |
|---|---|---|---|
| **blocking** | 高確定性、可機器判定、修法明確 | 硬編碼金鑰、幻覺 / 冷卻期未滿 / 黑名單套件、未參數化 SQL、`alg:none`、雙帳號 BOLA 實證、KEV 命中、Agent 工具清單含 `execute_sql` | shadow：報告並標示「enforce 時會擋」；enforce：PR 檢查失敗（exit code 1） |
| **advisory** | 需人工判斷的架構 / 設計建議 | 缺 owner filter（可能本就是公開資源）、單層 middleware 授權、CORS 寬鬆、缺 rate limit、缺 HITL | 兩種模式都只報告；進 risk register 由 reviewer 裁決 |

政策檔：`config/policy/blocking-policy.yaml`。試點預設 `mode: shadow`；驗收後改 `enforce`。**任何人都不能為了讓檢查通過而把 blocking 降成 advisory**；要改政策只能由人類在獨立 PR 中決定（CLAUDE.md 規則 1）。

### 5.2 輸出標準化（SARIF）

- 所有程式位置類發現統一輸出 **SARIF 2.1.0**（`reports/vibesec.sarif`），上傳 GitHub Code Scanning / GitLab Security Dashboard，並以 `config/catalogs/cwe-map.yaml` 對照 CWE。
- 架構類發現（沒有單一程式位置）進 `reports/risk_register.json`。
- 每筆 finding 同時符合 `schemas/finding.schema.json`：`control_id`、`cwe`、`cve`、CVSS v4.0 向量、EPSS + 查詢日、KEV + 日期、`evidence_grade`、`validation_status`、`priority`、`owner`、`due_date`、`evidence_refs`、`retest_result` 分欄，**不混算**（CLAUDE.md 規則 4、5）。
- 工具原生規則保留原名並加前綴：`gitleaks:`、`semgrep:`、`trivy:`、`grype:`、`checkov:`、`zap:`、`promptfoo:`、`garak:`。

### 5.3 差異感知（Diff-Aware）

- PR 階段只掃變更（`diff_aware: true`：G1、G3、G4），目標數分鐘內完成；G2 例外（`diff_aware: false`，因為祕密可能藏在歷史）。
- 夜間 `nightly-full.yml` 跑 CodeQL 與全量掃描補齊跨檔 / 跨函式路徑。
- 指令層：`semgrep ci`（自動取 PR base）或 `semgrep --baseline-commit <merge-base>`；G1 只對 lockfile diff 新增的套件查 Registry。

## 6. 風險分級與閘門深度（摘要；細節見 docs/01）

| `risk_tier` | 定義 | 閘門 |
|---|---|---|
| L1 | 純內部、不含 LLM、不處理個資 | 重點 G1、G2（其餘 `not_applicable` 附理由） |
| L2 | 對外或處理業務資料的一般企業應用 | G1–G6 全開；G3 需跨檔污點；G5 需雙帳號 BOLA |
| L3 | 對外 + 個資 / 商業機密 + 高權限 Agent | G1–G6 深度加倍；正式威脅建模（ASVS 5.0 L3 明列）；委外滲透；商用 AI 紅隊平台；沙箱隔離 + HITL |

## 7. 責任歸屬

| 角色 | 負責閘門 | 具體責任 | 不負責 |
|---|---|---|---|
| **DevOps / 平台** | G1、G2、G3（CI 整合） | 把 `pr-gates.yml` / `nightly-full.yml` / `staging-blackbox.yml` 接進目標專案；維護 `config/slopsquat/*`、`config/gitleaks.toml`、`config/checkov/`；SBOM 產出與保存（EU CRA 要求）；確保工具版本固定且 `incomplete` 會被看見 | 判定 advisory 是否成立；修改 blocking 政策 |
| **AppSec / 治理** | G0、G4，以及整體政策 | 主持 G0 威脅建模與 `risk_tier` 決定；維護 `config/policy/blocking-policy.yaml` 與 `config/catalogs/`；審核 `config/slopsquat/allowlist.yaml` 例外；人工裁決多模型分歧（`requires_human: true`）；對齊 ASVS 5.0 / NIST AI RMF / ISO 27001 / EU CRA / CSL-DSL-PIPL | 代替開發者修程式 |
| **Red Team** | G5、G6 | 維護 `config/zap/*`、`config/promptfoo/*`、`config/garak/*`；提供與輪替 `VIBESEC_TOKEN_A/B`；只打 `VIBESEC_TARGET_URL` 指向的授權環境；把黑箱證據回填白箱位置；L3 專案的委外滲透對接 | 在正式環境執行攻擊性探針 |
| **開發團隊** | 全部的修復 | 修復 P1 在 7 日內、P2 30 日、P3 90 日（`scoring.priority_sla_days`）；修復後觸發重測（`retest_result`） | 自行停用閘門 |

## 8. 文件導覽

| 文件 | 內容 | 主要讀者 |
|---|---|---|
| `docs/00-overview.md` | 本文 | 全部 |
| `docs/01-g0-threat-modeling.md` | 四問、STRIDE / LINDDUN / MAESTRO、DFD、Lethal Trifecta、L1–L3 決策樹、MAESTRO 七層表、NIST AI RMF Map | AppSec、架構師 |
| `docs/02-g1-supply-chain.md` | 四層防禦、冷卻期、相似度、postinstall 啟發式、SBOM + EPSS / KEV | DevOps |
| `docs/03-g2-secrets.md` | gitleaks 全歷史 / pre-commit / push protection、事故 SOP | DevOps、全體開發者 |
| `docs/04-g3-sast-iac.md` | 污點分析（HTTP + LLM 來源）、Semgrep / CodeQL 分工、IMDSv2 / CORS / Dockerfile | DevOps、AppSec |
| `docs/05-g4-access-control-agent-review.md` | owner binding、RLS、單層 middleware、Agent tool allow-list、HITL、Rules File Backdoor、RFC 8707、LLM 輔助審查 | AppSec、架構師 |
| `docs/06-g5-dast-api.md` | 設定外溢、雙帳號 BOLA 步驟、JWT、SSRF、rate limit、ZAP / Burp / Nuclei / Schemathesis | Red Team |
| `docs/07-g6-ai-red-team.md` | 五項檢查、garak / PyRIT / promptfoo、LLM Top 10 2025 對照、結果 → finding | Red Team |
| `docs/08-harness-agent.md` | 狀態機、閘門順序、exit code、incomplete 語意 | harness 開發者 |
| `docs/09-multi-model-review.md` | 四角色、輪次規則、少數意見、人工裁決 | AppSec |
| `docs/10-evidence-scoring-and-findings.md` | E0–E3、CVSS v4 / EPSS / KEV、P0–P3、finding JSON | 全部 |
| `docs/11-tool-selection-matrix.md` | 工具比較與 L1 / L2 / L3 組合 | DevOps、採購 |
| `docs/12-pilot-and-evaluation.md` | 四週試點、60+ 案例、驗收門檻 | 管理層 |
| `docs/13-roadmap-governance-compliance.md` | 12 個月路線圖、跨國合規 | 管理層 |
| `docs/templates/` | `threat-model.yaml`、`g0-report.md`、finding 與 risk register 範例 | 全部 |

## 9. 一條 PR 的完整旅程（把前面串起來）

以「開發者用 AI 生成一個待辦事項的 FastAPI 端點」為例，看一筆變更如何穿過雙軌：

1. **G0（設計期，已完成）**：threat-model 標記此服務 `exposure: public`、`data_sensitivity: pii`、有一個讀使用者資料的 Agent → `risk_tier: L2`；Agent 被切掉 `external_comms`（`tool_allowlist`），記 `trifecta_leg_cut: external_comms`。
2. **開發者送 PR**：AI 生成的程式碼裡 `requirements.txt` 新增 `reqeusts`、路由用 `cur.execute(f"... {todo_id}")`、查詢只 `filter(Todo.id == id)`、`.env` 忘了進 `.gitignore`。
3. **G1**：`reqeusts` 命中 `blacklist.yaml`（`looks_like: requests`）→ `vibesec.g1.hallucinated-package`（blocking）。CI 在安裝前就停。
4. **G2**：gitleaks 全歷史掃到前一個 commit 的 `sk-ant-api03-…` → `vibesec.g2.hardcoded-secret`（blocking，P0 走事故 SOP）；`.env` 未忽略 → `vibesec.g2.env-not-ignored`。
5. **G3**：Semgrep 污點分析把 `f-string` + `execute` 標成 `vibesec.g3.sql-string-concat` / `sql-fstring-execute`（blocking，CWE-89）。
6. **G4**：`vibesec.g4.missing-owner-filter`（advisory）→ identity-authz reviewer 確認這不是公開資源，升為待黑箱驗證（E2，pending）。
7. **合併到 staging 後 G5**：雙帳號測試以 `VIBESEC_TOKEN_B` 讀 A 的 todo 得 200 → `vibesec.g5.bola-cross-account`（blocking，E3）；回填 G4 finding 的 `validation_status: confirmed`。
8. **G6**：若此服務含聊天介面，promptfoo 誘導模型輸出 `<script>` 被前端渲染 → `vibesec.g6.stored-xss-via-ai-output`。
9. **harness 彙整**：七份 gate-result → 多模型審查補架構意見 → E0–E3 → CVSS v4.0 / EPSS / KEV → P0–P3 → SARIF + findings.json + risk_register.json + summary.md，上傳 Code Scanning。

shadow 模式下以上全部只報告並標「enforce 時會擋」；驗收後切 enforce，步驟 3/4/5/7 的 blocking 發現會讓 PR 檢查失敗。

## 10. 來源

OWASP ASVS 5.0.0（owasp.org）、OWASP Top 10 for LLM Applications 2025（genai.owasp.org）、OWASP Threat Modeling / Threat Modeling Manifesto、CSA MAESTRO（2025 年 2 月，Ken Huang）、NIST AI RMF 1.0、FIRST CVSS v4.0 與 EPSS（first.org）、CISA KEV（cisa.gov）、MITRE CWE Top 25 2025、Simon Willison「The Lethal Trifecta」、Perry et al.「Do Users Write More Insecure Code with AI Assistants?」（ACM CCS 2023）、Semgrep（semgrep.dev）、gitleaks（github.com/gitleaks/gitleaks）、promptfoo（promptfoo.dev）、garak（github.com/NVIDIA/garak）。
