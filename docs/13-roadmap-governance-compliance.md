
[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

> 本文件提供控制對照，不代表取得認證或保證符合法規。

# 13. 路線圖、治理與合規對齊

## 一、12 個月分階段落地路線圖

| 階段 | 重點閘門 | 任務 |
|---|---|---|
| **第 0–3 月：止血與基線** | G1、G2 | 建立 G1 供應鏈冷卻期 / SBOM 與 G2 祕密掃描；確保無阻擋性高危缺陷（幻覺套件、硬編碼金鑰）進入主幹。臺北 HQ 與捷克廠區先行。 |
| **第 3–6 月：靜態分析與架構** | G3、G4 | 導入 G3 跨檔污點分析與 G4 存取控制複查；標準化 OPA 政策與 CWE 產出格式；啟用 Supabase RLS 審查。 |
| **第 6–12 月：動態驗證與紅隊** | G5、G6 | 上線 G5 DAST/BOLA 與 G6 AI 紅隊；部署動態驗證與上線前測試；建立集團風險儀表板；依合規要求（如 CSL/PIPL）於各廠區硬性推隔離工具鏈。 |

> Vibe Coding 提供了指數級的開發速度；雙軌管線則提供了安全駕駛所需的煞車系統。

## 二、跨部門協作與管線責任歸屬

| 團隊 | 職責 | 主責閘門 |
|---|---|---|
| **DevOps / 平台工程** | 負責 CI 整合 | G1 供應鏈阻擋 → G2/G3 自動化掃描 |
| **AppSec / 資安治理** | 制定資安政策 | G0 威脅建模 → G4 架構與邏輯審查 |
| **Red Team / 滲透測試** | 攻擊面驗證 | G5 DAST 測試 → G6 AI 紅隊演練 |

## 三、合規框架對齊

| 框架 | 本框架對應 |
|---|---|
| **OWASP ASVS 5.0.0** | L2 預設基線、L3 高價值系統；G0 的文件化安全決策為後續驗證基礎。控制目錄 `config/catalogs/asvs-5.0-controls.yaml`。 |
| **OWASP LLM Top 10 2025** | G6 的五類測試對照 `config/catalogs/llm-top10-2025.yaml`。 |
| **CSA MAESTRO** | Agentic AI 七層威脅模型，G0 盤點、對接各閘門（`config/catalogs/maestro-layers.yaml`）。 |
| **NIST AI RMF 1.0** | 威脅建模為 Map 功能核心產物，文件化威脅行為者、攻擊向量與緩解措施。 |
| **EU CRA（Cyber Resilience Act）** | 需 G1/G3/G5 產出 SBOM 與無已知漏洞證明；捷克廠區作為 EU 前線。 |
| **ISO 27001:2022** | G0 產出的安全邊界與文件化決策。 |
| **中國 CSL / DSL / PIPL** | 上海、重慶廠區工具鏈地端私有化部署，掃描資料不出境，僅跨境傳送去識別化統計指標。 |

## 四、MAESTRO 七層 → 閘門對接

| MAESTRO 層 | 核心威脅面 | Vibe Coding 典型失效 | 對接閘門 |
|---|---|---|---|
| L1 Foundation Models | 模型可操縱性、訓練資料污染 | 越獄、幻覺捏造套件名 | G6、G1 |
| L2 Data Operations | 資料處理、RAG 向量檢索 | 未啟用 RLS 全表暴露、RAG 來源植入指令 | G4、G6 |
| L3 Agent Frameworks | Tool/Function Calling 授權、MCP | 工具缺 Allow-list、System Prompt 寫死金鑰、MCP 工具描述投毒 | G4、G2 |
| L4 Deployment & Infrastructure | 執行環境、網路出向、IaC | Agent 對正式 DB 破壞性權限、IaC 未強制 IMDSv2 | G3、G4 |
| L5 Evaluation & Observability | 監控、日誌、異常偵測 | 缺稽核日誌、未設用量限制（Denial of Wallet） | G6、治理監控 |
| L6 Security & Compliance | 貫穿各層的存取控制、身分驗證 | 前端防禦假象、單層授權繞過（CVE-2025-29927） | G4、G5 |
| L7 Agent Ecosystem | 第三方 Agent、人機信任 | 過度信任 AI 產出、Rules File Backdoor | G0、G1 |


---

<a id="english"></a>

# 13. Roadmap, Governance, and Compliance Alignment

## 1. Twelve-month rollout

| Phase | Gates | Work |
|---|---|---|
| Months 0–3: containment and baseline | G1/G2 | Establish package cooldown/SBOM and secret scanning. Keep blocking hallucinated-package and hard-coded-key defects out of main. Start with Taipei HQ and the Czech site. |
| Months 3–6: static analysis and architecture | G3/G4 | Add cross-file taint and access-control review; standardize OPA policies/CWE output; review Supabase RLS. |
| Months 6–12: dynamic verification and red team | G5/G6 | Deploy DAST/BOLA and AI red teaming, pre-release dynamic tests, and a group risk dashboard; enforce isolated site toolchains for requirements such as CSL/PIPL. |

Vibe Coding accelerates development; the dual-track pipeline supplies the corresponding safety controls.

## 2. Ownership

| Team | Responsibility | Primary gates |
|---|---|---|
| DevOps / platform engineering | CI integration | G1 blocking and G2/G3 automated scanning |
| AppSec / security governance | Security policy | G0 threat modeling and G4 architecture/logic review |
| Red team / penetration testing | Attack-surface verification | G5 DAST and G6 AI red-team exercises |

## 3. Compliance alignment

| Framework | Mapping |
|---|---|
| OWASP ASVS 5.0.0 | L2 default, L3 high-value systems; documented G0 decisions underpin verification. Catalog: `config/catalogs/asvs-5.0-controls.yaml`. |
| OWASP LLM Top 10 2025 | G6's five test categories map through `config/catalogs/llm-top10-2025.yaml`. |
| CSA MAESTRO | G0 inventories seven agentic-AI layers and maps them to gates (`config/catalogs/maestro-layers.yaml`). |
| NIST AI RMF 1.0 | Threat modeling supports Map by documenting actors, vectors, and mitigations. |
| EU CRA | G1/G3/G5 supply SBOM and known-vulnerability verification evidence; the Czech site is the EU rollout front line. |
| ISO 27001:2022 | G0 security boundaries and documented decisions. |
| China CSL / DSL / PIPL | Local private toolchains at Shanghai/Chongqing sites; scan data remains local, with only de-identified statistics transferred across borders. |

These are framework mappings, not automatic certification or a guarantee of legal compliance.

## 4. MAESTRO layers mapped to gates

| Layer | Threat surface | Typical Vibe Coding failure | Gates |
|---|---|---|---|
| L1 Foundation Models | Model manipulation, training-data poisoning | Jailbreaks, fabricated package names | G6/G1 |
| L2 Data Operations | Data processing, RAG retrieval | Missing RLS exposes tables; instructions planted in RAG sources | G4/G6 |
| L3 Agent Frameworks | Tool/function authorization, MCP | Missing allowlist, keys in system prompts, poisoned MCP descriptions | G4/G2 |
| L4 Deployment & Infrastructure | Runtime, network egress, IaC | Destructive production-DB privileges; no mandatory IMDSv2 | G3/G4 |
| L5 Evaluation & Observability | Monitoring, logs, anomalies | Missing audit logs or usage limits; denial of wallet | G6/governance monitoring |
| L6 Security & Compliance | Cross-layer authentication/authorization | Client-only protection, single-layer bypass (CVE-2025-29927) | G4/G5 |
| L7 Agent Ecosystem | Third-party agents, human-machine trust | Over-trusting AI output, rules-file backdoors | G0/G1 |
