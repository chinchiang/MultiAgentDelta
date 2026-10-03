# 13. 路線圖、治理與合規對齊

## 一、12 個月分階段落地路線圖

| 階段 | 重點閘門 | 任務 |
|---|---|---|
| **第 0–3 月：止血與基線** | G1、G2 | 建立 G1 供應鏈冷卻期 / SBOM 與 G2 祕密掃描；確保無阻擋性高危缺陷（幻覺套件、硬編碼金鑰）進入主幹。台北 HQ 與捷克廠區先行。 |
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
