# VibeSec — Vibe Coding 六道資安閘門（G0–G6）測試框架

> 為 Vibe Coding（開發者依賴 AI 產生程式碼並「全部接受」）建立一套**嵌入 CI/CD、不可繞過、白箱＋黑箱＋AI 紅隊**的常態化資安測試管線，並由一個 **harness agent** 把整個流程包起來：執行閘門、彙整發現、多模型審查、證據分級、評分、產出報告。

本 repo 這一版交付的是**框架文件、可直接使用的設定檔、GitHub Actions 工作流、harness agent 的 skill/agent 定義與一個刻意有漏洞的靶場**。確定性掃描由工具與工作流執行，LLM 審查與裁決由 skill 驅動的 agent 執行。之後若補 Python harness，這些文件即為其規格。

## 為什麼需要六道閘門

AI 生成程式碼有四大典型病徵：**幻覺套件（Slopsquatting）**、**硬編碼金鑰**、**靜態注入漏洞（SQLi / XSS / Command）**、**前端防禦假象（BOLA / IDOR）**。Vibe Coding 把「人類撰寫、同儕審查、測試」三道把關壓縮成只剩「測試」，所以測試必須變成 CI/CD 中不可繞過的閘門。

```
[ G0 威脅建模 ] (設計期前置：STRIDE / LINDDUN / MAESTRO，致命三要素檢驗，L1/L2/L3 分級)
       │
       ▼ (每次 Commit / PR —— 白箱，由內而外)
┌────────────────────────────────────────────────────────┐
│ G1 相依性與供應鏈   SCA / Slopsquatting 四層防禦 / SBOM │
│ G2 機密與金鑰       Gitleaks 全歷史 / Push Protection   │
│ G3 SAST 與 IaC      跨檔污點分析 / IMDSv2 / CORS        │
│ G4 架構與存取控制   BOLA / RLS / Agent Tool 權限 / HITL │
└────────────────────────────────────────────────────────┘
       │
       ▼ (部署至 Staging / 上線前 —— 黑箱，由外而內)
┌────────────────────────────────────────────────────────┐
│ G5 DAST 與 API      雙帳號 BOLA 實測 / JWT / SSRF / 設定外溢 │
│ G6 LLM / Agent 紅隊 Prompt Injection / 二次 XSS / Denial of Wallet │
└────────────────────────────────────────────────────────┘
       │
       ▼
[ harness agent ] 彙整 → 多模型審查 → E0–E3 證據分級 → CVSS/EPSS/KEV → P0–P3 → SARIF + findings.json + risk_register.json + summary.md
```

## 快速上手

1. 複製 `docs/templates/threat-model.yaml` 填寫 G0，決定 `risk_tier`（L1 / L2 / L3）並寫入 `vibesec.yaml`。
2. 把 `.github/workflows/` 三條工作流、`.pre-commit-config.yaml`、`config/` 複製到目標專案；在 repo 的 Actions variables 設定已授權測試目標 `VIBESEC_TARGET_URL`（未設定則只打內建靶場），在 secrets 設定 `VIBESEC_TOKEN_A`、`VIBESEC_TOKEN_B` 與模型金鑰（見 `config/providers.yaml`）。
3. 在 Claude Code 中執行 `/vibesec-harness`：harness agent 會依 `vibesec.yaml` 執行閘門、呼叫四個 reviewer sub-agent，並把報告寫到 `reports/`。
4. 試點期維持 `mode: shadow`（只報告）；驗收後改 `mode: enforce`，命中 `config/policy/blocking-policy.yaml` 的發現即擋 PR。
5. 要驗證黑箱閘門，先啟動靶場：`uv run --project examples/vulnapp uvicorn app.main:app --port 8000`。

## 目錄導覽

| 路徑 | 內容 |
|---|---|
| `vibesec.yaml` | 主設定：模式、風險分級、各閘門參數、審查與評分規則 |
| `docs/00-overview.md` | 四大病徵 → G0–G6 映射、雙軌架構、三大工程原則、責任歸屬 |
| `docs/01`–`07` | G0 威脅建模、G1 供應鏈、G2 機密、G3 SAST/IaC、G4 存取控制與 Agent 審查、G5 DAST/API、G6 AI 紅隊 |
| `docs/08-harness-agent.md` | harness 狀態機、閘門順序、模式、exit code、incomplete 語意 |
| `docs/09-multi-model-review.md` | provider 抽象、四個審查角色、輪次規則、少數意見、人工裁決 |
| `docs/10-evidence-scoring-and-findings.md` | E0–E3、validation_status、CVSS v4 / EPSS / KEV、P0–P3 SLA、finding JSON |
| `docs/11-tool-selection-matrix.md` | SAST / SCA / DAST / AI 紅隊工具比較與 L1/L2/L3 組合 |
| `docs/12-pilot-and-evaluation.md` | 四週試點、60+ 案例、三組比較、驗收門檻 |
| `docs/13-roadmap-governance-compliance.md` | 12 個月路線圖、ASVS 5.0 / NIST AI RMF / EU CRA / CSL-PIPL 對齊、MAESTRO 對接 |
| `docs/templates/` | G0 威脅模型模板、G0 報告模板、finding 與 risk register 範例 |
| `schemas/` | `finding`、`gate-result`、`threat-model` JSON Schema |
| `config/` | 各工具可直接使用的設定：Semgrep 規則、gitleaks、Checkov、slopsquat 清單、ZAP、promptfoo、garak、blocking 政策、catalogs、providers、harness 角色提示 |
| `.claude/skills/vibesec-harness/` | `/vibesec-harness` skill：harness agent 的操作流程 |
| `.claude/agents/` | 四個 reviewer sub-agent：architecture、appsec、identity、supplychain |
| `.github/workflows/` | `pr-gates.yml`（G1–G4 diff-aware）、`nightly-full.yml`（CodeQL + 全量）、`staging-blackbox.yml`（G5 + G6 打靶場） |
| `examples/vulnapp/` | 刻意有漏洞的 FastAPI 靶場（BOLA、JWT alg:none、SSRF、Prompt Injection、Stored XSS、Denial of Wallet） |
| `evals/` | 評測案例格式與種子案例（正例 / 反例、held_out） |
| `scripts/validate.py` | 本 repo 的自我驗證：YAML、schema、範例、catalogs 一致性 |

## 三大落地工程原則

1. **分層阻擋（Blocking vs Advisory）**：高確定性發現（硬編碼金鑰、幻覺或冷卻期未滿套件、未參數化 SQL、JWT alg:none、雙帳號 BOLA 實證、KEV 命中）為 blocking；需人工判斷的架構建議為 advisory。
2. **輸出標準化（SARIF）**：所有工具輸出統一為 SARIF 2.1.0 上傳 GitHub Code Scanning，並對照 CWE；架構類發現進 risk register。
3. **差異感知（Diff-Aware）**：PR 階段只掃變更；夜間全量補齊。

## 來源與對齊

OWASP ASVS 5.0.0（L2 預設基線、L3 高價值系統）、OWASP LLM Top 10 2025、CSA MAESTRO 七層威脅模型、NIST AI RMF 1.0、EU CRA、FIRST CVSS v4.0 / EPSS、CISA KEV。
