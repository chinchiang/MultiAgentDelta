
[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

文件採正體中文（臺灣慣用語）／英文雙語，使用頁首連結切換。設定欄位、規則 ID、指令與測試輸入保留原樣；兩種語言共用程式碼範例。修改文件時請同步更新兩種語言，提示內容變更也須更新 `prompt_version`。

# VibeSec — Vibe Coding 六道資安閘門（G0–G6）測試框架

> 為 Vibe Coding（開發者依賴 AI 產生程式碼並「全部接受」）建立一套**嵌入 CI/CD、不可繞過、白箱＋黑箱＋AI 紅隊**的常態化資安測試管線，並由一個 **harness agent** 把整個流程包起來：執行閘門、彙整發現、多模型審查、證據分級、評分、產出報告。

本 repo 這一版交付的是**框架文件、可直接使用的設定檔、GitHub Actions 工作流程、harness agent 的 skill/agent 定義與一個刻意有漏洞的靶場**。確定性掃描由工具與工作流程執行，LLM 審查與裁決由 skill 驅動的 agent 執行。之後若補 Python harness，這些文件即為其規格。

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
2. 把 `.github/workflows/`、`.github/scripts/`、`scripts/`、`schemas/`、`requirements-ci.txt`、`.pre-commit-config.yaml`、`config/` 複製到目標專案；在 repo 的 Actions variables 設定已授權測試目標 `VIBESEC_TARGET_URL`（未設定則只打內建靶場），在 secrets 設定 `VIBESEC_TOKEN_A`、`VIBESEC_TOKEN_B` 與模型金鑰（見 `config/providers.yaml`）。
3. 在 Claude Code 中執行 `/vibesec-harness`：harness agent 會依 `vibesec.yaml` 執行閘門、呼叫四個 reviewer sub-agent，並把報告寫到 `reports/`。
4. 試點期維持 `mode: shadow`（只報告）；驗收後改 `mode: enforce`，必要檢查成功才可合併；命中 `config/policy/blocking-policy.yaml` 的發現或必要閘門未完成時阻擋。須先完成 [GitHub 管理設定](docs/14-operation-and-verification.md)，只有修改 YAML 並不足以保護分支。
5. 要驗證黑箱閘門，先啟動靶場：`uv run --project examples/vulnapp uvicorn app.main:app --port 8000`。

## 開發驗證

```bash
python3 -m pip install --require-hashes -r requirements-ci.txt
python3 scripts/validate.py
python3 -m unittest discover -s tests -v
node --test .github/scripts/*.test.js
python3 scripts/run_evals.py --baseline evals/baseline.yaml --json reports/evals.json --md reports/evals.md
```

完整評測另需固定版本的 Semgrep、Checkov、Gitleaks 與 uv，版本及雜湊見 `nightly-full.yml`。目前共 94 個案例：90 個偵測案例、4 個失敗狀態驗證；狀態案例不混入召回率。這是工具與靶場驗證，不能取代真實模型的三組比較。操作、證據限制與部署串接見 [操作與驗證](docs/14-operation-and-verification.md)。

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
| `docs/templates/` | G0 威脅模型範本、G0 報告範本、finding 與 risk register 範例 |
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


---

<a id="english"></a>

Documentation is bilingual in Traditional Chinese (Taiwan) and English; use the navigation links above. Configuration keys, rule IDs, commands, and test inputs remain unchanged, and both languages share code examples. Update both languages together; prompt changes also require a new `prompt_version`.

# VibeSec — Six Security Gates for Vibe Coding (G0–G6)

> A continuous security testing pipeline for Vibe Coding—where developers rely on AI-generated code and accept it wholesale. The pipeline combines **white-box, black-box, and AI red-team testing in CI/CD**, with gates that must not be bypassed. A **harness agent** runs the gates, aggregates findings, coordinates multi-model review, grades evidence, scores risk, and produces reports.

This repository delivers **framework documentation, ready-to-use configuration, GitHub Actions workflows, harness skill/agent definitions, and an intentionally vulnerable lab**. Tools and workflows perform deterministic scans; skill-driven agents conduct LLM reviews and adjudication workflows. These documents also specify any future Python harness.

## Why six gates?

AI-generated code commonly introduces **hallucinated packages (slopsquatting), hard-coded keys, static injection vulnerabilities (SQLi/XSS/command injection), and illusory client-side authorization (BOLA/IDOR)**. Vibe Coding compresses human implementation, peer review, and testing into testing alone. Testing therefore needs enforceable CI/CD gates.

```text
G0 Threat modeling: STRIDE / LINDDUN / MAESTRO, lethal trifecta, L1/L2/L3
  ↓ Each commit / PR: white-box, inside out
G1 Dependencies and supply chain: SCA, four-layer slopsquatting defense, SBOM
G2 Secrets and keys: full-history Gitleaks, Push Protection
G3 SAST and IaC: cross-file taint analysis, IMDSv2, CORS
G4 Architecture and access control: BOLA, RLS, agent tool permissions, HITL
  ↓ Staging / pre-release: black-box, outside in
G5 DAST and API: two-account BOLA, JWT, SSRF, exposed configuration
G6 LLM / agent red team: prompt injection, secondary XSS, denial of wallet
  ↓
Harness agent: aggregate → multi-model review → E0–E3 evidence → CVSS/EPSS/KEV
→ P0–P3 priority → SARIF + findings.json + risk_register.json + summary.md
```

## Quick start

1. Copy and complete `docs/templates/threat-model.yaml` for G0. Set `risk_tier` (L1/L2/L3) in `vibesec.yaml`.
2. Copy `.github/workflows/`, `.github/scripts/`, `scripts/`, `schemas/`, `requirements-ci.txt`, `.pre-commit-config.yaml`, and `config/` into the target project. Set the authorized test URL in the repository Actions variable `VIBESEC_TARGET_URL`; if unset, only the bundled lab is tested. Configure secrets `VIBESEC_TOKEN_A`, `VIBESEC_TOKEN_B`, and model keys (see `config/providers.yaml`).
3. Run `/vibesec-harness` in Claude Code. The harness follows `vibesec.yaml`, calls the four reviewer subagents, and writes reports under `reports/`.
4. Keep `mode: shadow` during the pilot (reporting only). After acceptance, use `mode: enforce`: required checks must succeed before merging, and findings covered by `config/policy/blocking-policy.yaml` or incomplete required gates block release. Complete the [GitHub administration setup](docs/14-operation-and-verification.md#english); YAML alone cannot protect a branch.
5. Start the lab for black-box verification: `uv run --project examples/vulnapp uvicorn app.main:app --port 8000`.

## Development verification

```bash
python3 -m pip install --require-hashes -r requirements-ci.txt
python3 scripts/validate.py
python3 -m unittest discover -s tests -v
node --test .github/scripts/*.test.js
python3 scripts/run_evals.py --baseline evals/baseline.yaml --json reports/evals.json --md reports/evals.md
```

Full evaluations also require pinned Semgrep, Checkov, Gitleaks, and uv; versions and checksums are in `nightly-full.yml`. There are 94 cases: 90 detection cases and four failure-state checks. State checks are excluded from recall. Tool and lab validation does not replace a real three-arm model comparison. See [operation and verification](docs/14-operation-and-verification.md#english) for deployment integration and evidence limits.

## Repository guide

| Path | Contents |
|---|---|
| `vibesec.yaml` | Mode, risk tier, gate parameters, review and scoring rules |
| `docs/00-overview.md` | Four failure patterns mapped to G0–G6, dual-track architecture, engineering principles, ownership |
| `docs/01`–`07` | G0 threat modeling; G1 supply chain; G2 secrets; G3 SAST/IaC; G4 access control/agent review; G5 DAST/API; G6 AI red team |
| `docs/08-harness-agent.md` | Harness state machine, gate order, modes, exit codes, incomplete semantics |
| `docs/09-multi-model-review.md` | Provider abstraction, four review roles, rounds, dissent, human adjudication |
| `docs/10-evidence-scoring-and-findings.md` | E0–E3, validation status, CVSS v4/EPSS/KEV, P0–P3 SLAs, finding JSON |
| `docs/11-tool-selection-matrix.md` | Tool comparisons and L1/L2/L3 combinations |
| `docs/12-pilot-and-evaluation.md` | Four-week pilot, minimum 60 cases, three-arm comparison, acceptance criteria |
| `docs/13-roadmap-governance-compliance.md` | Twelve-month roadmap, ASVS/NIST AI RMF/EU CRA/CSL-PIPL alignment, MAESTRO mapping |
| `docs/templates/` | G0 threat model/report templates, finding and risk-register examples |
| `schemas/` | JSON schemas for findings, gate results, and threat models |
| `config/` | Semgrep, Gitleaks, Checkov, slopsquatting lists, ZAP, promptfoo, garak, blocking policy, catalogs, providers, review prompts |
| `.claude/skills/vibesec-harness/` | Operational `/vibesec-harness` skill |
| `.claude/agents/` | Architecture, AppSec, identity, and supply-chain reviewers |
| `.github/workflows/` | Diff-aware G1–G4 PR checks, nightly CodeQL/full scans, staging G5/G6 lab tests |
| `examples/vulnapp/` | Intentionally vulnerable FastAPI lab: BOLA, JWT alg:none, SSRF, prompt injection, stored XSS, denial of wallet |
| `evals/` | Positive/negative and held-out evaluation cases |
| `scripts/validate.py` | Repository checks: YAML, schemas, examples, catalog consistency |

## Three implementation principles

1. **Blocking versus advisory:** high-confidence findings—hard-coded keys, hallucinated or insufficiently aged packages, unparameterized SQL, JWT alg:none, demonstrated two-account BOLA, and KEV matches—block. Architectural recommendations requiring judgment are advisory.
2. **Standardized output:** normalize location-based findings into SARIF 2.1.0 for GitHub Code Scanning and map them to CWE. Architectural findings belong in the risk register.
3. **Diff awareness:** scan changes on PRs; run full scans nightly.

## Sources and alignment

OWASP ASVS 5.0.0 (L2 default, L3 for high-value systems), OWASP LLM Top 10 2025, CSA MAESTRO's seven layers, NIST AI RMF 1.0, EU CRA, FIRST CVSS v4.0/EPSS, and CISA KEV.
