[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# AGENTS.md — VibeSec repo 規範（給 harness agent 與所有 AI 協作者）

本 repo 是「Vibe Coding 六道資安閘門（G0–G6）」框架的文件、設定與靶場。主設定在 `vibesec.yaml`，流程定義在 `docs/08-harness-agent.md`，harness skill 在 `.claude/skills/vibesec-harness/SKILL.md`。

本檔是 repo 規範的唯一來源；`CLAUDE.md` 只有 `@AGENTS.md` 一行，讓 Claude Code 載入本檔。規範只改本檔。

## 不可違反的規則

1. **閘門不可繞過**：不得停用、跳過、放寬任何 `vibesec.yaml` 中 `enabled: true` 的閘門，也不得修改 `config/policy/blocking-policy.yaml` 把 blocking 降為 advisory 來讓檢查通過。要改政策必須由人類在獨立 PR 中決定。
2. **incomplete ≠ pass**：工具缺席、逾時、API 失敗、缺帳號、缺文件、環境無法啟動 → 該閘門狀態為 `incomplete` 並寫明 `status_reason`。絕不產生「通過」。
3. **ID 只能查目錄**：CWE、CVE、ASVS 控制編號、OWASP LLM Top 10 編號必須來自 `config/catalogs/`，不得猜測。查不到就填 `null` 並在 `notes` 說明。
4. **評分不混算**：CVSS v4.0 向量與分數、EPSS 與查詢日、KEV 與日期分欄記錄，不做任何 `CVSS × EPSS × 模型信心` 的自訂乘法。模型自評信心不轉成證據等級。
5. **證據等級與驗證狀態分開**：`evidence_grade`（E0–E3）描述證據有多可信；`validation_status`（pending/confirmed/refuted）描述目前結論；兩者都不等於嚴重度。
6. **多模型審查規則**：高風險控制至少兩個不同 `family` 的模型獨立檢查；第一輪不交換結論；之後最多兩輪交叉質疑；保留少數意見；不多數決；分歧交人工裁決（`requires_human: true`）。
7. **不得外傳**：未分類資料留在地端 provider；只有 `config/providers.yaml` 標記 `allowed_data_classes` 包含該資料分級的 provider 才可接收該內容。報告中的祕密只保留遮罩與指紋。
8. **靶場只能打靶場**：`examples/vulnapp` 是刻意有漏洞的測試目標。G5/G6 的攻擊性探針只能對 `VIBESEC_TARGET_URL` 指向的、已授權的測試環境執行。

## 命名與格式慣例

- 閘門 ID：`G0`–`G6`。規則 ID：`vibesec.g<N>.<kebab-name>`；外部工具規則保留原名並加前綴 `gitleaks:`、`semgrep:`、`trivy:`、`grype:`、`checkov:`、`zap:`、`promptfoo:`、`garak:`。
- 控制 ID：ASVS 用 `ASVS5-V<章>.<節>`（自編到節，非官方需求編號，見 `config/catalogs/asvs-5.0-controls.yaml` 的免責說明）；OWASP LLM Top 10 用 `LLM01:2025`…`LLM10:2025`；MAESTRO 用 `MAESTRO-L1`…`MAESTRO-L7`；vibesec 自有控制用 `VS-G<N>-<NAME>`。
- Finding ID：`VS-YYYYMMDD-<8 hex>`。
- 所有輸出必須符合 `schemas/finding.schema.json`、`schemas/gate-result.schema.json`。SARIF 2.1.0 給程式位置類發現；架構類發現進 `risk_register.json`。
- 文件以正體中文（臺灣慣用語）撰寫；**雙語集合**（`AGENTS.md`、`GLOSSARY.md`、`docs/agents/`、`docs/adr/`、`docs/research/`，目錄內新增的檔案也算）另加英文：同一份 Markdown 先放正體中文、再放英文，以 `<a id="zh-tw"></a>`、`<a id="english"></a>` 分段，檔首放切換連結（`scripts/bilingual.py` 檢查這些結構）；修改任一語言段落時，必須在同一個 PR 更新另一語言；兩者有出入時以**正體中文版為準**。集合外的文件只寫正體中文（#178）。技術名詞、程式識別碼、指令與 ID 保留原文。程式碼註解與工具輸出維持正體中文。
- 每份閘門文件固定章節：對抗成因 / 觸發時機與性質 / 核心任務 / 自動化作法 / 工具與設定檔 / 阻擋政策 / 對應控制（ASVS、CWE、LLM Top 10、MAESTRO）/ 驗證方式。

## 驗證指令

```bash
python3 scripts/validate.py          # YAML 語法、JSON schema、範例檔、catalogs ID 一致性
uv run --project examples/vulnapp uvicorn app.main:app --port 8000   # 啟動靶場
```

## Agent skills

### Issue tracker

Issue 與 spec 放在 GitHub Issues（`chinchiang/MultiAgentDelta`），用 `gh` 操作。見 `docs/agents/issue-tracker.md`。

### Triage labels

使用五個預設角色標籤（`needs-triage`、`needs-info`、`ready-for-agent`、`ready-for-human`、`wontfix`）。見 `docs/agents/triage-labels.md`。

### Domain docs

Single-context：`GLOSSARY.md` ＋ `docs/adr/`。見 `docs/agents/domain.md`。

### Workflow

實作 ticket、開 PR、合併前：步驟、判準（評測逐案比對、CI 閘門表格）與容易踩的坑，見 `docs/agents/workflow.md`。

---

<a id="english"></a>

# AGENTS.md — VibeSec Repository Rules (for the harness agent and all AI contributors)

This repository holds the documentation, configuration, and lab for the "Vibe Coding six security gates (G0–G6)" framework. The main configuration is `vibesec.yaml`, the process is defined in `docs/08-harness-agent.md`, and the harness skill lives in `.claude/skills/vibesec-harness/SKILL.md`.

This file is the single source of the repository rules; `CLAUDE.md` holds only the line `@AGENTS.md` so that Claude Code loads this file. Edit the rules here only.

## Mandatory rules

1. **Gates cannot be bypassed.** Do not disable, skip, or relax any gate with `enabled: true` in `vibesec.yaml`, and do not edit `config/policy/blocking-policy.yaml` to demote blocking to advisory so a check passes. Policy changes must be decided by a human in a separate PR.
2. **incomplete ≠ pass.** Missing tools, timeouts, API failures, missing accounts or documents, or an environment that cannot start → the gate status is `incomplete` with a `status_reason`. Never report a pass.
3. **IDs come only from the catalogs.** CWE, CVE, ASVS control IDs, and OWASP LLM Top 10 IDs must come from `config/catalogs/`; never guess. If an ID cannot be found, use `null` and explain in `notes`.
4. **Do not combine scores.** Record the CVSS v4.0 vector and score, EPSS with its query date, and KEV with its date in separate fields. No custom `CVSS × EPSS × model confidence` multiplication. Model self-reported confidence is never turned into an evidence grade.
5. **Evidence grade and validation status are separate.** `evidence_grade` (E0–E3) describes how trustworthy the evidence is; `validation_status` (pending/confirmed/refuted) describes the current conclusion. Neither equals severity.
6. **Multi-model review rules.** High-risk controls need independent checks by models from at least two different `family` values; round 1 does not exchange conclusions; at most two cross-examination rounds follow; minority opinions are kept; no majority vote; disagreement goes to human adjudication (`requires_human: true`).
7. **No exfiltration.** Unclassified data stays with on-premises providers; only providers whose `allowed_data_classes` in `config/providers.yaml` include the data class may receive that content. Secrets in reports keep only a mask and a fingerprint.
8. **Attack only the lab.** `examples/vulnapp` is a deliberately vulnerable test target. G5/G6 offensive probes may run only against the authorized test environment that `VIBESEC_TARGET_URL` points to.

## Naming and format conventions

- Gate IDs: `G0`–`G6`. Rule IDs: `vibesec.g<N>.<kebab-name>`; external tool rules keep their original names with a prefix: `gitleaks:`, `semgrep:`, `trivy:`, `grype:`, `checkov:`, `zap:`, `promptfoo:`, `garak:`.
- Control IDs: ASVS uses `ASVS5-V<chapter>.<section>` (self-assigned down to the section, not official requirement numbers; see the disclaimer in `config/catalogs/asvs-5.0-controls.yaml`); OWASP LLM Top 10 uses `LLM01:2025`…`LLM10:2025`; MAESTRO uses `MAESTRO-L1`…`MAESTRO-L7`; vibesec's own controls use `VS-G<N>-<NAME>`.
- Finding ID: `VS-YYYYMMDD-<8 hex>`.
- All output must conform to `schemas/finding.schema.json` and `schemas/gate-result.schema.json`. SARIF 2.1.0 is for code-location findings; architecture findings go into `risk_register.json`.
- Documentation is written in Traditional Chinese (Taiwan usage); the **bilingual set** (`AGENTS.md`, `GLOSSARY.md`, `docs/agents/`, `docs/adr/`, `docs/research/`, including new files in those directories) also carries English: each Markdown file has the Traditional Chinese section first, then the English section, separated by `<a id="zh-tw"></a>` and `<a id="english"></a>`, with language links at the top (`scripts/bilingual.py` checks this structure); when either language section changes, the other must be updated in the same PR; if they disagree, **the Traditional Chinese version prevails**. Files outside the set are Traditional Chinese only (#178). Technical terms, code identifiers, commands, and IDs stay in their original form. Code comments and tool output stay in Traditional Chinese.
- Every gate document has fixed sections: adversarial causes / triggers and nature / core tasks / automation / tools and configuration files / blocking policy / mapped controls (ASVS, CWE, LLM Top 10, MAESTRO) / verification.

## Verification commands

```bash
python3 scripts/validate.py          # YAML syntax, JSON schema, examples, catalog ID consistency
uv run --project examples/vulnapp uvicorn app.main:app --port 8000   # start the lab
```

## Agent skills

### Issue tracker

Issues and specs live in GitHub Issues (`chinchiang/MultiAgentDelta`), operated with `gh`. See `docs/agents/issue-tracker.md`.

### Triage labels

The five default role labels are used (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `GLOSSARY.md` plus `docs/adr/`. See `docs/agents/domain.md`.

### Workflow

Before implementing a ticket, opening a PR, or merging: steps, pass criteria (case-by-case eval comparison, CI gate table), and gotchas are in `docs/agents/workflow.md`.
