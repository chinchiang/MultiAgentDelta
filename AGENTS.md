# AGENTS.md — VibeSec repo 規範（給 harness agent 與所有 AI 協作者）

本 repo 是「Vibe Coding 六道資安閘門（G0–G6）」框架的文件、設定與靶場。主設定在 `vibesec.yaml`；執行或修改閘門流程前，讀 `docs/08-harness-agent.md`。

本檔是 repo 規範的唯一來源；`CLAUDE.md` 只有 `@AGENTS.md` 一行，讓 Claude Code 載入本檔。規範只改本檔，英文譯本的同步方式見「文件語言」。

## 不可違反的規則

規則編號被程式碼與文件引用（「AGENTS.md 規則 N」「#N」「第 N 條」）：新增規則一律接在最後，既有編號保持不變。

1. **閘門不可繞過**：不得停用、跳過、放寬任何 `vibesec.yaml` 中 `enabled: true` 的閘門，也不得修改 `config/policy/blocking-policy.yaml` 把 blocking 降為 advisory 來讓檢查通過。要改政策必須由人類在獨立 PR 中決定。
2. **incomplete ≠ pass**：工具缺席、逾時、API 失敗、缺帳號、缺文件、環境無法啟動 → 該閘門狀態為 `incomplete` 並寫明 `status_reason`。絕不產生「通過」。清單沒列到的情況一樣 fail-closed：拿不到證據，就是 `incomplete`。
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
- 每份閘門文件固定章節：對抗成因 / 觸發時機與性質 / 核心任務 / 自動化作法 / 工具與設定檔 / 阻擋政策 / 對應控制（ASVS、CWE、LLM Top 10、MAESTRO）/ 驗證方式。

### 文件語言

- 文件以正體中文（臺灣慣用語）撰寫。技術名詞、程式識別碼、指令與 ID 保留原文；程式碼註解與工具輸出維持正體中文。
- **雙語集合**（`GLOSSARY.md`、`docs/agents/`、`docs/adr/`、`docs/research/`，目錄內新增的檔案也算）另加英文：同一份 Markdown 先放正體中文、再放英文，以 `<a id="zh-tw"></a>`、`<a id="english"></a>` 分段，檔首放切換連結。
- **譯本**：本檔只寫正體中文，英文譯本是 `docs/agents/rules.en.md`。譯本不屬於雙語集合，標題結構須與本檔相同。
- 修改雙語集合的任一語言段落、或修改本檔時，同一個 PR 更新另一語言；兩者有出入時以**正體中文版為準**。
- 其他文件只寫正體中文（#178）。
- `scripts/bilingual.py` 檢查錨點、切換連結與標題結構（含譯本）；句子是否逐一對應靠 review。

## 驗證指令

```bash
python3 scripts/validate.py          # YAML 語法、JSON schema、範例檔、catalogs ID 一致性
uv run --project examples/vulnapp uvicorn app.main:app --port 8000   # 啟動靶場
```

## Agent skills

### Issue tracker

開 issue、讀 spec 或留言前，見 `docs/agents/issue-tracker.md`（GitHub Issues `chinchiang/MultiAgentDelta`，用 `gh` 操作）。

### Triage labels

新增或修改 issue 標籤前，見 `docs/agents/triage-labels.md`。

### Domain docs

替概念命名、使用領域詞彙、寫 ADR 或做 architecture review 前，先讀 `GLOSSARY.md` 與 `docs/adr/`（single-context，見 `docs/agents/domain.md`）。

### Workflow

實作 ticket、開 PR、合併前：步驟、判準（評測逐案比對、CI 閘門表格）與容易踩的坑，見 `docs/agents/workflow.md`。
