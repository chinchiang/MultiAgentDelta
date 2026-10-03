# CLAUDE.md — VibeSec repo 規範（給 harness agent 與所有 AI 協作者）

本 repo 是「Vibe Coding 六道資安閘門（G0–G6）」框架的文件、設定與靶場。主設定在 `vibesec.yaml`，流程定義在 `docs/08-harness-agent.md`，harness skill 在 `.claude/skills/vibesec-harness/SKILL.md`。

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
- 文件以正體中文撰寫，技術名詞保留英文；每份閘門文件固定章節：對抗成因 / 觸發時機與性質 / 核心任務 / 自動化作法 / 工具與設定檔 / 阻擋政策 / 對應控制（ASVS、CWE、LLM Top 10、MAESTRO）/ 驗證方式。

## 驗證指令

```bash
python3 scripts/validate.py          # YAML 語法、JSON schema、範例檔、catalogs ID 一致性
uv run --project examples/vulnapp uvicorn app.main:app --port 8000   # 啟動靶場
```
