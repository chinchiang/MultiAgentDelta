
[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# 12. 試點與評測

本框架在全面導入前，先以**觀察模式執行（shadow）**試點，量化多模型審查相對單模型的增益，並校準誤報。操作與可重現驗證見 [操作與驗證](14-operation-and-verification.md)。

## 一、試點設計

- **期程**：4 週。
- **範圍**：3 種代表性專案（例如 Web + API、純後端腳本、含 LLM/Agent 應用）。
- **啟動方式**：人工提交固定版本（commit / digest）啟動，`mode: shadow`，**不自動阻擋合併或部署**。
- **GitHub Actions**：納入測試內容；未使用 GitHub 的專案記為 `not_applicable` 並檢查實際 CI 平台。
- **資料隔離**：未分類資料留地端 provider；測試在隔離環境執行；無未核准外傳或越權操作。

## 二、評測案例集（`evals/`）

- 至少 **60 個**漏洞／控制測試案例，涵蓋 14 個審查領域與六道閘門；每個適用領域**至少一正例與一反例**（反例用於量測誤報）。
- 至少 **1/3** 不參與提示（prompt）調整（`held_out: true`），領域與風險層級分布記錄於 `evals/split.yaml`。
- 案例格式見 `evals/README.md`。目前 94 個案例置於 `evals/cases/g0..g6/`；90 個偵測案例與 4 個失敗狀態驗證分開計分。

## 三、三組比較

固定案例、資料與預算上限，比較：

1. **工具 + 單模型**
2. **工具 + 同模型多代理**（同一 family 多角色）
3. **工具 + 不同模型多代理**（≥2 不同 family，本框架預設）

量測：召回率、精確率、共同漏報（common false negatives）、每個模型的新增有效發現、人工確認時間、成本。

## 四、驗收門檻

- 保留集（held-out）**高風險召回率不低於最佳單模型**；整體召回率目標 **+10 個百分點**；最終發現**精確率 ≥ 80%**。附樣本數與不確定性，不宣稱小樣本能證明全面安全。
- 每件正式發現都有可追溯證據；有 CVSS 的案件都有完整向量且計算可重現。
- **XSS 與 CSP 分別測試**；授權包含跨角色與跨租戶；供應鏈包含套件、建置與發布三層。
- API 失敗、工具逾時、缺帳號／文件、環境無法啟動時標示 `incomplete`，**不產生「通過」**。
- 修復驗證使用新版本，重跑原失敗案例與相關安全對照，確認漏洞關閉且控制未退化（`retest_result`）。

## 五、交付物

完整控制矩陣、審查角色與提示、證據與評分規範、JSON/SARIF 格式、測試案例集、試點比較報告，以及修復與例外處理手冊。精確模型版本於啟動時盤點（見 `config/providers.yaml`）。

## 六、比較程式與證據

`python3 scripts/compare_reviews.py --records reports/review-trial/records.jsonl --out reports/comparison.json` 只比較保留集。每組必須覆蓋相同案例，提供實際模型版本、家族、第一輪獨立審查紀錄、原始證據檔及 SHA-256、成本與人工確認秒數。缺漏、重複、未裁決或證據指紋不符時回傳 `incomplete`（退出碼 2），不宣稱跨模型增益。

輸入每列的欄位如下；`evidence_ref` 相對於 JSONL 所在目錄，原始證據需經遮罩，且不得包含金鑰。

```json
{"arm":"cross_family","case_id":"保留集案例 ID","reviewers":[{"family":"實際家族一","model":"精確版本一","state":"ran","round1_independent":true},{"family":"實際家族二","model":"精確版本二","state":"ran","round1_independent":true}],"decision":"flag","requires_human":false,"cost_usd":0.02,"human_seconds":30,"evidence_ref":"case-response.json","evidence_sha256":"原始證據檔的 SHA-256"}
```

三組代碼為 `single`、`same_family`、`cross_family`，結論為 `flag` 或 `clear`。輸出包含各組 TP／FP／FN／TN、精確率與召回率的 Wilson 95% 區間、共同漏報、跨家族新增有效案例、成本及人工時間。雜湊僅核對檔案完整性，模型身分與獨立性仍須稽核原始紀錄。程式的合成單元測試不是三組實驗結果；尚未收齊真實模型紀錄前，本專案不宣稱多模型比單模型有效。


---

<a id="english"></a>

# 12. Pilot and Evaluation

Begin in **shadow mode** before broad rollout, calibrating false positives and measuring multi-model gains over a single model. See [operation and verification](14-operation-and-verification.md#english) for reproducible procedures.

## 1. Pilot design

- **Duration:** four weeks.
- **Scope:** three representative project types, such as web/API, backend scripts, and LLM/agent applications.
- **Initiation:** humans submit a fixed commit/digest. Use `mode: shadow`; do not automatically block merges or deployments.
- **GitHub Actions:** include workflows in the review. For projects not using GitHub, mark that part `not_applicable` and inspect their actual CI platform.
- **Isolation:** unclassified data stays with local providers; tests run in isolated environments without unapproved disclosure or unauthorized actions.

## 2. Evaluation cases (`evals/`)

- At least **60** vulnerability/control cases across 14 review domains and six gates; each applicable domain needs a positive and a negative case to measure false positives.
- Hold at least **one third** out of prompt tuning (`held_out: true`). Record domain and risk-tier distribution in `evals/split.yaml`.
- Format: `evals/README.md`. The current 94 cases live in `evals/cases/g0..g6/`; score 90 detection cases separately from four failure-state checks.

## 3. Three-arm comparison

Hold cases, data, and budget caps constant:

1. Tools + one model.
2. Tools + multiple agents from the same model family.
3. Tools + multiple agents from at least two model families (the default design).

Measure recall, precision, common false negatives, each model's additional valid findings, human confirmation time, and cost.

## 4. Acceptance criteria

- Held-out high-risk recall must be no worse than the best single model. Target an overall recall gain of **10 percentage points** and final precision **≥80%**. Report sample sizes and uncertainty; a small sample cannot establish universal security.
- Every formal finding has traceable evidence. CVSS-scored findings include a complete, reproducibly calculated vector.
- Test XSS and CSP separately; authorization covers roles and tenants; supply-chain testing covers packages, builds, and releases.
- API failures, timeouts, missing accounts/documents, and startup failures are `incomplete`, never pass.
- Retest a new revision using the original failing case and related safe controls. Record `retest_result` to show the flaw is closed without weakening controls.

## 5. Deliverables

A complete control matrix, reviewer roles/prompts, evidence and scoring rules, JSON/SARIF formats, case suite, pilot comparison report, and remediation/exception procedures. Inventory exact model versions at startup (`config/providers.yaml`).

## 6. Comparison program and evidence

```bash
python3 scripts/compare_reviews.py --records reports/review-trial/records.jsonl --out reports/comparison.json
```

Only held-out cases are compared. Every arm must cover the same cases and supply actual model versions/families, independent first-round review records, raw evidence files and SHA-256 hashes, costs, and human confirmation time in seconds. Missing, duplicate, unresolved, or hash-mismatched records yield `incomplete` (exit 2); no cross-model gain is claimed.

Each JSONL row has this form. `evidence_ref` is relative to the JSONL directory. Mask raw evidence and exclude keys.

```json
{"arm":"cross_family","case_id":"held-out-case-id","reviewers":[{"family":"actual-family-one","model":"exact-version-one","state":"ran","round1_independent":true},{"family":"actual-family-two","model":"exact-version-two","state":"ran","round1_independent":true}],"decision":"flag","requires_human":false,"cost_usd":0.02,"human_seconds":30,"evidence_ref":"case-response.json","evidence_sha256":"SHA-256-of-raw-evidence"}
```

Arm codes: `single`, `same_family`, `cross_family`; decisions: `flag` or `clear`. Output includes each arm's TP/FP/FN/TN, Wilson 95% intervals for precision/recall, common false negatives, additional cross-family valid cases, costs, and human time. Hashes establish file integrity only; identity and independence still require auditing raw records. Synthetic unit tests are not three-arm experimental results. No multi-model superiority is claimed before real records are complete.
