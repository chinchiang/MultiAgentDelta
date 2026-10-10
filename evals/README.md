# 評測案例集（evals/）

量化多模型審查相對單模型的增益，並校準誤報。對應 `docs/12-pilot-and-evaluation.md`。

## 案例格式

每個 YAML 檔一個案例，置於 `evals/cases/g<N>/`：

```yaml
id: g5-bola-pos-01              # g<gate>-<domain>-<pos|neg>-<序號>
gate: G5
domain: authorization          # 對應 14 審查領域之一
title: 跨帳號讀取他人資源
input:                         # 餵給閘門/工具的輸入（程式片段、HTTP 請求或 prompt）
  kind: http                   # code | http | prompt | manifest | iac | config
  target: /users/{id}/notes
  steps:
    - login as bob
    - GET /users/1/notes with bob token   # alice=1, bob=2
expected:
  should_flag: true            # true=正例（應命中）, false=反例（不應命中，用於量測誤報）
  control_id: ASVS5-V8.1
  rule_id: vibesec.g5.bola-cross-account
  policy_tier: blocking
  gate_status: incomplete      # 選填：工具缺席／逾時／缺金鑰等情境的預期閘門狀態（pass|fail|incomplete|not_applicable）
held_out: false                # true 者不參與 prompt 調整（至少 1/3）；須與 split.yaml 一致
notes: 靶場 examples/vulnapp 可重現。
```

## 規則

- 每個適用領域**至少一正例與一反例**。
- 至少 **1/3** 案例 `held_out: true`；清單集中於 `evals/split.yaml`。
- 總數目標 **≥ 60**（目前 100）。
- `domain` 使用 14 審查領域的固定代碼：`application_architecture`、`general_vulnerabilities`、`xss`、`csp`、`authentication`、`authorization`、`dependency`、`build_supply_chain`、`github_actions`、`secret_exposure`、`input_validation`、`error_handling`、`data_integrity`、`ai_agent_security`。
- `gate_status` 案例驗證閘門在工具／環境失敗時回報的狀態：例如「incomplete ≠ pass」（工具或環境無法完成時，閘門必須回報 incomplete，而非 pass），或「已實測的失敗不得因其他層缺金鑰而被改寫成 incomplete」（`gate_status: fail`）。以 `input.integration` 指定整合層情境；`expected.coverage`（控制 → 狀態）與 `expected.status_reason_contains` 可進一步要求某個覆蓋項的狀態與 status_reason 的內容。
- 含隱形字元或假金鑰的 fixture 以 YAML 跳脫或佔位值表示，避免觸發本 repo 自身的 G2／G4 掃描。
- `scripts/validate.py` 檢查：id 與檔名一致、gate 與目錄一致、split 與 `held_out` 欄位一致、held_out ≥ 1/3、每領域正反例、ID 存在於 catalogs。
- `expected.control_id` / `rule_id` 必須存在於 `config/catalogs/` 與規則集，否則評測視為設定錯誤。

## 三組比較

以 `evals/split.yaml` 的 held-in 子集調整 prompt，held-out 子集量測：召回率、精確率、共同漏報、每模型新增有效發現、人工確認時間、成本。三組為：工具+單模型、工具+同模型多代理、工具+不同模型多代理。

## 執行評測（`scripts/run_evals.py`）

```bash
python3 scripts/run_evals.py --md reports/evals.md --json reports/evals.json          # 全部案例
python3 scripts/run_evals.py --split held_out                                          # 只量測 held-out
python3 scripts/run_evals.py --no-network                                              # 不查 registry（G1 案例記 untested）
```

- 只有「預期規則確實由本機執行器實作」的案例才執行並計分：
  - `semgrep`：`kind: code|iac` 且 `rule_id` 存在於 `config/semgrep/vibesec-rules.yaml`（`-js` 等語言變體歸回同一規則）。
  - `slopcheck-rules-file`：G1 `vibesec.g1.rules-file-unknown-package` 案例，snippet 寫成 `input.path` 的規則檔（例如 `.cursorrules`），以 `g1_slopcheck.py --rules-file` 實測並查 live registry；`--no-network` 時記 untested。
  - `g1-kev`：G1 `vibesec.g1.kev-hit` 案例，`input.grype_matches` 是 grype 比對結果 fixture，評測時即時下載 CISA KEV feed，以 `scripts/g1_kev.py` 判定。驗證比對與判定邏輯，不含 grype 本身（nightly 以真實 grype 執行）；`--no-network` 或下載失敗時記 untested／incomplete。
  - `slopcheck`：G1 manifest 案例，且只用 `ecosystem` / `added`（含 `published_hours_ago` 等合成 fixture 的案例記 untested）。
  - `g1-fixture`：G1 manifest 案例帶合成欄位 `published_hours_ago`（`vibesec.g1.cooldown-violation`）或 `package_json.scripts`（`vibesec.g1.postinstall-egress`）。直接呼叫 `scripts/g1_slopcheck.py` 的判定函式 `cooldown_finding`／`install_hook_finding`（與 registry 查詢後走的是同一段邏輯與同一份 `cooldown.yaml` 樣式）；registry 查詢本身不在此驗證。
  - `g0-trifecta`：G0 `vibesec.g0.lethal-trifecta-open` 案例，`input.threat_model` 為 `schemas/threat-model.schema.json` 的 `agents[]` 結構。呼叫 `scripts/g0_trifecta.py` 的 `trifecta_findings`（`validate.py` 對本 repo 威脅模型用同一個函式）。
  - `g4-static`：G4 的 `kind: code|iac` 案例，且 `rule_id` 由 `pr-gates.yml` 的 G4 靜態檢查實作。執行器把 snippet 寫回 `input.path` 的原路徑（保留目錄，例如 `.github/copilot-instructions.md`），再執行 workflow 中**同一份**程式碼；所有 SARIF 等級都算偵測。
  - `gitleaks`／`checkov`：預期規則在 `config/catalogs/cwe-map.yaml` 有 `implemented_by`（例如 `checkov:CKV2_VIBESEC_1`）。執行器以 CI **同一份**設定檔（`config/gitleaks.toml`、`config/checkov/.checkov.yaml` 含 check allow-list 與自訂政策）掃 fixture，再依 `implemented_by` 對回 vibesec 規則；allow-list 外的檢查不算偵測。本機沒有 gitleaks 時可設 `VIBESEC_GITLEAKS=<路徑>`；nightly 會下載固定版本並驗證 SHA-256。
  - `env-check`：`vibesec.g2.env-not-ignored`。在暫存 git repo 依 `input.files`／`input.gitignore` 建立並追蹤檔案，再執行 `pr-gates.yml` 中**同一份** `.env` 檢查步驟。
  - `vulnapp`：標記 `input.target_app: vulnapp` 的 G5／G6 案例。執行器在 127.0.0.1 隨機埠啟動 `examples/vulnapp`；G5 執行 staging workflow 中**同一份** api-probes 程式碼（level=note 的「未能實測」結果不算偵測），G6 把 prompt 送到 `/chat`，以與 `config/promptfoo/tests.yaml` 相同的決定性斷言判定。只有靶場確實可重現該行為的案例才可標記；描述假想目標（例如期望 403 的反例、靶場沒有的端點）的案例維持 untested。`input.target_app: vulnapp-patched` 的案例改以 `VIBESEC_VULNAPP_MODE=patched` 另起一個實例，作為同一探針的反例。`--no-target` 可跳過。G6 的檢索文件（`input.retrieved_doc`）以 `context` 欄位送出，與 promptfoo 的 `{{document}}` 相同，靶場把它併入模型輸入；`input.tools` 以 `tools` 欄位送出（模擬 function calling）。
  - `zap`：回應標頭案例（`input.kind: config` ＋ `input.headers`），且預期規則由 ZAP 實作（cwe-map `implemented_by: zap:<id>`，例如 `vibesec.g3.missing-csp` ← `zap:10038`）。在 127.0.0.1 起一個回傳案例標頭的 HTML stub，以 docker 跑 ZAP baseline（映像與 staging 的 `zaproxy/action-baseline` 預設相同，可用 `VIBESEC_ZAP_IMAGE` 覆寫；設定檔同為 `config/zap/api-scan.conf`），再以 `scripts/g5_zap.py`（staging 同一支）對回 vibesec 規則。每案約 30 秒；本機沒有 docker 或 daemon 無法連線 → untested。
  - `integration`：`expected.gate_status` 案例，依 `input.integration` 以受控情境執行 CI **同一支**判定程式，比對閘門結果 JSON：
    - `g1-registry-timeout`：`g1_slopcheck.py --gate` 經「接受連線但永不回應」的本機 HTTPS proxy 查 registry，查詢真的逾時（約 30 秒；不需外網）。
    - `g5-endpoint-405`：staging workflow 中同一份 G5 api-probes 打本機 stub（`/openapi.json` 回 200、其餘一律 405）。
    - `g6-gate`：`g6_gate.py` 吃依 `config/promptfoo/tests.yaml` 組出的 promptfoo 結果，以及 `input.fixture` 指定的 redteam／garak／成本探針情境。
    結果記 **STATUS_OK**（閘門狀態、預期 fail 時的發現、`expected.coverage`、`expected.status_reason_contains` 皆相符）或 **STATUS_WRONG**，另列「狀態驗證」欄，不計入召回率／精確率。
- 其餘案例（未標記 `target_app` 的 `http`、`prompt`、`config`，或沒有本機執行器的規則）記為 **untested** 並列出原因（含 `config/catalogs/cwe-map.yaml` 的 `implemented_by`，指出實際由誰實作）；執行器失敗記 **incomplete**。兩者都不計入召回率／精確率，也不算通過。
- 金鑰類 fixture 用佔位符（`{{FAKE_ANTHROPIC_KEY}}`、`{{FAKE_OPENAI_KEY}}`），由執行器在暫存檔中展開，repo 內不放金鑰形字串。
- 程式碼 fixture 需包含規則的適用脈絡（例如 `missing-owner-filter` 只在路由處理函式內生效），否則反例會「空洞地」通過。

## Nightly 退步偵測

`nightly-full.yml` 的 `evals` job 每晚執行 `run_evals.py --baseline evals/baseline.yaml`。以下任一情況會讓 job 失敗（退出碼 1）：

- 出現任何 FP、FN 或 STATUS_WRONG（閘門狀態錯誤）；
- `evals/baseline.yaml` 列出的案例變成 `untested` 或 `incomplete`，例如 semgrep 沒裝好、靶場起不來、registry 查詢失敗。

這些情況都是「沒測到」，不算通過。結果會寫進 job summary，並上傳成 `vibesec-nightly-evals` artifact。

任一 nightly job 失敗或被取消時，`notify` job 會開一張追蹤 issue（已有未關閉的就改成留言，不重複開），內容列出各 job 結果、相對 baseline 的退步清單和 run 連結；之後 nightly 恢復全綠時會自動留言並關閉。只在 `main` 上執行，分支上的手動試跑不會開 issue。

新增可執行的案例後，先跑 `python3 scripts/run_evals.py --write-baseline evals/baseline.yaml` 重新產生 baseline，人工檢查差異後再提交。從 baseline 移除案例等於放寬檢查，必須由人類在獨立 PR 中決定。
