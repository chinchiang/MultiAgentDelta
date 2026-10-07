---
name: vibesec-harness
description: 依 vibesec.yaml 執行 G0–G6 閘門、彙整發現、呼叫 reviewer sub-agents、產出 reports/；用於 "/vibesec-harness"、"跑資安閘門"、"run the security gates"
---

# /vibesec-harness — VibeSec harness agent 操作流程

你現在是 VibeSec harness agent。完整系統提示在 `config/harness/harness-agent.md`（先讀它），流程規格在 `docs/08-harness-agent.md`，審查規則在 `docs/09-multi-model-review.md`，評分與格式在 `docs/10-evidence-scoring-and-findings.md`。本 skill 只告訴你**在 Claude Code 裡怎麼做**。

## 參數

```
/vibesec-harness [--gate g1,g2,...] [--mode shadow|enforce] [--diff <base>] [--target <path>] [--target-url <url>]
```

| 參數 | 預設 | 說明 |
|---|---|---|
| `--gate` | 依事件：有 `--target-url` 或 `VIBESEC_TARGET_URL` → `g5,g6`；有 `--target` → `g1,g2,g3,g4`；否則 `g1,g2,g3,g4`；`g0` 需明示 | 只跑指定閘門；與 `vibesec.yaml gates.*.enabled` 取交集。不可用它跳過 enforce 所需的閘門（跳過的閘門在 summary 標 `untested`，不是 pass） |
| `--mode` | `vibesec.yaml` 的 `mode` | 只能 shadow → enforce；傳 `shadow` 但設定是 `enforce` 時忽略並在 summary 註明 |
| `--diff` | `origin/main` 若存在，否則 full | diff-aware 閘門的比較基準 |
| `--target` | 本 repo（`.`） | 被測專案的本機路徑（git repo 根目錄），例如 `../MultiAgentBeta`。**G0–G4** 都支援：設定、清單、政策一律取自本 repo，報告寫在本 repo 的 `reports/`（不寫進被測專案）。本 repo 的 blocking-policy `exceptions` 只核准給本 repo 路徑，掃外部專案時不套用。外部專案的 G4 LLM 審查紀錄只採信本 repo 的 `reviews/g4/external/<commit>.yaml`（見下方 G4）；G0 讀目標自己的威脅模型（見下方 G0），**不得改用本 repo 的模型或結果充數** |
| `--target-url` | `$VIBESEC_TARGET_URL` | G5 / G6 目標；必須先確認是授權的測試環境 |

## 步驟 0：讀取與檢查

```bash
TARGET="${TARGET:-.}"     # --target 的值；未給為本 repo
cat vibesec.yaml config/policy/blocking-policy.yaml config/providers.yaml
ls config/catalogs/
git -C "$TARGET" rev-parse HEAD; git -C "$TARGET" rev-parse --abbrev-ref HEAD
mkdir -p reports/raw reports/gates
for b in syft grype trivy gitleaks semgrep checkov zap-baseline.py promptfoo garak; do printf '%s: ' "$b"; command -v "$b" || echo MISSING; done
for v in VIBESEC_TARGET_URL VIBESEC_TOKEN_A VIBESEC_TOKEN_B ANTHROPIC_API_KEY OPENAI_API_KEY GEMINI_API_KEY GLM_API_KEY DEEPSEEK_API_KEY; do printf '%s: ' "$v"; [ -n "${!v}" ] && echo set || echo UNSET; done
```

任一主設定（`vibesec.yaml`、blocking policy）缺席 → 寫 `reports/summary.md` 說明後停止，exit 2。缺的工具與環境變數先記下來，稍後對應閘門記 `incomplete`。**不要安裝任何工具或套件。**

讀 `project.threat_model`（`--target` 時改讀目標的模型，見 G0）；不存在 → G0 `incomplete`，`risk_tier` 用 `vibesec.yaml` 的值並標「未核對」。存在 → 核對 `risk_tier`，計算每個 agent 的致命三要素。

## 步驟 1：逐閘門執行（固定順序 G1 → G2 → G3 → G4；G5 → G6；G0）

每個閘門：記 `started_at`；依下表執行；原生輸出存 `reports/raw/G<N>/`；每個工具記 `name / version / state / exit_code / output_ref / duration_seconds`；受 `timeout_seconds` 約束（Bash 的 `timeout` 參數）。工具缺席記 `state: missing`，逾時記 `timeout`，非零且無輸出記 `error`。

### G1 供應鏈（必須最先；通過前不得執行任何安裝指令）

```bash
# 四層快篩（存在性／相似度／安裝 hook／冷卻期）：只給 --target 時全量掃描目標專案追蹤中的 manifest 與 agent 規則檔；
# diff-aware 時改給 --changed-files <清單> --base <base>（路徑相對目標專案）。exit 1 = blocking、2 = incomplete
python3 scripts/g1_slopcheck.py --target "$TARGET" \
  --sarif reports/raw/G1/slopcheck.sarif --gate reports/raw/G1/slopcheck-gate.json > reports/raw/G1/slopcheck.json
# SBOM（VS-G1-SBOM）：從受測 commit 匯出乾淨的樹（不讀工作目錄），syft 產生兩次比對可重現，核對鎖定檔釘選的套件
# 都在 SBOM（含 npm devDependencies），結果併入上一步的 gate。缺 syft（$VIBESEC_SYFT 或 PATH）→ exit 2 incomplete
python3 scripts/g1_sbom.py --target "$TARGET" --sbom reports/raw/G1/sbom.cdx.json \
  --sarif reports/raw/G1/sbom.sarif --json reports/raw/G1/sbom.json --merge-gate reports/raw/G1/slopcheck-gate.json
grype sbom:reports/raw/G1/sbom.cdx.json -o sarif > reports/raw/G1/grype.sarif
trivy fs --scanners vuln --format sarif -o reports/raw/G1/trivy.sarif "$TARGET"
# 相依變更（diff-aware）
git -C "$TARGET" diff --name-only <base>...HEAD -- package.json package-lock.json pnpm-lock.yaml yarn.lock requirements*.txt pyproject.toml uv.lock poetry.lock
```

`package-lock.json`（v1–3）逐筆檢查，名稱相似度只對直接相依；非 npm registry 來源的條目 → `incomplete`。`pnpm-lock.yaml`、`yarn.lock` 目前沒有解析器 → slopcheck 記 `incomplete` 並列出檔名（其中的套件沒逐一檢查，不是 pass）。

對新增 / 升版的每個套件（以 lockfile 為準）：
- 查 registry（`curl -s https://registry.npmjs.org/<pkg>`、`https://pypi.org/pypi/<pkg>/json`）：不存在 → `vibesec.g1.hallucinated-package`；版本發布日距今 < `cooldown_days` → `vibesec.g1.cooldown-violation`；週下載 < `min_weekly_downloads` → `vibesec.g1.low-download-package`。查詢失敗 → G1 `incomplete`。
- 對 `popular_lists` 做字串距離（PyPI 名稱先依 PEP 503 正規化；編輯距離 ≤ 2 且不相等，相鄰易位算 1、≤ 5 字元的名稱只認 1；鎖定檔的間接相依只查黑名單）→ `vibesec.g1.hallucinated-package`；命中 `blacklist` → `hallucinated-package`。`allowlist` 不跳過檢查：只把條目 `bypass` 列出的檢查（registry_health / low_download / cooldown / blacklist / similarity）在版本相符且未過期時降為 advisory，安裝 hook 不可放行（docs/02「套件例外」）。
- 掃 `scan_agent_rule_files` 中出現的套件名（`.cursorrules`、`AGENTS.md`、`SKILL.md`、`*.md`）同上處理；`-r`、`-e`、`--index-url` 這類帶值旗標的值不是套件名。
- 讀 `package.json scripts.postinstall|preinstall|install` 與 `setup.py`：含 `curl|wget|fetch|http`、`process.env`、`~/.aws|~/.npmrc|~/.ssh|keychain`、`claude|gemini|codex` CLI 呼叫 → `vibesec.g1.postinstall-egress`。
- 每個 CVE 查 EPSS（`https://api.first.org/data/v1/epss?cve=`）與 KEV（`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`）；查不到填 `null` + `notes`；KEV 命中且版本在範圍 → `vibesec.g1.kev-hit`。

### G2 機密（永遠全歷史）

```bash
# gitleaks 全歷史（--redact）＋ .env 防護 → reports/raw/G2/{gitleaks.sarif,g2-envcheck.json} 與 G2 gate JSON
# gitleaks 缺席／失敗、目標不是 git repo 根目錄或是 shallow clone → incomplete。exit 1 = blocking、2 = incomplete
python3 scripts/g2_secrets.py --target "$TARGET" --out-dir reports/raw/G2 --gate reports/gates/G2.json
```

外部專案：目標專案自己的 `gitleaks:allow` 註解不採信，`.gitleaksignore` 會在 `status_reason` 註明待人工確認。命中的祕密：`title` / `description` 只留前 4 後 4 遮罩與 `sha256`；通過格式驗證者 → `vibesec.g2.hardcoded-secret`（blocking）。

### G3 SAST / IaC

```bash
# semgrep（vibesec.yaml semgrep_rules）+ checkov（config/checkov/.checkov.yaml）+ trivy config → reports/raw/G3/*.sarif 與 G3 gate JSON
# 任一工具缺席／逾時／失敗、目標不是 git repo 根目錄 → incomplete。exit 1 = blocking、2 = incomplete
python3 scripts/g3_sast.py --target "$TARGET" [--base <base>] --out-dir reports/raw/G3 --gate reports/gates/G3.json
```

外部專案：`# nosemgrep` 不採信（`--disable-nosem`）；checkov 掃目標追蹤中檔案的副本（去掉 `.checkov.yaml` 與 symlink），trivy 以空目錄為工作目錄，目標自己的設定不會被載入；目標的 `.semgrepignore` 與 `checkov:skip=`／`trivy:ignore` 行內註解工具仍會採信，寫進 `status_reason` 待人工確認。Semgrep 缺席 → G3 `incomplete`；checkov / trivy-config 缺席 → 對應 IaC 控制 `untested`，G3 仍 `incomplete`。SARIF 內 `rule.id` 以 `vibesec.g3.*` 開頭者沿用，否則加前綴 `semgrep:` / `checkov:` / `trivy:`。

### G4 架構與存取控制

```bash
# CI 同一段靜態檢查（rules_file_unicode、supabase_rls、agent_tool_allowlist、single_middleware_authz），在目標追蹤中檔案的副本上執行
# + VS-G4-LLM-REVIEW：本 repo 照 CI 讀 reviews/g4；外部專案讀本 repo 的 reviews/g4/external/<目標 HEAD>.yaml（見下）。exit 1 = blocking、2 = incomplete／pending
python3 scripts/g4_access.py --target "$TARGET" --out-dir reports/raw/G4 --gate reports/gates/G4.json
```

六項靜態檢查（`static_checks`）中，上面的腳本涵蓋四項；`owner_binding`、`mcp_resource_indicator` 與腳本之外的細節以 Grep / Read 在 `$TARGET` 內執行：
- `owner_binding`：ORM / SQL 查詢含 `id = ` 但同函式無 `owner_id|user_id|tenant_id` 綁定 → `vibesec.g4.missing-owner-filter`。
- `supabase_rls`：`supabase/migrations/**` 有 `create table` 但無 `enable row level security` → `vibesec.g4.supabase-rls-disabled`。
- `single_middleware_authz`：Next.js 有 `middleware.ts`，或 FastAPI 的 app middleware 做授權而沒有任何路由／router 授權依賴（`Depends`／`Security`）→ `vibesec.g4.single-middleware-authz`（腳本已涵蓋這兩種；其他框架以 Grep／Read 檢查）。
- `agent_tool_allowlist`：Agent 工具定義含 `delete|drop|execute_sql|send_email|transfer` 且無 HITL 標記 → `vibesec.g4.agent-tool-overexposure`。
- `rules_file_unicode`：`grep -P '[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{FEFF}]' .cursorrules AGENTS.md` → `vibesec.g4.rules-file-invisible-unicode`。
- `mcp_resource_indicator`：MCP server OAuth 設定無 `resource` 參數 → `vibesec.g4.mcp-missing-resource-indicator`。

然後對所有 G4 發現與威脅模型執行 LLM 審查（步驟 2），角色 `architecture`、`identity-authz`。

### G5 DAST / API（只打授權靶場）

```bash
curl -sf -m 30 "$VIBESEC_TARGET_URL/healthz" || echo UNREACHABLE
zap-baseline.py -t "$VIBESEC_TARGET_URL" -J reports/raw/G5/zap-baseline.json -c config/zap/baseline.conf
zap-api-scan.py -t "$VIBESEC_TARGET_URL/openapi.json" -f openapi -J reports/raw/G5/zap-api.json
```

api-probes（用 `curl`，每個請求與回應存 `reports/raw/G5/api-probes/*.json`）：
- `bola_idor`：以 A 建資源取 id，以 B 的 token `GET /…/<id>`；200 且含 A 的資料 → `vibesec.g5.bola-cross-account`。缺任一 token → 此控制 `untested`，G5 `incomplete`。
- `jwt_alg_none`：把 A 的 JWT header 改 `{"alg":"none"}`、去簽章後請求；200 → `vibesec.g5.jwt-alg-none`。
- `jwt_alg_confusion`：若有 `/.well-known/jwks.json`，以公鑰為 HS256 密鑰簽署；200 → `vibesec.g5.jwt-alg-confusion`。
- `ssrf_metadata`：對 URL 匯入端點送 `http://169.254.169.254/latest/meta-data/`；回應含 metadata → `vibesec.g5.ssrf-metadata`。
- `swagger_exposed` / `graphql_introspection` / `debug_stacktrace` / `rate_limit`：對應端點探測。

URL 未設或 `UNREACHABLE` → G5 整體 `incomplete`，**不得**把無回應當無漏洞。

### G6 LLM / Agent 紅隊

```bash
promptfoo eval -c config/promptfoo/tests.yaml -o reports/raw/G6/promptfoo.json --no-cache   # 不需金鑰；退出碼 100 = 有測試失敗（≠ incomplete）
# 選用生成層（需 ANTHROPIC_API_KEY 或 OPENAI_API_KEY；只允許 internal 資料可送的 provider）：
# promptfoo redteam run -c config/promptfoo/promptfooconfig.yaml -o reports/raw/G6/promptfoo-redteam.json
garak --config config/garak/vibesec.probes.yaml --report_prefix g6-garak
python3 scripts/g6_gate.py --eval reports/raw/G6/promptfoo.json --redteam-skipped "<原因>" \
  --garak-glob 'reports/raw/G6/g6-garak*.report.jsonl' --gate reports/raw/G6/g6-gate.json
```

`project.contains_llm: false` → `not_applicable`，`status_reason: "project.contains_llm is false"`。對應 `checks` → `vibesec.g6.<check-kebab>`。

### G0 威脅建模

```bash
# schema／非範本、致命三要素（證據在目標內核對，tier 取本 repo 政策）、risk_tier（不得低於 docs/01 §4 決策樹推導值；
# 本 repo 另須與 vibesec.yaml 一致）→ reports/raw/G0/g0-findings.json 與 G0 gate JSON。exit 1 = fail、2 = incomplete
python3 scripts/g0_threat_model.py --target "$TARGET" [--threat-model <file>] --out-dir reports/raw/G0 --gate reports/gates/G0.json
```

外部專案的模型依序取：`--threat-model`（可放在目標之外，例如本 repo 為它寫的模型）→ 目標 `vibesec.yaml` 的 `project.threat_model` → 目標的 `docs/threat-model.yaml`；模型與證據檔從目標追蹤中檔案的副本讀（不跟隨 symlink）。找不到 → `incomplete`（threat model missing），不得拿本 repo 的模型代替。

驗證 `project.threat_model` 符合 `schemas/threat-model.schema.json`；每個 `agents[]` 三要素皆 true 且 `mitigations` 空、`trifecta_leg_cut` null → finding `vibesec.g0.lethal-trifecta-open`（`location.kind: architecture`）；`threats[].status: open` 進 risk register。

## 步驟 2：多模型審查（呼叫 sub-agents）

需審查的發現：G4 全部；其他閘門中 `evidence_grade` E1/E2 且（`policy_tier: blocking` 或 P0/P1 候選）者。

1. 替每個發現決定資料分級（docs/08 §12）。`confidential` / `pii` 內容只能送 `allowed_data_classes` 含該級的 provider；本 repo 內的四個 sub-agent 都是 anthropic family，依 `providers.yaml` 的 `anthropic-cloud` 只收 `public, internal`。
2. 組審查包：finding JSON（去 `review`）、相關檔案路徑與行號範圍、原生輸出片段路徑、威脅模型相關元件、**catalog 片段**（從 `config/catalogs/` 擷取可引用的 control_id / CWE 列表）。
3. **Round 1（獨立）**：用 Agent tool 分別呼叫 `vibesec-architecture`、`vibesec-appsec`、`vibesec-identity`、`vibesec-supplychain`（依發現類型挑角色；G4 用 architecture + identity）。每個呼叫是**獨立的 sub-agent**，提示內不得含其他角色的輸出。要求回傳 role prompt 定義的 JSON。
4. 解析：丟棄信心欄位；catalog 外的 ID 改 `null` + `notes`；`confirm` 無 `cited_evidence` 視為 `uncertain`；記 `prompt_version`、`family: anthropic`、`provider: claude-code-subagent`、`model`（inherit 時填實際模型名）。
5. verdict 分歧或有 `uncertain` → **Round 2**：再呼叫同角色，提示附上其他角色的 rationale 與 cited_evidence（標 `reviewer-anthropic-<role>`），要求逐點回應。仍分歧 → **Round 3**。仍分歧 → `requires_human: true`，少數方 `minority: true`。不多數決。裁決交人，格式與規則見 docs/09 §12（`scripts/ruling.py request <id>` 產生請求留言；你不得自行裁決或代填 `rulings/`）。
6. **family 門檻**：Claude Code 內的 sub-agent 只算一個 family。高風險控制（blocking、P0/P1 候選、授權類、發布信任類）需第二個 family：若環境有 `OPENAI_API_KEY` / `GEMINI_API_KEY` / `DEEPSEEK_API_KEY` / `GLM_API_KEY` 且資料分級允許（`ANTHROPIC_API_KEY` 與 sub-agent 同屬 anthropic family，不算第二個），先以 `python3 scripts/review_packet.py build --base <審查包.json> --target "$TARGET" [--diff-base <sha>] --out <含程式碼的審查包.json>` 把威脅模型與受測程式碼（含行號、gitleaks 命中已遮罩）附進審查包——外部 provider 不能自己讀 repo，沒有程式碼就無法引用 file:line；gitleaks 缺席或超過大小上限時不產生審查包，照實記錄、不改送不含程式碼的審查包。再以 `python3 scripts/review_provider.py call --provider <name> --role <role> --data-class <分級> --packet <審查包.json> --out reports/raw/G4/review/round<N>-<role>-<provider>.json` 呼叫（system = 同一份 role prompt，`temperature: 0`，JSON 輸出；分級不允許時回 `refused` 且不送出任何內容），把輸出的 `provider` / `family` / `model` / `prompt_version` 記進 opinion。`state` 為 `missing` / `timeout` / `error` / `refused` 時照實記入 g4-review.yaml 的 providers，不補假意見。否則 finding `validation_status: pending`、`requires_human: true`、`notes: "only 1 family (anthropic) available"`，該控制 coverage `pending`，閘門 `incomplete`。
7. 全員 `confirm` 最多升 E2；E3 需實測（G5 HTTP 交換）或人工核對。

## 步驟 3：評分與 finding 組裝

對每個發現依 `config/harness/harness-agent.md` §5 組 Finding，並用 Python 驗證：

```bash
python3 - <<'PY'
import json, jsonschema
s = json.load(open('schemas/finding.schema.json')); d = json.load(open('reports/findings.json'))
for f in d['findings']: jsonschema.validate(f, s)
g = json.load(open('schemas/gate-result.schema.json'))
import glob
for p in glob.glob('reports/gates/G*.json'): jsonschema.validate(json.load(open(p)), g)
print('schema ok')
PY
```

優先序走 docs/10 §5 查表；`due_date = created_at + scoring.priority_sla_days[priority]`。`combine_scores: false`：不得出現任何合成分數。

## 步驟 4：寫報告

- `reports/vibesec.sarif`：`location.kind ∈ {code, dependency, config}` 的發現，每工具一個 run，欄位對映見 docs/10 §7。
- `reports/findings.json`：全部發現。
- `reports/risk_register.json`：`architecture` / `prompt` 類 + G0 open threats。
- `reports/gates/G<N>.json`：每閘門一份。
- `reports/g4-review.yaml`：G4 LLM 審查紀錄（`schemas/g4-review.schema.json`，範例 `docs/templates/g4-review.example.yaml`）：`commit` = 審查時的 HEAD（40 碼）、實際呼叫的 providers 與狀態（缺席照實記 missing／timeout／error；資料分級不允許、未送出記 refused）、coverage（至少 `VS-G4-LLM-REVIEW`）、每個 G4 發現的全部意見（含 minority；分歧 → `requires_human: true`、`validation_status: pending`，不多數決）、`recorded_by.handle` 留空字串由人填（空白 = 未經人確認，check 會列為缺口，CI 不採信）。寫完跑 `python3 scripts/g4_review.py check reports/g4-review.yaml`。`--target` 指向外部專案時，`commit` 填目標的 HEAD；目標自己的 `reviews/g4`、`rulings` 不採信（不得自證），由人確認後複製為**本 repo** 的 `reviews/g4/external/<commit>.yaml` 提交（裁決放本 repo 的 `rulings/`），只在目標 HEAD 仍是該 commit 且沒有未提交修改時採用。**你不得把它寫進 `reviews/`**（規則 9）：由人確認後複製為 `reviews/g4/<commit>.yaml` 提交，CI 的 G4 job 才會把 `VS-G4-LLM-REVIEW` 從 pending 推進到結論；之後若再改 `reviews/g4/`、`rulings/` 以外的檔案，紀錄即過期。
- `reports/summary.md`：固定七節（閘門狀態矩陣 / INCOMPLETE / 致命三要素 / 發現表 / 控制覆蓋率 / 需人工裁決 / Exit code），版面見 `config/harness/harness-agent.md` §7。INCOMPLETE 節永遠存在。

## 步驟 5：exit code 與回覆

- `0`：shadow；或 enforce 且無 blocking 發現、無 blocking 閘門 incomplete。
- `1`：enforce 且有 `policy_tier: blocking` 且 `validation_status != refuted` 的發現。
- `2`：enforce 且 `incomplete_gate_is_blocking_in_enforce`（預設 G1、G2）內的閘門 incomplete；或主設定缺席。
- 同時 1 與 2 → 回 1，summary 兩者都列。

最後回覆使用者：exit code、一行理由、INCOMPLETE 清單、blocking 發現數、`requires_human` 數、報告路徑。不要只說「完成」。

## 禁止

1. 不停用 / 跳過 / 放寬 `enabled: true` 的閘門；不編輯 `vibesec.yaml`、`blocking-policy.yaml`、`providers.yaml`、catalogs。
2. 工具缺席 / 逾時 / API 失敗 / 缺 token / 缺文件 / 目標不可達 → `incomplete`，永不 `pass`；`not_applicable` 只用於設計上不適用且附理由。
3. 不猜 ID；不合成分數；不把模型信心寫進任何欄位；E 等級與 validation_status 分開。
4. 不多數決；不刪少數意見；family < 2 不放行高風險控制。
5. 不把 `confidential` / `pii` 送到不允許的 provider；不降級資料分類。
6. 不對 `VIBESEC_TARGET_URL` 以外的主機發探針。
7. 不安裝任何工具或套件；G1 完成前不執行安裝指令。
8. 報告中祕密只留遮罩與指紋。
9. 不修改被測專案的程式碼（本 skill 只讀與寫 `reports/`）；`--target` 指向外部專案時，報告仍寫在本 repo 的 `reports/`。
