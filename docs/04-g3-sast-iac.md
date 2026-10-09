
[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# 04 G3 SAST 與 IaC（白箱；每次 PR）

| 項目 | 值 |
|---|---|
| 閘門 ID | `G3` |
| 性質 | 白箱、確定性（規則 + 污點分析）；PR diff-aware < 5 分鐘；夜間全量 |
| 設定 | `vibesec.yaml` → `gates.g3_sast_iac`（`diff_aware: true`、`tools: [semgrep, checkov, trivy-config]`、`semgrep_rules: [config/semgrep/vibesec-rules.yaml, p/owasp-top-ten, p/security-audit]`、`semgrep_taint_mode: true`、`nightly_full: [codeql]`、`timeout_seconds: 900`） |
| 規則 / 設定 | `config/semgrep/vibesec-rules.yaml`、`config/checkov/.checkov.yaml`、`config/checkov/custom/imdsv2_required.yaml`、`config/checkov/custom/cors_wildcard.yaml` |
| 負責 | DevOps / 平台（CI 整合）、AppSec（規則） |

## 對抗成因

1. **訓練資料偏差**：公開程式碼中字串拼接 SQL / shell / HTML 的範例遠多於參數化寫法，模型因此偏好 `f"SELECT … {name}"`、`os.system("ls " + path)`、`el.innerHTML = reply`。Veracode 量測 AI 生成程式碼對 XSS 的防禦率僅 14%；CWE-79 是 MITRE 2025 CWE Top 25 第 1 名。
2. **上下文破碎**：模型在一個檔案把 `request.args["q"]` 存進物件，在另一個檔案把它拼進 SQL；單檔單函式的檢查看不到這條路徑。更新的來源是 **LLM 輸出**：AI 應用把 `completion.choices[0].message.content` 當可信字串直接丟進 `db.query` 或 DOM，形成「間接注入 → SQLi / XSS」的新路徑（OWASP LLM05 Improper Output Handling）。
3. **IaC 也是 AI 寫的**：Terraform / Dockerfile / K8s manifest 由 AI 產生時常省略 `metadata_options`、用 root 跑容器、CORS 設 `*`，為 SSRF 讀 `169.254.169.254` 鋪路。

## 觸發時機與性質

| 時機 | 範圍 | 工具 | 時間目標 |
|---|---|---|---|
| 每次 PR（`diff_aware: true`） | 變更檔 + 其直接相依 | Semgrep（taint）、Checkov、`trivy config` | **< 5 分鐘**（超過 → 縮 ruleset，不是關閉） |
| 夜間（`nightly_full: [codeql]`） | 全 repo | CodeQL（跨檔跨函式）、Semgrep 全量、Checkov 全規則 | 不限 |
| 手動 | 指定目錄 | 同上 | — |

性質：各規則的基礎層級與 L3 覆寫，以 `config/policy/blocking-policy.yaml` 為準；高確定性並不代表一律 blocking。工具缺席 / 逾時 → `incomplete`。

## 核心任務

### 1. 跨檔跨函式污點分析：Source → Sink

| 角色 | 內容（`vibesec-rules.yaml` 的 `pattern-sources` / `pattern-sinks`） |
|---|---|
| **Source（不可信）** | HTTP：`request.args/form/json/headers/cookies`、`req.query/body/params/headers`、FastAPI / Flask 路由函式參數、Next.js `searchParams`、`await req.json()`。**LLM 輸出**：`resp.choices[i].message.content`、`msg.content[i].text`、`client.chat.completions.create()`、`client.messages.create()`、`completion()`、`llm.invoke()`、`agent.run()`、`generateText()`、tool call `arguments` |
| **Sink（危險）** | SQL：`cursor.execute/executemany`、`session.execute(text(…))`、`text()`、`Model.objects.raw()`、`db.query/raw/execute`、Prisma `$queryRawUnsafe`。Command：`subprocess.*(shell=True)`、`os.system/popen`、`child_process.exec/execSync`。HTML：`innerHTML/outerHTML/insertAdjacentHTML/document.write`、`dangerouslySetInnerHTML`、`Markup()`、`render_template_string()`、`HTMLResponse()`。另有 `eval`、`pickle.loads`、`yaml.load` 由 `p/security-audit` 涵蓋 |
| **Sanitizer** | `int()`、`uuid.UUID()`、`bindparam()`、`sql.Identifier()`、`shlex.quote()`、`DOMPurify.sanitize()`、`markupsafe.escape()`、`bleach.clean()` |

Semgrep 預設把「函式呼叫的汙點參數」傳播到回傳值，所以 `"…{}".format(x)`、`" + x`、f-string 都會傳遞污點；跨檔則需 Semgrep Pro 的 interfile 分析或 CodeQL。

### 2. 工具分工

| 能力 | Semgrep CE | Semgrep Pro | CodeQL |
|---|---|---|---|
| 單檔單函式污點 | ✔ | ✔ | ✔ |
| 跨函式（同檔） | 部分 | ✔ | ✔ |
| **跨檔跨模組**（上下文破碎的核心） | ✘ | ✔（interfile） | ✔ |
| 速度（中型 repo diff） | 秒–分 | 分 | 10 分–小時 |
| 授權 | LGPL 規則引擎 + 社群規則 | 商用 | GitHub 公開 repo 免費；私有需 GHAS |
| 自訂規則難度 | 低（YAML） | 低 | 高（QL） |
| 在 vibesec 的位置 | L1 PR 階段 | L2 / L3 PR 階段 | 全層級夜間全量 |

其他可選：SonarQube（AI Code Assurance 品質閘門）、Snyk Code（ML + 符號執行，IDE 體驗佳，商用）。工具原生規則 `rule_id` 前綴 `semgrep:` / `checkov:` / `trivy:`；vibesec 自訂規則用 `vibesec.g3.*`。

### 3. IaC 三件必查

**IMDSv2**（`vibesec.g3.imdsv1-allowed`，CWE-918，blocking）。IMDSv1 讓任何 SSRF 直接 GET 取得實例角色憑證；IMDSv2 要求先 PUT 拿 session token，SSRF 通常做不到：

```hcl
resource "aws_instance" "app" {
  ami           = var.ami
  instance_type = "t3.small"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"   # ← IMDSv2 only；CKV_AWS_79 / CKV2_VIBESEC_1
    http_put_response_hop_limit = 1            # 容器內的 SSRF 也拿不到（CKV_AWS_341）
  }
}
```

`aws_launch_template` 同樣要有 `metadata_options`。G5 會用 URL 匯入端點對 `http://169.254.169.254/latest/meta-data/` 實測（白箱 → 黑箱）。

**CORS 萬用字元**（`vibesec.g3.cors-wildcard`，CWE-942，advisory）。IaC 層由 `CKV2_VIBESEC_2` 檢查 `aws_apigatewayv2_api.cors_configuration.allow_origins`、`aws_s3_bucket_cors_configuration.cors_rule.allowed_origins`、`aws_lambda_function_url.cors.allow_origins` 不含 `*`；程式層（`CORSMiddleware(allow_origins=["*"], allow_credentials=True)`、Express `cors({origin: true, credentials: true})`）由 `p/security-audit` 與 G5 回應標頭驗證。修法：明列來源；需要憑證時絕不可 `*`。

**Dockerfile root**（`vibesec.g3.dockerfile-root-user`，CWE-250，advisory；`CKV_DOCKER_3` / `CKV_DOCKER_8`）：

```dockerfile
FROM python:3.12-slim
RUN useradd --create-home --uid 10001 app
USER app             # ← 最後一個 USER 不得為 root
```

另：`CKV_DOCKER_7` 禁 `:latest`、`CKV_DOCKER_4` 用 COPY 不用 ADD；K8s `CKV_K8S_23` 非 root、`CKV_K8S_20` 禁 privilege escalation。

### 4. 其他 vibesec 規則（G3 範圍）

| 規則 | 偵測 | CWE | 層級 |
|---|---|---|---|
| `vibesec.g3.sql-string-concat`（py / js） | 污點 → SQL sink | CWE-89 | blocking |
| `vibesec.g3.sql-fstring-execute` | `execute(f"…")` / `%` / `.format` / `+`，無需來源 | CWE-89 | blocking |
| `vibesec.g3.command-injection`（py / js） | 污點 → shell | CWE-78 | blocking |
| `vibesec.g3.xss-innerhtml`（js）、`vibesec.g3.xss-unescaped-render-py` | 污點（含 LLM 輸出）→ HTML sink | CWE-79 | advisory |
| `vibesec.g3.jwt-alg-none`（py / js） | `algorithms=["none"]`、`verify=False`、`verify_signature: False`、以 `jwt.decode()` 結果做授權 | CWE-347 | blocking |
| `vibesec.g3.jwt-alg-confusion`（py / js） | `algorithms` 同時含 HS256 與 RS256 | CWE-347 | advisory |
| `vibesec.g3.actions-unpinned-action` | `uses: owner/repo@ref`，ref 非 40 位 commit SHA（workflow 與 composite `action.yml`；`./` 與 `docker://` 除外） | CWE-829 | advisory |
| `vibesec.g3.actions-pull-request-target` | `pull_request_target` 觸發卻引用 PR head／title／body／`head_ref` | CWE-94 | advisory |
| `vibesec.g2.hardcoded-llm-key` | 同一規則檔內的 G2 第二道 | CWE-798 | blocking |
| `vibesec.g4.*` | G4 的靜態部分（owner filter、RLS、agent tool）也由這支規則檔執行，但結果歸 G4 | — | — |

## 自動化作法

```bash
# ---- PR 階段（diff-aware）----
# 方式 A：semgrep ci（自動取 PR base、只掃變更、產 SARIF；需 SEMGREP_APP_TOKEN 才能用 Pro 與 interfile）
semgrep ci --config config/semgrep/vibesec-rules.yaml --config p/owasp-top-ten --config p/security-audit \
  --sarif --output reports/semgrep.sarif --metrics=off

# 方式 B：純 CLI（無 App）
BASE=$(git merge-base HEAD origin/main)
semgrep --config config/semgrep/vibesec-rules.yaml --config p/owasp-top-ten --config p/security-audit \
  --baseline-commit "$BASE" --sarif -o reports/semgrep.sarif --timeout 300 --max-memory 4000 .

# Checkov：Terraform / Dockerfile / K8s / GitHub Actions（soft-fail 由 harness 決定 exit code）
checkov -d . --config-file config/checkov/.checkov.yaml          # 輸出 reports/checkov/results_sarif.sarif

# Trivy misconfig（第二意見；與 Checkov 重疊處以 Checkov 為準）
trivy config . --format sarif --output reports/trivy-config.sarif --severity HIGH,CRITICAL

# ---- 夜間全量 ----
semgrep --config config/semgrep/vibesec-rules.yaml --config p/owasp-top-ten --config p/security-audit \
  --sarif -o reports/semgrep-full.sarif .
# CodeQL（nightly-full.yml 使用 github/codeql-action；本機等價）
codeql database create /tmp/db --language=python,javascript --source-root .
codeql database analyze /tmp/db codeql/python-queries:codeql-suites/python-security-extended.qls \
  codeql/javascript-queries:codeql-suites/javascript-security-extended.qls --format=sarif-latest --output=reports/codeql.sarif
checkov -d . --config-file config/checkov/.checkov.yaml --check ''   # 清空 allow-list 跑全規則
```

掃其他專案（本機 harness；CI 的 G3 jobs 只掃本 repo）：

```bash
python3 scripts/g3_sast.py --target ../MultiAgentBeta [--base <ref>] --out-dir reports/raw/G3 --gate reports/gates/G3.json
```

以本 repo 的設定對目標跑三個工具，再由 `scripts/sarif_gate.py` 推導 G3 gate JSON（同一份規則對應、tier、coverage）；任一工具缺席／逾時／失敗、目標不是 git repo 根目錄 → `incomplete`。`--base` 只讓 semgrep diff-aware（`--baseline-commit`），checkov／trivy 仍全量。被測專案自己的設定不採信：

| 工具 | 做法 | 原因 |
|---|---|---|
| semgrep | 在目標根目錄掃 `.`；外部專案加 `--disable-nosem` | `# nosemgrep` 是目標自己的抑制。目標的 `.semgrepignore` semgrep 一定會讀（沒有公開選項可關）→ 寫進 `status_reason` 待人工確認 |
| checkov | 掃目標**追蹤中檔案的暫存副本**（去掉 `.checkov.yaml`／`.checkov.yml` 與 symlink），工作目錄為空的暫存目錄；SARIF 路徑改回相對目標根目錄 | checkov 會自動載入被掃目錄與工作目錄的 `.checkov.yaml`，可停用檢查，或以 `external-checks-dir` 載入並**執行**目標的 Python 檢查；symlink 可能指向主機上的檔案 |
| trivy | `trivy config <target>`，工作目錄為空的暫存目錄 | trivy 從工作目錄讀 `.trivyignore`／`trivy.yaml` |

外部專案也不套用本 repo blocking-policy 的 `exceptions`；`checkov:skip=`、`trivy:ignore` 行內註解工具一定會採信 → 列進 `status_reason`。`config/checkov/.checkov.yaml` 的 `skip-path`（含本 repo 靶場路徑）對所有目標相同。

工作流程對應：`pr-gates.yml`（方式 A 或 B + Checkov + Trivy）、`nightly-full.yml`（CodeQL + 全量）。所有 SARIF 由 harness 合併進 `reports/vibesec.sarif`，`rule_id` 對 `config/catalogs/cwe-map.yaml` 補 CWE / control_id。

## 工具與設定檔

| 工具 | 用途 | 設定 |
|---|---|---|
| Semgrep CE / Pro（semgrep.dev） | 污點分析、自訂規則、PR 首選 | `config/semgrep/vibesec-rules.yaml` + `p/owasp-top-ten` + `p/security-audit` |
| CodeQL | 夜間跨檔跨函式 | `nightly-full.yml` |
| Checkov | Terraform / Dockerfile / K8s / GHA / secrets | `config/checkov/.checkov.yaml`、`config/checkov/custom/*.yaml` |
| Trivy（`trivy config`） | IaC 第二意見 | — |
| `scripts/g3_sast.py` | 本機／harness：三個工具 → G3 gate JSON；`--target` 掃其他專案 | 同上三份設定 |
| Dependabot（github-actions） | 已釘 SHA 的 Actions 自動升級 PR（每週、cooldown 14 天，與 G1 一致）；升級 PR 照常跑閘門 | `.github/dependabot.yml` |
| KICS（可選） | IaC 第三意見；Terraform / CloudFormation / Ansible | — |

## 阻擋政策

CI 的閘門狀態由 `pr-gates.yml` summary job 以 `scripts/sarif_gate.py` 從semgrep、Checkov、Trivy config 的 SARIF推導（gate JSON，`schemas/gate-result.schema.json`）：外部工具規則經 `config/catalogs/cwe-map.yaml` 的 `implemented_by` 對回 vibesec 規則，tier 依 `config/policy/blocking-policy.yaml`（含 `tier_overrides` 與未過期的 `exceptions`）；有 blocking → `fail`；任一工具輸出缺席或無法解析 → `incomplete`；其餘 → `pass`。enforce 模式下 incomplete 是否擋 merge 依政策的 `incomplete_gate_is_blocking_in_enforce`。

| 條件 | 層級 |
|---|---|
| `vibesec.g3.sql-*`、`command-injection`、`xss-*`、`jwt-alg-*`、`imdsv1-allowed` | blocking |
| `semgrep:` 規則 severity ERROR 且 metadata.confidence HIGH | blocking |
| `checkov:CKV_AWS_79`、`CKV2_VIBESEC_1`、`CKV_AWS_41/45/46`（硬編碼祕密） | blocking |
| `vibesec.g3.cors-wildcard`、`dockerfile-root-user`、其他 Checkov / Trivy misconfig | advisory |
| Semgrep 逾時（`timeout_seconds: 900`）或規則載入失敗 | `incomplete` |
| 白箱靜態發現 → 由 G5 / G6 證實可利用 | `evidence_grade` E1/E2 → E3，priority 依政策升級 |

`soft-fail: true` 只是讓 Checkov 不自行中止 job；是否擋 PR 由 `config/policy/blocking-policy.yaml` 決定。

## 對應控制（ASVS、CWE、LLM Top 10、MAESTRO）

| 類型 | ID |
|---|---|
| ASVS 5.0（節層級，自編） | `ASVS5-V1.1` 輸出編碼、`ASVS5-V1.2` 注入防範、`ASVS5-V1.3` 淨化 / SSRF / eval、`ASVS5-V1.4` 反序列化 / XXE、`ASVS5-V2.2` 輸入驗證、`ASVS5-V3.3` CORS / CSP、`ASVS5-V5.2` 檔案路徑、`ASVS5-V9.1` JWT、`ASVS5-V13.2` 後端通訊 / IMDS |
| CWE | `CWE-89`、`CWE-78`、`CWE-79`、`CWE-347`、`CWE-918`、`CWE-942`、`CWE-250`、`CWE-798` |
| LLM Top 10 2025 | `LLM05:2025` Improper Output Handling（LLM 輸出為污點來源） |
| MAESTRO | `MAESTRO-L4` Deployment & Infrastructure（IMDSv2、容器 root） |

## 驗證方式

1. **規則語法**：`semgrep --validate --config config/semgrep/vibesec-rules.yaml`（本 repo 已驗證：18 條規則、0 錯誤）。
2. **正例 / 反例 fixture**（`evals/`）：
   - `cur.execute(f"… {q}")` → `sql-fstring-execute` + `sql-string-concat`；`cur.execute("… %s", (q,))` → 無。
   - LLM 輸出 `+` 拼接 → `cur.execute(sql)` → `sql-string-concat`（證明 LLM 來源有效）。
   - `el.innerHTML = r.choices[0].message.content` → `xss-innerhtml`；`DOMPurify.sanitize()` 後 → 無。
   - `jwt.decode(t, k, algorithms=["HS256","RS256"])` → `jwt-alg-confusion`；`["RS256"]` → 無。
   - Terraform 無 `metadata_options` → `CKV_AWS_79` + `CKV2_VIBESEC_1`；`http_tokens = "required"` → 無。
3. **Checkov 自訂政策載入**：`checkov -d evals/iac --config-file config/checkov/.checkov.yaml --list | grep CKV2_VIBESEC` 顯示兩條。
4. **時效**：PR 階段 wall-clock < 5 分鐘；超過時先移除 `p/security-audit` 的低信心規則而非關閉閘門。
5. **跨檔案例**：source 在 `routers/`、sink 在 `services/` 的 fixture，CE 漏報、CodeQL / Pro 命中 → 在 summary 標記「需夜間全量」，不得因 CE 漏報記 pass。
6. **SARIF 完整性**：每筆結果有 `ruleId`、`locations[].physicalLocation`、`properties.cwe`；上傳 Code Scanning 後能在 PR 看到註解。


---

<a id="english"></a>

# 04 G3 SAST and IaC (White-Box; Every PR)

G3 is deterministic rule/taint analysis: diff-aware PR checks target under five minutes; nightly scans cover the whole repository. Configure `gates.g3_sast_iac`: Semgrep, Checkov, Trivy config, taint mode, nightly CodeQL, 900-second timeout. Rules: `config/semgrep/vibesec-rules.yaml`, `p/owasp-top-ten`, `p/security-audit`; IaC configuration and custom IMDSv2/CORS rules live in `config/checkov/`. DevOps integrates; AppSec maintains rules.

## Causes addressed

Training examples favor concatenated SQL/shell/HTML over safe APIs; reported AI XSS defense is only 14%, and CWE-79 leads MITRE's 2025 Top 25. Fragmented context hides cross-file paths from request input to sinks. **LLM output is also untrusted input**: completions passed to SQL/DOM create indirect-injection-to-SQLi/XSS paths (`LLM05`). AI-generated Terraform/Docker/Kubernetes often omits IMDS controls, runs as root, or enables wildcard CORS.

## Triggers and nature

PRs scan changes/direct dependencies with Semgrep, Checkov, and Trivy; nightly adds full CodeQL, Semgrep, and Checkov. Manual scans target selected directories. Tune low-value rules if PR latency exceeds five minutes; do not disable gates. Missing tools/timeouts are incomplete. Actual blocking/advisory tiers come from policy, not scanner severity alone.

## Core tasks

### 1. Source-to-sink taint analysis

| Role | Examples |
|---|---|
| Untrusted HTTP sources | request args/form/JSON/headers/cookies; Express query/body/params; FastAPI/Flask route arguments; Next.js searchParams/request JSON |
| Untrusted LLM sources | choices/message content; Anthropic content text; completion/message creation; `completion()`, `llm.invoke()`, `agent.run()`, `generateText()`, tool-call arguments |
| SQL sinks | cursor execute/executemany, session execute/text, raw ORM queries, db query/raw/execute, Prisma `$queryRawUnsafe` |
| Command sinks | subprocess with `shell=True`, os.system/popen, child_process exec/execSync |
| HTML sinks | innerHTML/outerHTML/insertAdjacentHTML/document.write, dangerouslySetInnerHTML, Markup, render_template_string, HTMLResponse |
| Other sinks | eval, pickle.loads, yaml.load via security-audit rules |
| Recognized sanitizers | int, UUID, bindparam, sql.Identifier, shlex.quote, DOMPurify, markupsafe.escape, bleach.clean (appropriate to their contexts) |

Semgrep propagates taint through formatting, concatenation, and f-strings. Cross-file analysis requires Pro interfile support or CodeQL.

### 2. Tool responsibilities

| Capability | Semgrep CE | Semgrep Pro | CodeQL |
|---|---|---|---|
| Single-function taint | Yes | Yes | Yes |
| Same-file interprocedural | Partial | Yes | Yes |
| Cross-file/modules | No | Yes | Yes |
| Typical speed | Seconds/minutes | Minutes | Ten minutes to hours |
| Licensing | LGPL engine/community rules | Commercial | Public GitHub free; private use requires an eligible plan |
| Custom rules | YAML, lower effort | YAML, lower effort | QL, higher effort |
| Role | L1 PRs | L2/L3 PRs | Full nightly scans at all tiers |

Optional SonarQube AI Code Assurance or Snyk Code can complement the chain. Preserve native prefixed IDs; custom rules use `vibesec.g3.*`.

### 3. Required IaC checks

**IMDSv2:** `vibesec.g3.imdsv1-allowed`, CWE-918, blocking. Require `metadata_options.http_tokens = "required"` for instances and launch templates; use `http_put_response_hop_limit = 1` where applicable. IMDSv1 makes credentials accessible through simple GET-based SSRF; IMDSv2's token exchange raises the barrier. Relevant checks: CKV_AWS_79, CKV2_VIBESEC_1, CKV_AWS_341. G5 tests metadata access through authorized URL-import endpoints.

**CORS:** `cors-wildcard`, CWE-942, advisory under base policy. CKV2_VIBESEC_2 covers API Gateway v2, S3 CORS, and Lambda Function URLs. Application patterns such as wildcard origins with credentials or reflected origins are covered by security-audit and G5 response tests. Enumerate trusted origins; do not combine wildcard permission with credentialed access.

**Container root:** `dockerfile-root-user`, CWE-250, advisory; CKV_DOCKER_3/8. Create an application user and ensure the final USER is non-root. Also check mutable `:latest` (CKV_DOCKER_7), COPY versus ADD (CKV_DOCKER_4), Kubernetes non-root (CKV_K8S_23), and no privilege escalation (CKV_K8S_20). The HCL/Dockerfile examples above are shared executable examples.

### 4. Rule inventory

| Rule suffix | Detection | CWE |
|---|---|---|
| sql-string-concat | HTTP/LLM taint reaching SQL | 89 |
| sql-fstring-execute | f-string, %, format, or concatenated SQL even without known source | 89 |
| command-injection | Taint reaching shell | 78 |
| xss-innerhtml / xss-unescaped-render-py | Taint reaching HTML | 79 |
| jwt-alg-none | none/disabled signature verification or decode-only authorization | 347 |
| jwt-alg-confusion | HS256 and RS256 accepted together | 347 |
| actions-unpinned-action | Non-40-character-SHA external action refs; local/docker refs excluded | 829 |
| actions-pull-request-target | Privileged event referencing untrusted PR head/title/body/head_ref | 94 |

The same rules file includes G2 hard-coded LLM keys and G4 ownership/RLS/tool checks; assign their results to their own gates.

## Automation

Use `semgrep ci` with the three configured rulesets, SARIF output, and metrics disabled, or CLI scanning with `--baseline-commit <merge-base> --timeout 300 --max-memory 4000`. Pro interfile needs its token. Run Checkov with the repository config and Trivy config for HIGH/CRITICAL misconfiguration. Nightly runs full Semgrep/CodeQL/Checkov; see the workflows for pinned executable commands and language-specific CodeQL setup.

```bash
python3 scripts/g3_sast.py --target ../MultiAgentBeta --out-dir reports/raw/G3 --gate reports/gates/G3.json
```

Optional `--base <ref>` makes only Semgrep diff-aware; Checkov/Trivy remain full scans. Shared `sarif_gate.py` derives tiers/coverage. Missing/failed/timed-out tools or a target that is not a Git root yield incomplete.

External-target trust rules:

- Semgrep scans from the target root with `--disable-nosem`; target `.semgrepignore` cannot be disabled through the public CLI, so disclose it for review.
- Checkov scans a temporary tracked-file snapshot excluding target `.checkov.yaml/.yml` and symlinks, from an empty working directory. This prevents target configuration from disabling checks or executing Python external checks. Rewrite SARIF paths back to target-relative paths.
- Trivy runs from an empty working directory to avoid target working-directory `.trivyignore`/`trivy.yaml`.
- Do not apply this repository's path exceptions externally. Disclose `checkov:skip`/`trivy:ignore`, which the tools still honor. The trusted Checkov skip-path settings apply consistently to all targets.

Merge outputs into `reports/vibesec.sarif` using catalog rule/CWE/control mappings. Dependabot updates SHA-pinned actions weekly with a 14-day cooldown; update PRs still run gates. KICS is an optional third IaC opinion.

## Blocking policy

Derive G3 from all three required SARIF reports. Missing/malformed output is incomplete; blocking results fail; otherwise pass. Enforce's incomplete behavior follows policy.

- SQL, command, XSS, JWT algorithm, and IMDSv1 rules block according to the configured policy.
- High-confidence Semgrep ERROR rules and specified Checkov IMDS/secret checks (CKV_AWS_79, CKV2_VIBESEC_1, CKV_AWS_41/45/46) block.
- Base-policy CORS, container-root, and other misconfiguration findings are advisory unless overridden.
- Rule-load failures/timeouts are incomplete.
- Dynamic reproduction promotes E1/E2 evidence to E3 and updates priority by policy.

Checkov soft-fail lets aggregation finish; it does not decide whether the PR may merge.

## Mapped controls

ASVS local section IDs: V1.1 encoding, V1.2 injection, V1.3 sanitization/SSRF/eval, V1.4 deserialization/XXE, V2.2 validation, V3.3 CORS/CSP, V5.2 paths, V9.1 JWT, V13.2 backend/IMDS. CWE 89/78/79/347/918/942/250/798; `LLM05:2025`; MAESTRO L4.

## Verification

Validate Semgrep rules, run vulnerable/safe SQL, LLM-output SQL/XSS, sanitized DOM, mixed-versus-fixed JWT algorithms, and missing-versus-required IMDSv2 fixtures. Confirm custom Checkov rules load. Keep PR latency under five minutes by tuning low-confidence rules, not gates. Include cross-file source/router-to-service cases: CE limitations must be disclosed as requiring deeper nightly analysis, not used as proof of coverage. Every SARIF result needs a rule ID, source location, and CWE mapping; verify uploaded annotations.
