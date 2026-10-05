# 06 G5 DAST 與 API（黑箱；部署至 Staging 後、上線前）

| 項目 | 值 |
|---|---|
| 閘門 ID | `G5` |
| 性質 | 黑箱、由外而內；staging 階段；需要兩個不同權限帳號的 Token |
| 設定 | `vibesec.yaml` → `gates.g5_dast_api`（`stage: staging`、`target_url_env: VIBESEC_TARGET_URL`、`tools: [zap-baseline, zap-api-scan, api-probes]`、`two_account_test: required`、`account_a_token_env: VIBESEC_TOKEN_A`、`account_b_token_env: VIBESEC_TOKEN_B`、`checks: [bola_idor, jwt_alg_none, jwt_alg_confusion, ssrf_metadata, swagger_exposed, graphql_introspection, debug_stacktrace, rate_limit]`、`timeout_seconds: 1800`） |
| 設定檔 | `config/zap/api-scan.conf`、`config/zap/two-account-context.yaml` |
| 負責 | Red Team |
| 硬規則 | 探針只能對 `VIBESEC_TARGET_URL` 指向的、已授權的測試環境執行（CLAUDE.md 規則 8）。CI 中由 repo 管理者設定的 Actions 變數 `vars.VIBESEC_TARGET_URL` 提供，工作流不接受手動輸入的目標 |

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
| `vibesec.g5.ssrf-metadata` | blocking（E3） | CWE-918 |
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

1. **缺 Token 行為**：移除 `VIBESEC_TOKEN_B` → G5 `incomplete`（`status_reason: "VIBESEC_TOKEN_B missing"`），絕不 pass。
2. **靶場正例**（`examples/vulnapp`）：B 讀 A 的 todo 回 200 → `bola-cross-account`；`alg:none` 被接受；`/api/import` 讀到 `169.254.169.254` 的角色名；`/docs` 回 200。
3. **反例**：修復後 B 讀 A 回 404、`alg:none` 回 401、SSRF 被 egress allowlist 擋 → 對應 finding `retest_result: fixed`、`validation_status: confirmed`。
4. **只打授權目標**：harness 拒絕 `VIBESEC_TARGET_URL` 指向非 staging / 非允許清單的主機（CLAUDE.md 規則 8）；單元測試覆蓋此拒絕。
5. **證據留存**：每個 blocking 發現有 `reports/g5/*.http`（Token 已遮罩）與 `evidence_grade: E3`。
6. **回填白箱**：Stack Trace 洩漏的路徑在 SARIF 有對應位置；BOLA 端點能對回 G4 的 `missing-owner-filter` finding。
