
[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# ⚠️ VibeSec VulnApp — 刻意有漏洞的測試靶場

> **⚠️ 這是刻意有漏洞的測試靶場，僅供 VibeSec G5/G6 閘門在隔離環境演練，嚴禁部署到任何正式或公開可達環境。**
>
> 本 app 的每一個端點都內建已知弱點（類似 OWASP Juice Shop / DVWA）。它存在的唯一目的，是讓 `.github/workflows/staging-blackbox.yml` 的 G5（DAST/API）與 G6（LLM/Agent 紅隊）探針在 CI 中有一個可重現、可離線執行的攻擊目標。請只在本機或受控 staging 環境以 `VIBESEC_TARGET_URL` 指向它。

## 啟動

```bash
uv run --project examples/vulnapp uvicorn app.main:app --port 8000
```

- Swagger UI：<http://127.0.0.1:8000/docs>（刻意對外）
- OpenAPI schema：<http://127.0.0.1:8000/openapi.json>

## seeded 帳號

| username | password | id | 備註 |
|---|---|---|---|
| alice | `alice-pass` | 1 | 含一筆私密筆記（BOLA 受害目標） |
| bob | `bob-pass` | 2 | 攻擊者帳號，用其 token 讀 alice 的筆記 |

登入取得 JWT：

```bash
curl -s -X POST http://127.0.0.1:8000/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"bob-pass"}'
# → {"access_token":"<JWT>","token_type":"bearer"}
```

## 內建弱點 → 對應閘門與 rule_id

| 端點 / 行為 | 弱點 | 閘門 | rule_id |
|---|---|---|---|
| JWT 以 RS256 簽發、公鑰於 `/.well-known/jwks.json` 公開；`_decode_token` 的 `alg` 取自 header，接受 `alg:none`（未簽章），也接受 `HS256` 並拿公鑰 PEM 當 HMAC 金鑰 | Broken Authentication（接受未簽章 / RS256→HS256 混淆 token） | G5 | `vibesec.g5.jwt-alg-none`、`vibesec.g5.jwt-alg-confusion` |
| `GET /users/{id}/notes` 未將 `{id}` 綁定當前已驗證主體 | BOLA / IDOR（bob 讀 alice 私密筆記） | G5 | `vibesec.g5.bola-cross-account` |
| `GET /admin/users` 後端未驗 token（前端只對管理員顯示） | 缺 Session 驗證 / 前端防禦假象（匿名取得全部帳號與筆記） | G5 | `vibesec.g5.missing-session-check` |
| `GET /fetch?url=` 對任意 URL 發 server-side GET，無 allow-list、未封私網 | SSRF（可讀 `169.254.169.254` metadata） | G5 | `vibesec.g5.ssrf-metadata` |
| `/docs`、`/redoc`、`/openapi.json` 全對外 | 開發便利設定外溢 | G5 | `vibesec.g5.swagger-exposed` |
| 全域 middleware 把請求的 `Origin` 原樣寫回 `Access-Control-Allow-Origin` 並帶 `Access-Control-Allow-Credentials: true` | CORS 錯誤設定（任意網站可帶憑證讀回應） | G5 | `vibesec.g5.cors-reflect-origin` |
| 未處理例外回吐 traceback | Debug Mode / Stack Trace 外洩 | G5 | `vibesec.g5.debug-stacktrace` |
| `/login`、`/chat` 無 rate limiting / captcha | 缺速率限制 | G5 / G6 | `vibesec.g5.missing-rate-limit` |
| `POST /graphql` introspection 開啟 | Schema 洩漏 | G5 | `vibesec.g5.graphql-introspection` |
| `POST /chat` → `llm_stub` 於被要求時洩漏含 `VIBESEC-SYSPROMPT-CANARY` 的 system prompt | Direct Prompt Injection / System Prompt Extraction | G6 | `direct_prompt_injection`、`system_prompt_extraction`（LLM01:2025、LLM07:2025） |
| `llm_stub` 服從外部文件夾帶指令並回報外連意圖 | Indirect Prompt Injection | G6 | `indirect_prompt_injection`（LLM01:2025） |
| `llm_stub` 原樣回吐 `<script>…</script>` | Stored XSS via AI Output | G6 | `stored_xss_via_ai_output`（LLM05:2025） |
| `llm_stub` 對超長輸入（>5000 字元）延遲 ~6s 才回應 | Denial of Wallet（延遲/資源耗用） | G6 | `denial_of_wallet`（LLM10:2025） |

> rule_id 以 `.github/workflows/staging-blackbox.yml` 的 api-probes 與 `config/promptfoo`、`config/garak`（由其他元件提供）實際發出者為準；本表為對應索引。

## 已修補模式（`VIBESEC_VULNAPP_MODE=patched`）

```bash
VIBESEC_VULNAPP_MODE=patched uv run --project examples/vulnapp uvicorn app.main:app --port 8000
```

用來提供**反例**（should_flag: false）：同一套 G5/G6 探針打在已修補版本上不應命中，以量測誤報。預設（未設定）仍是有漏洞的版本，staging workflow 行為不變。

| 已修補 | 作法 |
|---|---|
| JWT alg:none / RS256→HS256 混淆 | `jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])`，固定非對稱演算法並驗章 |
| BOLA / IDOR | `/users/{id}/notes` 僅允許本人，否則 403 |
| 缺 Session 驗證 | `/admin/users` 與其他受保護端點相同，缺少或無效 token 回 401 |
| SSRF | `/fetch` 一律 400（無允許清單即拒絕） |
| CORS 反射 Origin | 只對固定白名單 `https://app.vulnapp.example` 回 ACAO／ACAC，陌生 Origin 不帶任何 CORS 標頭 |
| Stack trace 外洩 | 例外回傳一般化 `{"error":"internal error"}` |
| Prompt injection / system prompt 外洩 | `llm_stub` 拒絕擷取與夾帶指令，不回吐輸入 |
| AI 輸出 XSS | 回覆經 HTML 編碼 |
| Denial of Wallet | `/chat` 超過 4000 字元回 413 |

JWKS 端點：`GET /.well-known/jwks.json` 公開 RS256 公鑰（n/e）；RSA 金鑰每次啟動在記憶體產生，不落地。

**刻意未修補**：Swagger/OpenAPI 對外、GraphQL introspection、缺 rate limit。這些在 patched 模式下仍會被回報，因此 G5 的 advisory 不為零；但在 patched 模式下所有 blocking 檢查（含 `jwt_alg_confusion`）都應為 `pass`，整體 G5 狀態為 `pass`。

## 安全界線（對應 CLAUDE.md #8）

G5/G6 攻擊性探針僅能用於本靶場或另經明確授權的目標；`VIBESEC_TARGET_URL` 必須指向已授權的測試環境。切勿將本 app 對外暴露。


---

<a id="english"></a>

# VibeSec VulnApp — Intentionally Vulnerable Test Lab

> **Use only for isolated G5/G6 exercises. Never deploy to production or expose it publicly.** Like Juice Shop/DVWA, it provides reproducible vulnerable behavior for staging-blackbox CI, including an offline deterministic LLM stub. Point VIBESEC_TARGET_URL to it only in an authorized local/controlled test environment.

## Start and accounts

```bash
uv run --project examples/vulnapp uvicorn app.main:app --port 8000
```

Swagger: <http://127.0.0.1:8000/docs>; OpenAPI: <http://127.0.0.1:8000/openapi.json>.

| Username | Password | ID | Purpose |
|---|---|---|---|
| alice | alice-pass | 1 | Private seeded note; BOLA victim |
| bob | bob-pass | 2 | Other subject attempting to read Alice's note |

```bash
curl -s -X POST http://127.0.0.1:8000/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"bob-pass"}'
```

The response contains access_token and token_type bearer.

## Vulnerabilities and gate mapping

| Behavior | Flaw / rule |
|---|---|
| RS256 issued, but decoder accepts header-selected none or HS256 using public PEM | G5 jwt-alg-none / jwt-alg-confusion |
| GET /users/{id}/notes without current-user binding | G5 bola-cross-account (Bob reads Alice) |
| GET /admin/users without backend token validation | G5 missing-session-check; anonymous account/note disclosure |
| GET /fetch?url= with unrestricted server fetch | G5 ssrf-metadata |
| Public docs/redoc/openapi | G5 swagger-exposed |
| Arbitrary reflected Origin with credentials | G5 cors-reflect-origin |
| Unhandled traceback | G5 debug-stacktrace |
| Login/chat without throttling/CAPTCHA | G5 missing-rate-limit / G6 consumption checks |
| GraphQL introspection | G5 graphql-introspection |
| Stub reveals VIBESEC-SYSPROMPT-CANARY on request | G6 direct injection / system-prompt extraction (LLM01/07) |
| Stub follows document instructions and reports egress intent | G6 indirect injection (LLM01); simulated evidence, not actual external exfiltration |
| Stub echoes script content | G6 unsafe AI output (LLM05) |
| Input over 5,000 characters delays about six seconds | G6 denial of wallet/resource-use fixture (LLM10) |

Actual emitted IDs from shared probes/promptfoo/garak govern; this table is an index.

## Patched controls

```bash
VIBESEC_VULNAPP_MODE=patched uv run --project examples/vulnapp uvicorn app.main:app --port 8000
```

Patched mode supplies should_flag:false controls for the same probes; default remains vulnerable. It fixes JWT verification to RS256, restricts notes to their owner (403 otherwise), requires valid tokens on protected/admin paths (401 otherwise), rejects all fetches absent an allowlist (400), permits CORS only for https://app.vulnapp.example, returns generic internal-error JSON, refuses extraction/injected instructions, HTML-encodes output, and rejects chat input over 4,000 characters with 413.

JWKS publishes RSA n/e; keys are generated in memory on each startup and not persisted.

Swagger/OpenAPI, GraphQL introspection, and missing rate limits are deliberately left visible. Patched G5 therefore still has advisory findings, while blocking checks including JWT confusion should pass and the gate can pass under policy. Patched mode is a testing control, not a production-hardening claim.

## Safety boundary

The bundled lab is the default authorized fixture target. External projects require their own explicit test authorization and configuration under the repository's G5/G6 rules. Never expose this vulnerable application publicly.
