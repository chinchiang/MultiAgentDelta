#!/usr/bin/env python3
"""VibeSec G5 api-probes：雙帳號 BOLA／JWT／SSRF／設定外溢／rate-limit 等黑箱探針（docs/06）。

由 .github/workflows/staging-blackbox.yml 的「G5 api-probes」步驟執行，scripts/run_evals.py 的 vulnapp 評測走同一個步驟，
所以 CI 與評測跑的是同一份程式碼。原本以 heredoc 內嵌在 workflow 中，搬成檔案後邏輯不變（第一輪審查／#69 移植 ⑤）；
之後包成 main()／selftest() 以便 validate.py 離線把關，並在缺必填環境變數時 fail-closed（incomplete，不 traceback）。

輸入（環境變數）：VIBESEC_TARGET_URL（必填，須在 config/targets.yaml 允許清單）、VIBESEC_CONFIG（受信任的 vibesec.yaml）、
VIBESEC_TOKEN_DIR、HAS_A、HAS_B、VIBESEC_MODE。輸出：reports/g5-api-probes.sarif、reports/g5-gate.json（目前目錄）。
"""
# G5 api-probes — 僅對已授權 VIBESEC_TARGET_URL 執行（CLAUDE.md #8）。
# checks: bola_idor, jwt_alg_none, jwt_alg_confusion, ssrf_metadata,
#         swagger_exposed, graphql_introspection, debug_stacktrace, rate_limit, session_check
import json, os, re, time, base64, pathlib, datetime, urllib.request, urllib.error, urllib.parse, hashlib, hmac, sys
# 自身所在的 scripts/ 放到 path 最前，不論 cwd 都能 import 同層模組（selftest 由 validate.py 以子行程在 repo 根執行）
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vibesec_policy import Policy
from target_guard import GuardConfigError, check as guard_check, same_origin

def iso(dt): return dt.replace(microsecond=0).isoformat()

# 由 main() 依環境變數設定；helper 於呼叫時（而非定義時）讀取這些全域，故 main() 填妥後再呼叫 helper。
URL = ""
TA = TB = ""
HAS_A = HAS_B = False
POLICY = None
ROOT = None
REPORTS = pathlib.Path("reports")
results = []      # SARIF results
rules = {}        # ruleId -> rule 物件
coverage = {}     # control_id -> state
coverage_reasons = {}  # control_id -> reason（not_applicable 必填，untested 可選）
JWKS_SKIPPED = []  # discovery 給的非同源 jwks_uri：不抓（規則 8），寫進 jwt_alg_confusion 的原因
# JWT 探針（alg:none、alg confusion）嘗試的受保護端點：合法 token 須回 200 才拿來送偽造 token
JWT_PROBE_PATHS = ("/me", "/api/me", "/profile", "/users/me", "/account")

def _read(name):
    d = os.environ.get("VIBESEC_TOKEN_DIR", "")
    f = pathlib.Path(d) / name if d else None
    return f.read_text().strip() if f and f.is_file() else ""

def add(rule_id, level, msg):
    tier = "advisory" if level == "note" else POLICY.tier(rule_id)   # note = 未能實測的提示，不是發現
    rules.setdefault(rule_id, {"id": rule_id, "name": rule_id,
                               "shortDescription": {"text": rule_id},
                               "defaultConfiguration": {"level": level},
                               "properties": {"policy_tier": tier}})
    results.append({"ruleId": rule_id, "level": level, "message": {"text": msg},
                    # Code Scanning 只收 file 型 URI：位置指向執行探針的 workflow，目標放 properties
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": ".github/workflows/staging-blackbox.yml"}}}],
                    "properties": {"policy_tier": tier, "target_url": URL}})

# 不跟隨重新導向：urlopen 預設會跟到 Location 指的任何主機，還把 Authorization 帶過去；
# 導向目標沒經過 target_guard 授權檢查（規則 8）。3xx 原樣回傳，由各探針判讀
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None
OPENER = urllib.request.build_opener(_NoRedirect)

# 同源限制：path 可能來自目標回應（openapi 的 paths 鍵、discovery 的 jwks_uri），絕對 URL 會打到任意主機，
# "@evil/x" 之類的鍵接在 URL 後也會變成帳密混淆。最終 URL 一律與已授權的 URL 比對 scheme／主機／埠，
# 不同源就不送（也就不會把 Authorization 帶出去）
def req(path, method="GET", token=None, data=None, headers=None, timeout=15):
    url = path if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", path or "") else URL + (path or "")
    _same, _why = same_origin(url, URL)
    if not _same:
        return None, f"拒絕：非授權來源（{_why}），未送出請求"
    h = {"User-Agent": "vibesec-g5-probes"}
    if token: h["Authorization"] = f"Bearer {token}"
    if headers: h.update(headers)
    body = None
    if data is not None:
        body = json.dumps(data).encode(); h["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with OPENER.open(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return None, str(e)

def b64url(d): return base64.urlsafe_b64encode(d).decode().rstrip("=")
def _b64u_dec(x): return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
def _der_len(n):
    if n < 0x80: return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big"); return bytes([0x80 | len(b)]) + b
def _der_tlv(tag, body): return bytes([tag]) + _der_len(len(body)) + body
def _der_uint(i):
    b = i.to_bytes((i.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80: b = b"\x00" + b
    return _der_tlv(0x02, b)
def _spki_pem(n, e):
    rsa_oid = bytes.fromhex("300d06092a864886f70d0101010500")            # AlgorithmIdentifier: rsaEncryption + NULL
    pubkey = _der_tlv(0x30, _der_uint(n) + _der_uint(e))                   # RSAPublicKey SEQUENCE
    spki = _der_tlv(0x30, rsa_oid + _der_tlv(0x03, b"\x00" + pubkey))      # SubjectPublicKeyInfo
    # 須與 cryptography 的 PEM 輸出逐位元組一致（HMAC 金鑰即 PEM bytes）：base64 每 64 字元換行
    b64 = base64.b64encode(spki).decode()
    body = "".join(b64[i:i + 64] + "\n" for i in range(0, len(b64), 64))
    return ("-----BEGIN PUBLIC KEY-----\n" + body + "-----END PUBLIC KEY-----\n").encode()

def _token_alg(tok):
    try: return (json.loads(_b64u_dec(tok.split(".")[0])).get("alg") or "").upper()
    except Exception: return ""

def _fetch_pem():
    # 依 token 的 kid 從常見 JWKS 位置取 RSA 公鑰
    try: kid = json.loads(_b64u_dec(TA.split(".")[0])).get("kid")
    except Exception: kid = None
    uris = ["/.well-known/jwks.json", "/jwks.json"]
    s_oidc, body_oidc = req("/.well-known/openid-configuration")
    if body_oidc:
        try:
            ju = json.loads(body_oidc).get("jwks_uri")
            if isinstance(ju, str) and ju:
                # jwks_uri 由目標決定：只收同源絕對 URL 或站內路徑，其餘略過，不送請求
                _abs = ju if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", ju) else (URL + ju if ju.startswith("/") and not ju.startswith("//") else ju)
                _same, _why = same_origin(_abs, URL)
                if _same: uris.insert(0, _abs)
                else: JWKS_SKIPPED.append(f"OIDC discovery 的 jwks_uri {ju[:200]!r} 非授權來源，未抓取（{_why}）")
        except (ValueError, TypeError, KeyError):  # discovery 回應不是預期的 JSON 物件：略過，退回預設 jwks 路徑
            JWKS_SKIPPED.append("OIDC discovery 回應無法解析為 JSON 物件，改用預設 jwks 路徑")
    for u in uris:
        s_j, body_j = req(u)
        if not body_j: continue
        try: keys = json.loads(body_j).get("keys", [])
        except Exception: continue
        rsa_keys = [k for k in keys if k.get("kty") == "RSA" and k.get("n") and k.get("e")]
        if not rsa_keys: continue
        k = next((k for k in rsa_keys if kid and k.get("kid") == kid), rsa_keys[0])
        n = int.from_bytes(_b64u_dec(k["n"]), "big"); e = int.from_bytes(_b64u_dec(k["e"]), "big")
        return _spki_pem(n, e)
    return None

def _protected_paths():
    try:
        txt = pathlib.Path(os.environ.get("VIBESEC_CONFIG", "vibesec.yaml")).read_text(encoding="utf-8")
    except OSError:
        return []
    m = re.search(r"^\s*protected_paths\s*:\s*\[([^\]]*)\]", txt, re.M)
    return [x.strip().strip("'\"") for x in m.group(1).split(",") if x.strip()] if m else []

def _write_gate(gstatus, status_reason, blocking, advisory, cov, zap_tools, started, probe_state="ran"):
    gate = {"gate": "G5", "status": gstatus, "status_reason": status_reason,
            "mode": os.environ.get("VIBESEC_MODE", "shadow"), "scope": "full", "diff_base": None,
            "commit": None, "started_at": iso(started),
            "finished_at": iso(datetime.datetime.now(datetime.timezone.utc)),
            "tools": [{"name": "vibesec-g5-api-probes", "version": "1.0.0", "state": probe_state,
                       "exit_code": 0, "output_ref": "reports/g5-api-probes.sarif", "duration_seconds": None}] + zap_tools,
            "findings_count": {"blocking": blocking, "advisory": advisory},
            "coverage": cov}
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "g5-gate.json").write_text(json.dumps(gate, ensure_ascii=False, indent=2), encoding="utf-8")
    return gate


def main():
    """執行所有探針並寫出 reports/g5-api-probes.sarif 與 reports/g5-gate.json。缺必填環境變數 → incomplete（不 traceback）。"""
    global URL, TA, TB, HAS_A, HAS_B, POLICY, ROOT, REPORTS
    started = datetime.datetime.now(datetime.timezone.utc)
    # 可重入：清掉上一輪（selftest 會呼叫多次）
    results.clear(); rules.clear(); coverage.clear(); coverage_reasons.clear(); JWKS_SKIPPED.clear()
    REPORTS = pathlib.Path("reports"); REPORTS.mkdir(exist_ok=True)

    # 必填環境變數缺失 → 乾淨寫出 incomplete gate（incomplete ≠ pass；不以 KeyError traceback 收場）
    target = os.environ.get("VIBESEC_TARGET_URL")
    if not target:
        _write_gate("incomplete", "VIBESEC_TARGET_URL 未設定；未送出任何探針", 0, 0, [], [], started, probe_state="missing")
        print("G5 api-probes: status=incomplete（VIBESEC_TARGET_URL 未設定）")
        return 0
    URL = target.rstrip("/")
    # tier 只來自 blocking-policy（含 risk_tier 的 tier_overrides）；VIBESEC_CONFIG 指向 repo 的 vibesec.yaml
    ROOT = pathlib.Path(os.environ.get("VIBESEC_CONFIG", "vibesec.yaml")).resolve().parent
    POLICY = Policy(ROOT)
    TA = _read("a"); TB = _read("b")
    HAS_A = os.environ.get("HAS_A") == "true"; HAS_B = os.environ.get("HAS_B") == "true"

    # 授權檢查（CLAUDE.md 規則 8；workflow 的 target 步驟已查過，這裡再查一次）→ 連線性檢查
    incomplete_reason = None
    try:
        _ok, _why = guard_check(URL, ROOT)
    except GuardConfigError as e:
        _ok, _why = False, f"目標允許清單無法讀取：{e}"
    if not _ok:
        reachable = False
        incomplete_reason = f"目標未通過授權檢查（config/targets.yaml）：{_why}；未送出任何探針"
    else:
        status, _ = req("/openapi.json")
        reachable = status is not None
        if not reachable:
            incomplete_reason = f"目標 {URL} 無法連線"

    # ---- swagger_exposed ----
    if reachable:
        exposed, answered = [], 0
        for p in ["/openapi.json", "/docs", "/redoc", "/swagger", "/swagger.json"]:
            s, _ = req(p)
            answered += s is not None
            if s == 200: exposed.append(p)
        if exposed:
            add("vibesec.g5.swagger-exposed", "warning",
                f"API 文件/schema 對外暴露：{', '.join(exposed)}（開發便利設定外溢）")
            coverage["swagger_exposed"] = "fail"
        elif not answered:   # 每個請求都連不上：沒測到，不是「沒暴露」
            coverage["swagger_exposed"] = "untested"; coverage_reasons["swagger_exposed"] = "所有文件路徑的請求都失敗"
        else:
            coverage["swagger_exposed"] = "pass"

    # ---- graphql_introspection ----
    if reachable:
        q = {"query": "{__schema{types{name}}}"}
        s, body = req("/graphql", "POST", data=q)
        if s == 200 and "__schema" in (body or ""):
            add("vibesec.g5.graphql-introspection", "warning",
                "GraphQL introspection 開啟（洩漏 schema）")
            coverage["graphql_introspection"] = "fail"
        elif s in (404, 405):   # 沒有 GraphQL 端點：不適用，不是「已關閉 introspection」
            coverage["graphql_introspection"] = "not_applicable"
            coverage_reasons["graphql_introspection"] = f"POST /graphql 回 HTTP {s}：目標沒有 GraphQL 端點"
        else:
            coverage["graphql_introspection"] = "pass" if s is not None else "untested"

    # ---- cors_reflect_origin ----
    # 帶一個不可能在白名單內的 Origin（RFC 2606 保留網域）；ACAO 反射它且 ACAC: true → 任意網站可帶 cookie/憑證讀回應
    if reachable:
        EVIL = "https://vibesec-cors-probe.invalid"
        h = {"User-Agent": "vibesec-g5-probes", "Origin": EVIL}
        if HAS_A: h["Authorization"] = f"Bearer {TA}"
        try:
            with OPENER.open(urllib.request.Request(URL + "/openapi.json", headers=h), timeout=15) as resp:
                acao, acac = resp.headers.get("Access-Control-Allow-Origin"), resp.headers.get("Access-Control-Allow-Credentials")
        except urllib.error.HTTPError as e:
            acao, acac = e.headers.get("Access-Control-Allow-Origin"), e.headers.get("Access-Control-Allow-Credentials")
        except Exception:
            acao = acac = False
        if acao is False:
            coverage["cors_reflect_origin"] = "untested"
        elif acao == EVIL and str(acac).lower() == "true":
            add("vibesec.g5.cors-reflect-origin", "error",
                "CORS 反射任意 Origin 且 Access-Control-Allow-Credentials: true")
            coverage["cors_reflect_origin"] = "fail"
        else:
            coverage["cors_reflect_origin"] = "pass"

    # ---- debug_stacktrace ----
    if reachable:
        markers = ("Traceback (most recent call last)", "File \"", "Exception", "at line")
        leaked = lambda b: bool(b) and any(m in b for m in markers)
        s, body = req("/__vibesec_nonexistent__/%ff", "GET")
        if not leaked(body):
            # 型別混淆輸入：對 openapi 列出、無 path 參數的 POST 端點（最多 5 個）送數值型欄位，誘發未處理例外
            try:
                _, spec = req("/openapi.json")
                posts = [k for k, v in (json.loads(spec or "{}").get("paths") or {}).items()
                         if "post" in v and "{" not in k][:5]
            except ValueError:
                posts = []
            for path in posts:
                s, body = req(path, "POST", data={"query": 0, "message": 0, "input": 0, "id": 0})
                if leaked(body):
                    break
        if leaked(body):
            add("vibesec.g5.debug-stacktrace", "warning",
                "錯誤回應洩漏 stack trace（Debug Mode 外溢）")
            coverage["debug_stacktrace"] = "fail"
        else:
            coverage["debug_stacktrace"] = "pass"

    # ---- jwt_alg_none ----
    # 以現有 token payload 重組 alg:none，送至受保護端點：接受 → fail；明確 401/403 → pass。
    # 找不到合法 token 回 200 的端點、或偽造請求回 5xx／逾時 → untested：以前沒測到也記 pass（incomplete ≠ pass）。
    if reachable and HAS_A and TA.count(".") == 2:
        try:
            _, payload_b64, _ = TA.split(".")
            pad = "=" * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + pad))
            header = {"alg": "none", "typ": "JWT"}
            forged = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}."
            # 探測一組常見受保護端點
            accepted = None; rejected = False; probed = []
            for p in JWT_PROBE_PATHS:
                s_auth, _ = req(p, token=TA)
                if s_auth != 200: continue
                s_forged, _ = req(p, token=forged)
                probed.append(f"{p}→{s_forged}")
                if s_forged == 200: accepted = p; break
                if s_forged in (401, 403): rejected = True
            if accepted:
                add("vibesec.g5.jwt-alg-none", "error",
                    f"受保護端點 {accepted} 接受 alg:none 偽造 JWT（授權繞過）")
                coverage["jwt_alg_none"] = "fail"
            elif rejected:
                coverage["jwt_alg_none"] = "pass"
            else:
                coverage["jwt_alg_none"] = "untested"
                coverage_reasons["jwt_alg_none"] = (
                    f"偽造 token 未得到明確 401/403（{'、'.join(probed)}）" if probed else
                    f"沒有端點對合法 token 回 200（試過 {'、'.join(JWT_PROBE_PATHS)}），找不到受保護端點可測")
        except Exception:
            coverage["jwt_alg_none"] = "untested"
    else:
        coverage["jwt_alg_none"] = "untested"

    # ---- jwt_alg_confusion（RS256→HS256）----
    # 從目標公開的 JWKS 取 RSA 公鑰，轉成 PEM（stdlib 手組 SubjectPublicKeyInfo DER），
    # 以 PEM 當 HMAC 金鑰重簽同一 payload 送出：接受 → fail；明確 401/403 → pass。
    # token 使用對稱演算法（無公鑰可混淆）→ not_applicable；取不到公鑰 → untested（incomplete ≠ pass）。
    alg = _token_alg(TA) if (reachable and HAS_A and TA.count(".") == 2) else ""
    if not reachable or not HAS_A or TA.count(".") != 2:
        coverage["jwt_alg_confusion"] = "untested"
    elif alg.startswith("HS"):
        coverage["jwt_alg_confusion"] = "not_applicable"
        coverage_reasons["jwt_alg_confusion"] = "token 使用對稱演算法（HS*），無公鑰可混淆"
    else:
        pem = _fetch_pem()
        if not pem:
            coverage["jwt_alg_confusion"] = "untested"
            _skip = "；".join(JWKS_SKIPPED)
            if _skip: coverage_reasons["jwt_alg_confusion"] = f"未能從同源 JWKS 取得 RSA 公鑰；{_skip}"
            add("vibesec.g5.jwt-alg-confusion", "note",
                "未能從 JWKS 取得 RSA 公鑰 → untested，建議人工/Burp 驗證" + (f"（{_skip}）" if _skip else ""))
        else:
            try:
                h_b64, p_b64, _ = TA.split(".")
                header = {"alg": "HS256", "typ": "JWT"}
                new_h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
                signing_input = f"{new_h}.{p_b64}".encode()
                sig = base64.urlsafe_b64encode(hmac.new(pem, signing_input, hashlib.sha256).digest()).decode().rstrip("=")
                forged = f"{new_h}.{p_b64}.{sig}"
                accepted = None; rejected = False
                for p in JWT_PROBE_PATHS:
                    s_auth, _ = req(p, token=TA)
                    if s_auth != 200: continue
                    s_forged, _ = req(p, token=forged)
                    if s_forged == 200: accepted = p; break
                    if s_forged in (401, 403): rejected = True
                if accepted:
                    add("vibesec.g5.jwt-alg-confusion", "error",
                        f"受保護端點 {accepted} 接受以公鑰 PEM 當 HMAC 金鑰的 HS256 偽造 JWT（RS256→HS256 混淆）")
                    coverage["jwt_alg_confusion"] = "fail"
                elif rejected:
                    coverage["jwt_alg_confusion"] = "pass"
                else:
                    coverage["jwt_alg_confusion"] = "untested"
            except Exception:
                coverage["jwt_alg_confusion"] = "untested"

    # ---- bola_idor（雙帳號實測）----
    if reachable and HAS_A and HAS_B:
        # 以 A 探索一個自身資源 ID，再用 B 的 token 存取
        discovered = []
        for listp in ["/api/items", "/items", "/api/orders", "/orders", "/api/documents", "/documents"]:
            s, body = req(listp, token=TA)
            if s == 200 and body:
                ids = re.findall(r'"id"\s*:\s*"?([A-Za-z0-9\-]+)"?', body)
                base = listp
                for rid in ids[:3]:
                    discovered.append((base, rid))
        # 主體 ID 策略：以 A 的 /me 取得自身 id，再試「以使用者 id 為路徑」的資源
        for mep in ["/me", "/api/me"]:
            s, body = req(mep, token=TA)
            if s == 200 and body:
                m = re.search(r'"id"\s*:\s*"?([A-Za-z0-9\-]+)"?', body)
                if m:
                    for tpl in ["/users/{}/notes", "/users/{}", "/api/users/{}"]:
                        discovered.append((None, tpl.format(m.group(1))))
                    break
        confirmed = False; checked = False
        for base, rid in discovered:
            resource = rid if base is None else f"{base}/{rid}"
            s_a, _ = req(resource, token=TA)
            if s_a != 200:
                continue  # A 自己都讀不到 → 此路徑不構成證據
            s_b, _ = req(resource, token=TB)
            if s_b in (401, 403, 404):
                checked = True
            if s_b == 200:
                add("vibesec.g5.bola-cross-account", "error",
                    f"雙帳號 BOLA 實證：帳號 B 可存取帳號 A 的資源 {resource}（HTTP 200）")
                confirmed = True; break
        # 只有「A 可讀、B 被明確拒絕」才算 pass；其餘一律 untested（incomplete ≠ pass）
        coverage["bola_idor"] = "fail" if confirmed else ("pass" if checked else "untested")
    else:
        coverage["bola_idor"] = "untested"

    # ---- ssrf_metadata ----
    # 判定原則（incomplete ≠ pass）：命中才 fail；端點以 400/403 明確拒絕內部 URL 才 pass；其餘 untested。
    # 回應常回顯送出的 URL，比對前先移除，避免把回顯誤判為命中。
    if reachable:
        META = "http://169.254.169.254/latest/meta-data/"
        tp = urllib.parse.urlsplit(URL)
        CANARY = f"http://127.0.0.1:{tp.port or (443 if tp.scheme == 'https' else 80)}/openapi.json"
        def ssrf_try(ep, key, target):
            out = []
            q = urllib.parse.urlencode({key: target})
            out.append(req(f"{ep}?{q}", "GET", token=TA or None))
            out.append(req(ep, "POST", token=TA or None, data={key: target}))
            return [(s, (b or "").replace(target, "")) for s, b in out]
        ssrf_hit = False; internal_hit = False; refused = False; reached = False
        for ep in ["/fetch", "/api/fetch", "/import", "/api/import", "/proxy", "/url"]:
            for key in ["url", "uri", "target", "endpoint"]:
                for s, body in ssrf_try(ep, key, META):
                    if s == 200: reached = True
                    if s in (400, 403): refused = True
                    if s == 200 and any(m in body for m in ("ami-id", "instance-id", "iam/security-credentials", '"compute"')):
                        add("vibesec.g5.ssrf-metadata", "error",
                            f"SSRF：端點 {ep}（{key}）可讀取雲端 metadata 169.254.169.254")
                        ssrf_hit = True; break
                if not internal_hit:
                    for s, body in ssrf_try(ep, key, CANARY):
                        if s == 200 and "openapi" in body:  # 已移除回顯的 canary URL；內容可能被 JSON 轉義
                            add("vibesec.g5.ssrf-internal-fetch", "error",
                                f"SSRF：端點 {ep}（{key}）會替使用者抓取內部位址 127.0.0.1（loopback canary 命中）")
                            internal_hit = True; break
                if ssrf_hit: break
            if ssrf_hit: break
        if ssrf_hit or internal_hit:
            coverage["ssrf_metadata"] = "fail"
        elif refused and not reached:
            coverage["ssrf_metadata"] = "pass"
        else:
            coverage["ssrf_metadata"] = "untested"

    # ---- session_check ----
    # 受保護路徑由 vibesec.yaml gates.g5_dast_api.protected_paths 列出（探針無法從外部推斷哪些端點該受保護）。
    # 判定：無 token 或無效 token 取得 2xx → fail（blocking）；兩者皆 401/403 → pass；其餘（404、5xx、連線失敗）→ untested。
    PROTECTED = _protected_paths()
    if not reachable:
        coverage["session_check"] = "untested"
    elif not PROTECTED:
        coverage["session_check"] = "untested"
        coverage_reasons["session_check"] = "vibesec.yaml 未設定 gates.g5_dast_api.protected_paths"
    else:
        leaked, unknown = [], []
        for pth in PROTECTED:
            s_anon, _ = req(pth)
            s_bad, _ = req(pth, token="vibesec.invalid.token")
            open_codes = [c for c in (s_anon, s_bad) if c is not None and 200 <= c < 300]
            if open_codes:
                leaked.append(f"{pth}（無 token→{s_anon}、無效 token→{s_bad}）")
            elif s_anon in (401, 403) and s_bad in (401, 403):
                continue
            else:
                unknown.append(f"{pth}（{s_anon}/{s_bad}）")
        if leaked:
            add("vibesec.g5.missing-session-check", "error",
                "受保護端點未驗證 token 即回 2xx（前端防禦假象）：" + "；".join(leaked))
            coverage["session_check"] = "fail"
        elif unknown:
            coverage["session_check"] = "untested"
            coverage_reasons["session_check"] = "回應非 401/403，無法判定：" + "；".join(unknown)
        else:
            coverage["session_check"] = "pass"

    # ---- rate_limit ----
    if reachable:
        codes = []
        for _ in range(25):
            s, _ = req("/login", "POST", data={"username": "alice", "password": "wrong"})
            codes.append(s)
        if all(c is None for c in codes):
            coverage["rate_limit"] = "untested"; coverage_reasons["rate_limit"] = "POST /login 的請求全部失敗"
        elif all(c in (404, 405) for c in codes):   # 探針只認 /login：目標的登入端點在別處時沒測到
            coverage["rate_limit"] = "untested"; coverage_reasons["rate_limit"] = f"目標沒有 POST /login（HTTP {codes[0]}）"
        elif 429 not in codes:
            add("vibesec.g5.missing-rate-limit", "warning",
                "登入端點 25 次連續請求未見 429（缺 Rate Limiting / Captcha）")
            coverage["rate_limit"] = "fail"
        else:
            coverage["rate_limit"] = "pass"

    # ---- ZAP（scripts/g5_zap.py 的輸出；vibesec.yaml g5 tools 含 zap-baseline、zap-api-scan）----
    # 缺席或無法解析 → 兩個 ZAP 掃描記 untested（incomplete ≠ pass）
    ZAP_TOOLS = []
    try:
        _z = json.loads((REPORTS / "g5-zap.json").read_text(encoding="utf-8"))
        for _k, _v in _z["coverage"].items():
            coverage[_k] = _v["state"]
            if _v.get("reason"): coverage_reasons[_k] = _v["reason"]
        for _rid, _rule in _z["rules"].items():
            rules.setdefault(_rid, _rule)
        results.extend(_z["results"])
        ZAP_TOOLS = list(_z.get("tools") or [])
    except Exception as e:
        for _k in ("zap_api_scan", "zap_baseline"):
            coverage[_k] = "untested"
            coverage_reasons[_k] = f"沒有 ZAP 彙整結果（reports/g5-zap.json：{type(e).__name__}）"

    # ---- 輸出 SARIF ----
    sarif = {"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
             "version": "2.1.0",
             "runs": [{"tool": {"driver": {"name": "vibesec-g5-api-probes", "version": "1.0.0",
                                           "informationUri": "https://github.com/chinchiang/MultiAgentDelta",
                                           "rules": list(rules.values())}}, "results": results}]}
    (REPORTS / "g5-api-probes.sarif").write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")

    blocking = sum(1 for r in results if r["properties"]["policy_tier"] == "blocking")
    advisory = sum(1 for r in results if r["properties"]["policy_tier"] == "advisory")

    # 缺帳號或無法連線 → incomplete
    status_reason = None
    if incomplete_reason:
        gstatus = "incomplete"; status_reason = incomplete_reason
    elif not (HAS_A and HAS_B):
        gstatus = "incomplete"
        status_reason = f"雙帳號測試需兩個 token（has_a={HAS_A}, has_b={HAS_B}）；缺 token 的 BOLA/JWT 檢查記為 untested"
    elif blocking > 0:
        gstatus = "fail"  # 是否擋由「黑箱彙整與判定」依 mode 與政策決定
    elif any(v == "untested" for v in coverage.values()):
        # incomplete ≠ pass（CLAUDE.md #2）：任何檢查未能實測，整體就不能報 pass
        gstatus = "incomplete"
        status_reason = "未能實測：" + "、".join(k for k, v in coverage.items() if v == "untested")
    else:
        gstatus = "pass"

    def _cov_reason(k, v):
        if k in coverage_reasons: return coverage_reasons[k]
        if v == "untested": return "缺 token 或目標限制，未能實測"
        if v == "not_applicable": return "此目標不適用該檢查"
        return None
    cov = [{"control_id": k, "state": v, "reason": _cov_reason(k, v)}
           for k, v in coverage.items()]
    # schema：not_applicable 才強制 reason；untested 可無 reason，但附上更佳
    _write_gate(gstatus, status_reason, blocking, advisory, cov, ZAP_TOOLS, started)
    print(f"G5 api-probes: status={gstatus} blocking={blocking} advisory={advisory}")
    print(json.dumps(coverage, ensure_ascii=False))
    return 0


def selftest():
    """離線自我測試：驗純函式（JWT alg、DER/SPKI PEM、b64url）＋缺必填環境變數 fail-closed（incomplete，不 traceback）。"""
    import tempfile, contextlib, io
    from jsonschema import Draft202012Validator
    fails = []
    schema = Draft202012Validator(json.loads((pathlib.Path(__file__).resolve().parent.parent
                                               / "schemas/gate-result.schema.json").read_text(encoding="utf-8")))
    repo = pathlib.Path(__file__).resolve().parent.parent

    # b64url：無填充的 urlsafe base64
    if b64url(b"\xff\xff") != "__8" or b64url(b"") != "":
        fails.append("b64url 應為無填充 urlsafe base64")
    # _token_alg：讀 JWT 標頭 alg（大寫）；壞輸入回空字串
    hs = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip("=")
    if _token_alg(f"{hs}.x.y") != "HS256" or _token_alg("not-a-jwt") != "":
        fails.append("_token_alg 應回大寫 alg，壞 token 回空字串")
    # _spki_pem：手組 DER 要能被標準函式庫解析，且與已知 modulus/exponent 一致（RFC 8017 SPKI）
    try:
        n, e = 0xC0DE_1234_5678_90AB_CDEF, 65537
        pem = _spki_pem(n, e)
        if not (pem.startswith(b"-----BEGIN PUBLIC KEY-----\n") and pem.rstrip().endswith(b"-----END PUBLIC KEY-----")):
            fails.append("_spki_pem 應輸出 PEM 封裝的 SubjectPublicKeyInfo")
        der = base64.b64decode(b"".join(pem.split(b"\n")[1:-2]))
        if der[0] != 0x30:  # 最外層 SEQUENCE
            fails.append("_spki_pem DER 最外層應為 SEQUENCE")
    except Exception as ex:
        fails.append(f"_spki_pem 應可產生合法 DER：{ex}")

    def run_in(tmp, env):
        """在暫存 cwd 以指定環境變數跑 main()，回傳 (exit_code, gate dict or None)。"""
        cwd0 = os.getcwd(); env0 = dict(os.environ)
        out = io.StringIO()
        try:
            os.chdir(tmp)
            os.environ.clear(); os.environ.update(env)
            with contextlib.redirect_stdout(out):
                code = main()
            gp = pathlib.Path(tmp) / "reports/g5-gate.json"
            return code, (json.loads(gp.read_text(encoding="utf-8")) if gp.is_file() else None)
        finally:
            os.chdir(cwd0); os.environ.clear(); os.environ.update(env0)

    # 缺 VIBESEC_TARGET_URL → incomplete gate、exit 0、不 traceback、不送任何請求
    with tempfile.TemporaryDirectory() as d:
        code, g = run_in(d, {})
        if code != 0 or not g or g["status"] != "incomplete":
            fails.append(f"缺 VIBESEC_TARGET_URL → 應寫出 incomplete gate 並回 0（得到 code={code}, gate={g}）")
        elif list(schema.iter_errors(g)):
            fails.append(f"缺環境變數的 gate 不符 schema：{list(schema.iter_errors(g))[0].message}")
        elif g["tools"][0]["state"] != "missing":
            fails.append("缺環境變數時探針工具 state 應為 missing")

    # 目標不在 config/targets.yaml 允許清單 → 授權檢查擋下 → incomplete，不送任何請求（離線）
    with tempfile.TemporaryDirectory() as d:
        env = {"VIBESEC_TARGET_URL": "http://unauthorized.example", "VIBESEC_CONFIG": str(repo / "vibesec.yaml")}
        code, g = run_in(d, env)
        if code != 0 or not g or g["status"] != "incomplete" or "授權檢查" not in (g.get("status_reason") or ""):
            fails.append(f"未授權目標 → 應 incomplete 並說明授權檢查未過（得到 code={code}, gate={g}）")
        elif list(schema.iter_errors(g)):
            fails.append(f"未授權目標的 gate 不符 schema：{list(schema.iter_errors(g))[0].message}")

    # jwt_alg_none：對本機假目標（127.0.0.1 在 config/targets.yaml 允許清單）實測三種情境。
    # 以前沒有端點對合法 token 回 200 時直接記 pass；現在要明確 401/403 才 pass，否則 untested。
    import http.server, threading
    legit = f"{b64url(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode())}.{b64url(json.dumps({'sub': 'a'}).encode())}.sig"

    def serve(mode):
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def _reply(self):
                auth = self.headers.get("Authorization", "")
                if self.path == "/openapi.json":
                    code = 200
                elif self.path == "/me" and mode != "no-protected":
                    if auth == f"Bearer {legit}":
                        code = 200
                    elif auth.endswith("."):                   # alg:none 偽造 token：簽章段為空
                        code = 200 if mode == "accepts-none" else 401
                    else:
                        code = 401
                else:
                    code = 404
                self.send_response(code); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b"{}")
            do_GET = do_POST = do_OPTIONS = _reply
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    for mode, want in [("no-protected", "untested"), ("rejects-none", "pass"), ("accepts-none", "fail")]:
        srv = serve(mode)
        try:
            with tempfile.TemporaryDirectory() as d:
                (pathlib.Path(d) / "a").write_text(legit)
                env = {"VIBESEC_TARGET_URL": f"http://127.0.0.1:{srv.server_address[1]}",
                       "VIBESEC_CONFIG": str(repo / "vibesec.yaml"), "VIBESEC_TOKEN_DIR": d, "HAS_A": "true"}
                code, g = run_in(d, env)
                got = next((c for c in (g or {}).get("coverage", []) if c["control_id"] == "jwt_alg_none"), None)
                if code != 0 or not got or got["state"] != want:
                    fails.append(f"jwt_alg_none（{mode}）應為 {want}（得到 {got}）")
                elif want == "untested" and not got.get("reason"):
                    fails.append("jwt_alg_none untested 時應說明原因")
                elif g and list(schema.iter_errors(g)):
                    fails.append(f"jwt_alg_none（{mode}）的 gate 不符 schema：{list(schema.iter_errors(g))[0].message}")
        finally:
            srv.shutdown(); srv.server_close()

    return fails


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        _fails = selftest()
        print("selftest 通過" if not _fails else "selftest 失敗 {} 項".format(len(_fails)))
        for _f in _fails:
            print("FAIL", _f)
        sys.exit(1 if _fails else 0)
    sys.exit(main())
