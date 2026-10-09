#!/usr/bin/env python3
"""G5 API 探針：只對明確授權的目標執行；CI 與評測共用。"""

def main():
    # G5 api-probes — 僅對已授權 VIBESEC_TARGET_URL 執行（CLAUDE.md #8）。
    # checks: bola_idor, jwt_alg_none, jwt_alg_confusion, ssrf_metadata,
    #         swagger_exposed, graphql_introspection, debug_stacktrace, rate_limit, session_check
    import json, os, re, time, base64, pathlib, datetime, urllib.request, urllib.error, sys
    NOW = datetime.datetime.now(datetime.timezone.utc)
    def iso(dt): return dt.replace(microsecond=0).isoformat()
    URL = os.environ["VIBESEC_TARGET_URL"].rstrip("/")
    # tier 只來自 blocking-policy（含 risk_tier 的 tier_overrides）；VIBESEC_CONFIG 指向 repo 的 vibesec.yaml
    ROOT = pathlib.Path(os.environ.get("VIBESEC_CONFIG", "vibesec.yaml")).resolve().parent
    sys.path.insert(0, str(ROOT / "scripts"))
    from vibesec_policy import Policy
    POLICY = Policy(ROOT)
    import yaml
    CONFIG = yaml.safe_load((ROOT / "vibesec.yaml").read_text())
    MODE = "enforce" if CONFIG.get("mode") == "enforce" or os.environ.get("VIBESEC_MODE") == "enforce" else "shadow"
    def _read(name):
        d = os.environ.get("VIBESEC_TOKEN_DIR", "")
        f = pathlib.Path(d) / name if d else None
        return f.read_text().strip() if f and f.is_file() else ""
    TA = _read("a") or os.environ.get("VIBESEC_TOKEN_A", ""); TB = _read("b") or os.environ.get("VIBESEC_TOKEN_B", "")
    HAS_A = bool(TA); HAS_B = bool(TB) and TA != TB
    REPORTS = pathlib.Path("reports"); REPORTS.mkdir(exist_ok=True)

    results = []; rules = {}
    coverage = {}  # control_id -> state
    coverage_reasons = {}  # control_id -> reason（not_applicable 必填，untested 可選）
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

    from safe_http import TargetClient
    client = TargetClient(URL)
    def req(path, method="GET", token=None, data=None, headers=None, timeout=15):
        return client.request(path, method, token, data, headers, timeout)

    # 連線性檢查
    status, _ = req("/openapi.json")
    reachable = status is not None
    incomplete_reason = None
    if not reachable:
        incomplete_reason = f"目標 {URL} 無法連線"

    # ---- swagger_exposed ----
    if reachable:
        exposed = []
        for p in ["/openapi.json", "/docs", "/redoc", "/swagger", "/swagger.json"]:
            s, _ = req(p)
            if s == 200: exposed.append(p)
        if exposed:
            add("vibesec.g5.swagger-exposed", "warning",
                f"API 文件/schema 對外暴露：{', '.join(exposed)}（開發便利設定外溢）")
            coverage["swagger_exposed"] = "fail"
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
        else:
            coverage["graphql_introspection"] = "pass" if s is not None else "untested"

    # ---- cors_reflect_origin ----
    # 帶一個不可能在白名單內的 Origin（RFC 2606 保留網域）；ACAO 反射它且 ACAC: true → 任意網站可帶 cookie/憑證讀回應
    if reachable:
        EVIL = "https://vibesec-cors-probe.invalid"
        h = {"User-Agent": "vibesec-g5-probes", "Origin": EVIL}
        if HAS_A: h["Authorization"] = f"Bearer {TA}"
        try:
            with client.open(urllib.request.Request(URL + "/openapi.json", headers=h), timeout=15) as resp:
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
    # 以現有 token payload 重組 alg:none，送至受保護端點
    def b64url(d): return base64.urlsafe_b64encode(d).decode().rstrip("=")
    if reachable and HAS_A and TA.count(".") == 2:
        try:
            _, payload_b64, _ = TA.split(".")
            pad = "=" * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + pad))
            header = {"alg": "none", "typ": "JWT"}
            forged = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}."
            # 探測一組常見受保護端點
            accepted = None; rejected = False
            for p in ["/me", "/api/me", "/profile", "/users/me", "/account"]:
                s_auth, _ = req(p, token=TA)
                if s_auth == 200:
                    s_forged, _ = req(p, token=forged)
                    if s_forged == 200:
                        accepted = p; break
                    if s_forged in (401, 403): rejected = True
            if accepted:
                add("vibesec.g5.jwt-alg-none", "error",
                    f"受保護端點 {accepted} 接受 alg:none 偽造 JWT（授權繞過）")
                coverage["jwt_alg_none"] = "fail"
            else:
                coverage["jwt_alg_none"] = "pass" if rejected else "untested"
        except Exception as e:
            coverage["jwt_alg_none"] = "untested"
    else:
        coverage["jwt_alg_none"] = "untested"

    # ---- jwt_alg_confusion（RS256→HS256）----
    # 從目標公開的 JWKS 取 RSA 公鑰，轉成 PEM（stdlib 手組 SubjectPublicKeyInfo DER），
    # 以 PEM 當 HMAC 金鑰重簽同一 payload 送出：接受 → fail；明確 401/403 → pass。
    # token 使用對稱演算法（無公鑰可混淆）→ not_applicable；取不到公鑰 → untested（incomplete ≠ pass）。
    import hashlib, hmac
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
                if ju: uris.insert(0, ju)
            except Exception: pass
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
            add("vibesec.g5.jwt-alg-confusion", "note",
                "未能從 JWKS 取得 RSA 公鑰 → untested，建議人工/Burp 驗證")
        else:
            try:
                h_b64, p_b64, _ = TA.split(".")
                header = {"alg": "HS256", "typ": "JWT"}
                new_h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
                signing_input = f"{new_h}.{p_b64}".encode()
                sig = base64.urlsafe_b64encode(hmac.new(pem, signing_input, hashlib.sha256).digest()).decode().rstrip("=")
                forged = f"{new_h}.{p_b64}.{sig}"
                accepted = None; rejected = False
                for p in ["/me", "/api/me", "/profile", "/users/me", "/account"]:
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

    # 專案宣告的情境：資源建立、跨租戶、寫入與功能層級權限。
    context_path = os.environ.get("VIBESEC_ACCESS_CONTEXT") or str(ROOT / "config/zap/two-account-context.yaml")
    try:
        from access_scenarios import run as run_access
        context = yaml.safe_load(pathlib.Path(context_path).read_text())
        found, state, why = run_access(client, context, {"A": TA, "B": TB}, os.environ)
        for rule, message in found: add(rule, "error", message)
        coverage["ASVS5-V8.1"] = state
        if why: coverage_reasons["ASVS5-V8.1"] = why
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError) as e:
        coverage["ASVS5-V8.1"] = "untested"
        coverage_reasons["ASVS5-V8.1"] = f"存取控制情境無法執行：{type(e).__name__}"

    # ---- ssrf_metadata ----
    # 判定原則（incomplete ≠ pass）：命中才 fail；端點以 400/403 明確拒絕內部 URL 才 pass；其餘 untested。
    # 回應常回顯送出的 URL，比對前先移除，避免把回顯誤判為命中。
    if reachable:
        import urllib.parse
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
    def _protected_paths():
        try:
            cfg = yaml.safe_load(pathlib.Path(os.environ.get("VIBESEC_CONFIG", str(ROOT / "vibesec.yaml"))).read_text(encoding="utf-8"))
        except OSError:
            return []
        paths = cfg.get("gates", {}).get("g5_dast_api", {}).get("protected_paths")
        return paths if isinstance(paths, list) and all(isinstance(p, str) and p.startswith("/") for p in paths) else []
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
        if 429 not in codes:
            add("vibesec.g5.missing-rate-limit", "warning",
                "登入端點 25 次連續請求未見 429（缺 Rate Limiting / Captcha）")
            coverage["rate_limit"] = "fail"
        else:
            coverage["rate_limit"] = "pass"

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
        gstatus = "fail"  # 但 mode=shadow 僅報告（見 summary）
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
    gate = {"gate": "G5", "status": gstatus, "status_reason": status_reason,
            "mode": MODE, "scope": "full", "diff_base": None,
            "commit": None, "started_at": iso(NOW),
            "finished_at": iso(datetime.datetime.now(datetime.timezone.utc)),
            "tools": [{"name": "vibesec-g5-api-probes", "version": "1.0.0", "state": "ran",
                       "exit_code": 0, "output_ref": "reports/g5-api-probes.sarif", "duration_seconds": None}],
            "findings_count": {"blocking": blocking, "advisory": advisory},
            "coverage": cov}
    (REPORTS / "g5-gate.json").write_text(json.dumps(gate, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"G5 api-probes: status={gstatus} blocking={blocking} advisory={advisory}")
    print(json.dumps(coverage, ensure_ascii=False))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
