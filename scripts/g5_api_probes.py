#!/usr/bin/env python3
"""VibeSec G5 api-probes：雙帳號 BOLA／JWT／SSRF／設定外溢／rate-limit 等黑箱探針（docs/06）。

核心邏輯收斂於無全域狀態、無環境變數與檔案副作用的純值入口：
  outcome = run_probes(G5Request(...), transport=...)

命令列薄殼讀取環境變數（VIBESEC_TARGET_URL、VIBESEC_CONFIG、VIBESEC_TOKEN_DIR、HAS_A、HAS_B）與選用的
reports/g5-zap.json，呼叫 run_probes 後寫出 reports/g5-api-probes.sarif（或刪除舊檔）與 reports/g5-gate.json。
mode 與規則政策 tier 唯一取自受信任樹政策（ADR 0002）；所有 HTTP 請求經 target_guard.authorize_target 發送（AGENTS.md 規則 8）。
"""
from __future__ import annotations
import base64, contextlib, dataclasses, datetime, hashlib, hmac, json, os, pathlib, re, sys, types, typing, urllib.parse

# 自身所在的 scripts/ 放到 path 最前，不論 cwd 或 python3 -I 都能 import 同層模組
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import gate_result  # noqa: E402
from target_guard import (  # noqa: E402
    AuthorizedTarget,
    HttpResponse,
    OffOrigin,
    TargetDenied,
    TargetTransport,
    TransportError,
    authorize_target,
)
from vibesec_policy import Policy, effective_mode, load_policy  # noqa: E402
import yaml  # noqa: E402

DEFAULT_ROOT: typing.Final[pathlib.Path] = pathlib.Path(__file__).resolve().parent.parent
TOOL_NAME, TOOL_VERSION = "vibesec-g5-api-probes", "1.0.0"
USER_AGENT: typing.Final[str] = "vibesec-g5-probes"
SARIF_REF: typing.Final[str] = "reports/g5-api-probes.sarif"
SARIF_LOCATION_URI: typing.Final[str] = ".github/workflows/staging-blackbox.yml"

# JWT 探針（alg:none、alg confusion）嘗試的受保護端點：合法 token 須回 200 才拿來送偽造 token
JWT_PROBE_PATHS: typing.Final[tuple[str, ...]] = ("/me", "/api/me", "/profile", "/users/me", "/account")
# 探針的 check（同 vibesec.yaml gates.g5_dast_api.checks，selftest 核對）；政策檔讀不到時與 ZAP 掃描一起記 untested
CHECKS: typing.Final[tuple[str, ...]] = (
    "bola_idor",
    "jwt_alg_none",
    "jwt_alg_confusion",
    "ssrf_metadata",
    "swagger_exposed",
    "graphql_introspection",
    "debug_stacktrace",
    "rate_limit",
    "session_check",
    "cors_reflect_origin",
)
ZAP_SCANS: typing.Final[tuple[str, ...]] = ("zap_api_scan", "zap_baseline")
# 正常路徑的 coverage 順序＝探針的執行順序；與 CHECKS＋ZAP_SCANS 是同一組控制（#184 決定 5）
EXEC_ORDER: typing.Final[tuple[str, ...]] = (
    "swagger_exposed",
    "graphql_introspection",
    "cors_reflect_origin",
    "debug_stacktrace",
    "jwt_alg_none",
    "jwt_alg_confusion",
    "bola_idor",
    "ssrf_metadata",
    "session_check",
    "rate_limit",
    *ZAP_SCANS,
)
RULE_CONTROL: typing.Final[typing.Mapping[str, str]] = types.MappingProxyType(
    {
        "vibesec.g5.bola-cross-account": "bola_idor",
        "vibesec.g5.jwt-alg-none": "jwt_alg_none",
        "vibesec.g5.jwt-alg-confusion": "jwt_alg_confusion",
        "vibesec.g5.ssrf-metadata": "ssrf_metadata",
        "vibesec.g5.ssrf-internal-fetch": "ssrf_metadata",
        "vibesec.g5.swagger-exposed": "swagger_exposed",
        "vibesec.g5.graphql-introspection": "graphql_introspection",
        "vibesec.g5.debug-stacktrace": "debug_stacktrace",
        "vibesec.g5.missing-rate-limit": "rate_limit",
        "vibesec.g5.missing-session-check": "session_check",
        "vibesec.g5.cors-reflect-origin": "cors_reflect_origin",
    }
)
_VALID_COV_STATES: typing.Final[frozenset[str]] = frozenset({"pass", "fail", "untested", "not_applicable"})
_VALID_TIERS: typing.Final[frozenset[str]] = frozenset({"blocking", "advisory"})


@dataclasses.dataclass(frozen=True)
class ProbeTokens:
    token_a: str | None = None
    token_b: str | None = None

    def __post_init__(self) -> None:
        norm_a = self.token_a.strip() if isinstance(self.token_a, str) else ""
        norm_b = self.token_b.strip() if isinstance(self.token_b, str) else ""
        object.__setattr__(self, "token_a", norm_a or None)
        object.__setattr__(self, "token_b", norm_b or None)

    @property
    def has_a(self) -> bool:
        return self.token_a is not None

    @property
    def has_b(self) -> bool:
        return self.token_b is not None


@dataclasses.dataclass(frozen=True)
class ZapUnavailable:
    reason: str


@dataclasses.dataclass(frozen=True)
class G5Request:
    target_url: str | None
    policy_root: pathlib.Path = DEFAULT_ROOT
    tokens: ProbeTokens = dataclasses.field(default_factory=ProbeTokens)
    zap: typing.Mapping[str, typing.Any] | ZapUnavailable | None = None
    sarif_ref: str = SARIF_REF
    started_at: datetime.datetime | None = None


@dataclasses.dataclass(frozen=True)
class G5Finding:
    rule_id: str
    policy_tier: str
    level: str
    message: str
    source: str


@dataclasses.dataclass(frozen=True)
class G5Outcome:
    gate: dict[str, typing.Any]
    sarif: dict[str, typing.Any] | None
    findings: tuple[G5Finding, ...]
    coverage: typing.Mapping[str, str]

    def control(self, control_id: str) -> dict[str, typing.Any] | None:
        for item in self.gate.get("coverage") or ():
            if item.get("control_id") == control_id:
                return item
        return None


def iso(dt: datetime.datetime) -> str:
    return dt.replace(microsecond=0).isoformat()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64u_dec(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _der_uint(val: int) -> bytes:
    b = val.to_bytes((val.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return _der_tlv(0x02, b)


def _spki_pem(n: int, e: int) -> bytes:
    rsa_oid = bytes.fromhex("300d06092a864886f70d0101010500")          # AlgorithmIdentifier: rsaEncryption + NULL
    pub_seq = _der_tlv(0x30, _der_uint(n) + _der_uint(e))                 # RSAPublicKey SEQUENCE
    spki = _der_tlv(0x30, rsa_oid + _der_tlv(0x03, b"\x00" + pub_seq))    # SubjectPublicKeyInfo
    # 須與 cryptography 的 PEM 輸出逐位元組一致（HMAC 金鑰即 PEM bytes）：base64 每 64 字元換行
    b64 = base64.b64encode(spki).decode()
    body = "".join(b64[i : i + 64] + "\n" for i in range(0, len(b64), 64))
    return ("-----BEGIN PUBLIC KEY-----\n" + body + "-----END PUBLIC KEY-----\n").encode()


def _token_alg(tok: str) -> str:
    try:
        return (json.loads(_b64u_dec(tok.split(".")[0])).get("alg") or "").upper()
    except Exception:
        return ""


def _graphql_shaped(body: str | None) -> bool:
    """回應是否為 GraphQL 格式（JSON 物件且有 errors 或 data 鍵）。"""
    try:
        d = json.loads(body or "")
    except ValueError:
        return False
    return isinstance(d, dict) and ("errors" in d or "data" in d)


def _protected_paths(policy_root: pathlib.Path) -> tuple[str, ...]:
    try:
        cfg = yaml.safe_load((policy_root / "vibesec.yaml").read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return ()
    if not isinstance(cfg, dict):
        return ()
    gates = cfg.get("gates")
    if not isinstance(gates, dict):
        return ()
    g5_cfg = gates.get("g5_dast_api")
    if not isinstance(g5_cfg, dict):
        return ()
    raw_paths = g5_cfg.get("protected_paths")
    if not isinstance(raw_paths, list) or any(not isinstance(item, str) for item in raw_paths):
        return ()
    return tuple(s for item in raw_paths if (s := item.strip()))


def _cors_paths(protected: typing.Sequence[str]) -> list[str]:
    """CORS 探測的端點：受保護路徑與 JWT 探針端點（實際 API），最後才是 /openapi.json 與 /。"""
    seen: set[str] = set()
    out: list[str] = []
    for p in [*protected, *JWT_PROBE_PATHS, "/openapi.json", "/"]:
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _gate_run(mode: str, started: datetime.datetime, controls: typing.Iterable[str]) -> gate_result.GateRun:
    return gate_result.GateRun("G5", controls=list(controls), mode=mode, scope="full", started_at=iso(started))


def _problems(incomplete_reason: str | None, has_a: bool, has_b: bool) -> list[str]:
    problems = [incomplete_reason] if incomplete_reason else []
    if not (has_a and has_b):
        problems.append(f"雙帳號測試需兩個 token（has_a={has_a}, has_b={has_b}）；缺 token 的 BOLA/JWT 檢查記為 untested")
    return problems


class _ProbeSession:
    def __init__(self, request: G5Request, policy: Policy, base_url: str) -> None:
        self.request = request
        self.policy = policy
        self.base_url = base_url
        self.tokens = request.tokens
        self.protected_paths: tuple[str, ...] = _protected_paths(request.policy_root)
        self.rules: dict[str, dict[str, typing.Any]] = {}
        self.results: list[dict[str, typing.Any]] = []
        self.coverage: dict[str, str] = {}
        self.coverage_reasons: dict[str, str] = {}
        self.jwks_skipped: list[str] = []
        self.zap_tools: list[dict[str, typing.Any]] = []

    def add(self, rule_id: str, level: str, msg: str) -> None:
        tier = "advisory" if level == "note" else self.policy.tier(rule_id)  # note = 未能實測的提示，不是發現
        self.rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": rule_id},
                "defaultConfiguration": {"level": level},
                "properties": {"policy_tier": tier},
            },
        )
        self.results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": msg},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": SARIF_LOCATION_URI}}}],
                "properties": {"policy_tier": tier, "target_url": self.base_url},
            }
        )

    @staticmethod
    def send(
        auth: AuthorizedTarget,
        path: str,
        method: str = "GET",
        *,
        token: str | None = None,
        data: object = None,
        headers: typing.Mapping[str, str] | None = None,
        timeout: float = 15.0,
    ) -> tuple[int | None, str]:
        outcome = auth.request(
            path,
            method=method,
            json_body=data,
            headers=headers,
            bearer_token=token,
            timeout=timeout,
        )
        if isinstance(outcome, OffOrigin):
            return None, f"拒絕：非授權來源（{outcome.reason}），未送出請求"
        if isinstance(outcome, TransportError):
            return None, outcome.reason
        assert isinstance(outcome, HttpResponse)
        return outcome.status, outcome.text

    def probe_forged_jwt(self, auth: AuthorizedTarget, tok_a: str, forged: str) -> tuple[str | None, bool, list[str]]:
        accepted: str | None = None
        rejected = False
        probed: list[str] = []
        for p in JWT_PROBE_PATHS:
            s_auth, _ = self.send(auth, p, token=tok_a)
            if s_auth != 200:
                continue
            s_forged, _ = self.send(auth, p, token=forged)
            probed.append(f"{p}→{s_forged}")
            if s_forged == 200:
                accepted = p
                break
            if s_forged in (401, 403):
                rejected = True
        return accepted, rejected, probed

    @staticmethod
    def _jwt_untested_reason(probed: list[str]) -> str:
        if probed:
            return f"偽造 token 未得到明確 401/403（{'、'.join(probed)}）"
        return f"沒有端點對合法 token 回 200（試過 {'、'.join(JWT_PROBE_PATHS)}），找不到受保護端點可測"

    def fetch_pem(self, auth: AuthorizedTarget) -> bytes | None:
        tok_a = self.tokens.token_a or ""
        try:
            kid = json.loads(_b64u_dec(tok_a.split(".")[0])).get("kid")
        except Exception:
            kid = None
        uris = ["/.well-known/jwks.json", "/jwks.json"]
        _, body_oidc = self.send(auth, "/.well-known/openid-configuration")
        if body_oidc:
            try:
                oidc_doc = json.loads(body_oidc)
                if not isinstance(oidc_doc, dict):
                    raise TypeError("oidc root")
                ju = oidc_doc.get("jwks_uri")
                if isinstance(ju, str) and ju:
                    off = auth.check_origin(ju)
                    if off is None:
                        uris.insert(0, ju)
                    else:
                        self.jwks_skipped.append(f"OIDC discovery 的 jwks_uri {ju[:200]!r} 非授權來源，未抓取（{off.reason}）")
            except (ValueError, TypeError, KeyError):
                self.jwks_skipped.append("OIDC discovery 回應無法解析為 JSON 物件，改用預設 jwks 路徑")
        for u in uris:
            status_j, body_j = self.send(auth, u)
            if status_j is None or not body_j:
                continue
            try:
                jwk_items = json.loads(body_j).get("keys", [])
            except Exception:
                continue
            rsa_items = [k for k in jwk_items if isinstance(k, dict) and k.get("kty") == "RSA" and k.get("n") and k.get("e")]
            if not rsa_items:
                continue
            chosen = next((k for k in rsa_items if kid and k.get("kid") == kid), rsa_items[0])
            n = int.from_bytes(_b64u_dec(chosen["n"]), "big")
            e = int.from_bytes(_b64u_dec(chosen["e"]), "big")
            return _spki_pem(n, e)
        return None

    def check_swagger(self, auth: AuthorizedTarget) -> None:
        exposed, answered = [], 0
        for p in ("/openapi.json", "/docs", "/redoc", "/swagger", "/swagger.json"):
            s, _ = self.send(auth, p)
            answered += s is not None
            if s == 200:
                exposed.append(p)
        if exposed:
            self.add(
                "vibesec.g5.swagger-exposed",
                "warning",
                f"API 文件/schema 對外暴露：{', '.join(exposed)}（開發便利設定外溢）",
            )
            self.coverage["swagger_exposed"] = "fail"
        elif not answered:
            self.coverage["swagger_exposed"] = "untested"
            self.coverage_reasons["swagger_exposed"] = "所有文件路徑的請求都失敗"
        else:
            self.coverage["swagger_exposed"] = "pass"

    def check_graphql(self, auth: AuthorizedTarget) -> None:
        s, body = self.send(auth, "/graphql", "POST", data={"query": "{__schema{types{name}}}"})
        if s == 200 and "__schema" in (body or ""):
            self.add("vibesec.g5.graphql-introspection", "warning", "GraphQL introspection 開啟（洩漏 schema）")
            self.coverage["graphql_introspection"] = "fail"
        elif s in (404, 405):
            self.coverage["graphql_introspection"] = "not_applicable"
            self.coverage_reasons["graphql_introspection"] = f"POST /graphql 回 HTTP {s}：目標沒有 GraphQL 端點"
        elif s in (200, 400) and _graphql_shaped(body):
            self.coverage["graphql_introspection"] = "pass"
        else:
            self.coverage["graphql_introspection"] = "untested"
            self.coverage_reasons["graphql_introspection"] = (
                f"POST /graphql 回 HTTP {s}，不是 GraphQL 格式的拒絕回應，無法判定"
                if s is not None
                else "POST /graphql 請求失敗"
            )

    def check_cors(self, auth: AuthorizedTarget) -> None:
        evil = "https://vibesec-cors-probe.invalid"
        tok = self.tokens.token_a if self.tokens.has_a else None
        reflected = None
        clean: list[str] = []
        tried: list[str] = []
        for p in _cors_paths(self.protected_paths):
            outcome = auth.request(p, headers={"Origin": evil}, bearer_token=tok, timeout=15.0)
            if isinstance(outcome, OffOrigin):
                continue
            if isinstance(outcome, TransportError):
                tried.append(f"{p}→失敗")
                continue
            assert isinstance(outcome, HttpResponse)
            code = outcome.status
            tried.append(f"{p}→{code}")
            acao = outcome.header("Access-Control-Allow-Origin")
            acac = outcome.header("Access-Control-Allow-Credentials")
            if acao == evil and str(acac).lower() == "true":
                reflected = f"{p}（HTTP {code}）"
                break
            if code != 404:
                clean.append(p)
        if reflected:
            self.add(
                "vibesec.g5.cors-reflect-origin",
                "error",
                f"CORS 反射任意 Origin 且 Access-Control-Allow-Credentials: true：{reflected}",
            )
            self.coverage["cors_reflect_origin"] = "fail"
        elif clean:
            self.coverage["cors_reflect_origin"] = "pass"
        else:
            self.coverage["cors_reflect_origin"] = "untested"
            self.coverage_reasons["cors_reflect_origin"] = "沒有任何實際存在的端點可測 CORS（" + "、".join(tried) + "）"

    def check_stacktrace(self, auth: AuthorizedTarget) -> None:
        markers = ("Traceback (most recent call last)", 'File "', "Exception", "at line")
        leaked = lambda b: bool(b) and any(m in b for m in markers)
        s, body = self.send(auth, "/__vibesec_nonexistent__/%ff", "GET")
        answered = s is not None
        if not leaked(body):
            try:
                _, spec = self.send(auth, "/openapi.json", token=self.tokens.token_a)
                spec_obj = json.loads(spec or "{}")
                paths_map = spec_obj.get("paths") if isinstance(spec_obj, dict) else None
                posts = [
                    p_name
                    for p_name, ops in (paths_map or {}).items()
                    if isinstance(p_name, str) and isinstance(ops, dict) and "post" in ops and "{" not in p_name
                ][:5]
            except ValueError:
                posts = []
            for path in posts:
                s, body = self.send(auth, path, "POST", data={"query": 0, "message": 0, "input": 0, "id": 0})
                answered = answered or s is not None
                if leaked(body):
                    break
        if leaked(body):
            self.add("vibesec.g5.debug-stacktrace", "warning", "錯誤回應洩漏 stack trace（Debug Mode 外溢）")
            self.coverage["debug_stacktrace"] = "fail"
        elif not answered:
            self.coverage["debug_stacktrace"] = "untested"
            self.coverage_reasons["debug_stacktrace"] = "錯誤誘發請求都沒有得到 HTTP 回應"
        else:
            self.coverage["debug_stacktrace"] = "pass"

    def check_jwt_none(self, auth: AuthorizedTarget) -> None:
        tok_a = self.tokens.token_a or ""
        if self.tokens.has_a and tok_a.count(".") == 2:
            try:
                _, payload_b64, _ = tok_a.split(".")
                payload = json.loads(_b64u_dec(payload_b64))
                header = {"alg": "none", "typ": "JWT"}
                forged = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}."
                accepted, rejected, probed = self.probe_forged_jwt(auth, tok_a, forged)
                if accepted:
                    self.add("vibesec.g5.jwt-alg-none", "error", f"受保護端點 {accepted} 接受 alg:none 偽造 JWT（授權繞過）")
                    self.coverage["jwt_alg_none"] = "fail"
                elif rejected:
                    self.coverage["jwt_alg_none"] = "pass"
                else:
                    self.coverage["jwt_alg_none"] = "untested"
                    self.coverage_reasons["jwt_alg_none"] = self._jwt_untested_reason(probed)
            except Exception:
                self.coverage["jwt_alg_none"] = "untested"
        else:
            self.coverage["jwt_alg_none"] = "untested"

    def check_jwt_confusion(self, auth: AuthorizedTarget) -> None:
        tok_a = self.tokens.token_a or ""
        if not self.tokens.has_a or tok_a.count(".") != 2:
            self.coverage["jwt_alg_confusion"] = "untested"
            return
        alg = _token_alg(tok_a)
        if alg.startswith("HS"):
            self.coverage["jwt_alg_confusion"] = "not_applicable"
            self.coverage_reasons["jwt_alg_confusion"] = "token 使用對稱演算法（HS*），無公鑰可混淆"
            return
        pem = self.fetch_pem(auth)
        if not pem:
            self.coverage["jwt_alg_confusion"] = "untested"
            skip = "；".join(self.jwks_skipped)
            if skip:
                self.coverage_reasons["jwt_alg_confusion"] = f"未能從同源 JWKS 取得 RSA 公鑰；{skip}"
            self.add(
                "vibesec.g5.jwt-alg-confusion",
                "note",
                "未能從 JWKS 取得 RSA 公鑰 → untested，建議人工/Burp 驗證" + (f"（{skip}）" if skip else ""),
            )
            return
        try:
            _, p_b64, _ = tok_a.split(".")
            new_h = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
            sig = b64url(hmac.new(pem, f"{new_h}.{p_b64}".encode(), hashlib.sha256).digest())
            forged = f"{new_h}.{p_b64}.{sig}"
            accepted, rejected, probed = self.probe_forged_jwt(auth, tok_a, forged)
            if accepted:
                self.add(
                    "vibesec.g5.jwt-alg-confusion",
                    "error",
                    f"受保護端點 {accepted} 接受以公鑰 PEM 當 HMAC 金鑰的 HS256 偽造 JWT（RS256→HS256 混淆）",
                )
                self.coverage["jwt_alg_confusion"] = "fail"
            elif rejected:
                self.coverage["jwt_alg_confusion"] = "pass"
            else:
                self.coverage["jwt_alg_confusion"] = "untested"
                self.coverage_reasons["jwt_alg_confusion"] = self._jwt_untested_reason(probed)
        except Exception:
            self.coverage["jwt_alg_confusion"] = "untested"

    def check_bola(self, auth: AuthorizedTarget) -> None:
        tok_a = self.tokens.token_a or ""
        tok_b = self.tokens.token_b or ""
        if not (self.tokens.has_a and self.tokens.has_b):
            self.coverage["bola_idor"] = "untested"
            return
        discovered: list[tuple[str | None, str]] = []
        for listp in ("/api/items", "/items", "/api/orders", "/orders", "/api/documents", "/documents"):
            s, body = self.send(auth, listp, token=tok_a)
            if s == 200 and body:
                ids = re.findall(r'"id"\s*:\s*"?([A-Za-z0-9\-]+)"?', body)
                for rid in ids[:3]:
                    discovered.append((listp, rid))
        for mep in ("/me", "/api/me"):
            s, body = self.send(auth, mep, token=tok_a)
            if s == 200 and body:
                m = re.search(r'"id"\s*:\s*"?([A-Za-z0-9\-]+)"?', body)
                if m:
                    for tpl in ("/users/{}/notes", "/users/{}", "/api/users/{}"):
                        discovered.append((None, tpl.format(m.group(1))))
                    break
        confirmed = False
        checked = False
        for base, rid in discovered:
            resource = rid if base is None else f"{base}/{rid}"
            s_a, _ = self.send(auth, resource, token=tok_a)
            if s_a != 200:
                continue
            s_b, _ = self.send(auth, resource, token=tok_b)
            if s_b in (401, 403, 404):
                checked = True
            if s_b == 200:
                self.add(
                    "vibesec.g5.bola-cross-account",
                    "error",
                    f"雙帳號 BOLA 實證：帳號 B 可存取帳號 A 的資源 {resource}（HTTP 200）",
                )
                confirmed = True
                break
        self.coverage["bola_idor"] = "fail" if confirmed else ("pass" if checked else "untested")

    def check_ssrf(self, auth: AuthorizedTarget) -> None:
        meta = "http://169.254.169.254/latest/meta-data/"
        canary = f"http://127.0.0.1:{auth.origin.port}/openapi.json"
        tok_a = self.tokens.token_a

        def ssrf_try(ep: str, param: str, dest: str) -> list[tuple[str, int | None, str]]:
            out = []
            q = urllib.parse.urlencode({param: dest})
            out.append(("GET",) + self.send(auth, f"{ep}?{q}", "GET", token=tok_a))
            out.append(("POST",) + self.send(auth, ep, "POST", token=tok_a, data={param: dest}))
            return [(m, s, (b or "").replace(dest, "")) for m, s, b in out]

        baseline_cache: dict[tuple[str, str], int | None] = {}

        def ssrf_baseline(ep: str, method: str) -> int | None:
            if (ep, method) not in baseline_cache:
                junk = {"vibesec_unrelated": "x"}
                res = (
                    self.send(auth, f"{ep}?{urllib.parse.urlencode(junk)}", "GET", token=tok_a)
                    if method == "GET"
                    else self.send(auth, ep, "POST", token=tok_a, data=junk)
                )
                baseline_cache[(ep, method)] = res[0]
            return baseline_cache[(ep, method)]

        ssrf_hit = False
        internal_hit = False
        refused = False
        reached = False
        for ep in ("/fetch", "/api/fetch", "/import", "/api/import", "/proxy", "/url"):
            for param in ("url", "uri", "target", "endpoint"):
                for m, s, body in ssrf_try(ep, param, meta):
                    if s == 200:
                        reached = True
                    if s in (400, 403) and ssrf_baseline(ep, m) != s:
                        refused = True
                    if s == 200 and any(ind in body for ind in ("ami-id", "instance-id", "iam/security-credentials", '"compute"')):
                        self.add("vibesec.g5.ssrf-metadata", "error", f"SSRF：端點 {ep}（{param}）可讀取雲端 metadata 169.254.169.254")
                        ssrf_hit = True
                        break
                if not internal_hit:
                    for _, s, body in ssrf_try(ep, param, canary):
                        if s == 200 and "openapi" in body:
                            self.add(
                                "vibesec.g5.ssrf-internal-fetch",
                                "error",
                                f"SSRF：端點 {ep}（{param}）會替使用者抓取內部位址 127.0.0.1（loopback canary 命中）",
                            )
                            internal_hit = True
                            break
                if ssrf_hit:
                    break
            if ssrf_hit:
                break
        if ssrf_hit or internal_hit:
            self.coverage["ssrf_metadata"] = "fail"
        elif refused and not reached:
            self.coverage["ssrf_metadata"] = "pass"
        else:
            self.coverage["ssrf_metadata"] = "untested"
            self.coverage_reasons["ssrf_metadata"] = (
                "端點接受了內部 URL 但未見 metadata 內容，無法判定"
                if reached
                else "沒有端點針對 URL 參數明確拒絕內部位址（400／403 與無關參數的回應相同或沒有回應）"
            )

    def check_session(self, auth: AuthorizedTarget) -> None:
        protected = self.protected_paths
        if not protected:
            self.coverage["session_check"] = "untested"
            self.coverage_reasons["session_check"] = "vibesec.yaml 未設定 gates.g5_dast_api.protected_paths"
            return
        leaked: list[str] = []
        unknown: list[str] = []
        for pth in protected:
            s_anon, _ = self.send(auth, pth)
            s_bad, _ = self.send(auth, pth, token="vibesec.invalid.token")
            open_codes = [c for c in (s_anon, s_bad) if c is not None and 200 <= c < 300]
            if open_codes:
                leaked.append(f"{pth}（無 token→{s_anon}、無效 token→{s_bad}）")
            elif s_anon in (401, 403) and s_bad in (401, 403):
                continue
            else:
                unknown.append(f"{pth}（{s_anon}/{s_bad}）")
        if leaked:
            self.add(
                "vibesec.g5.missing-session-check",
                "error",
                "受保護端點未驗證 token 即回 2xx（前端防禦假象）：" + "；".join(leaked),
            )
            self.coverage["session_check"] = "fail"
        elif unknown:
            self.coverage["session_check"] = "untested"
            self.coverage_reasons["session_check"] = "回應非 401/403，無法判定：" + "；".join(unknown)
        else:
            self.coverage["session_check"] = "pass"

    def check_rate_limit(self, auth: AuthorizedTarget) -> None:
        codes = [self.send(auth, "/login", "POST", data={"username": "alice", "password": "wrong"})[0] for _ in range(25)]
        if all(c is None for c in codes):
            self.coverage["rate_limit"] = "untested"
            self.coverage_reasons["rate_limit"] = "POST /login 的請求全部失敗"
        elif all(c in (404, 405) for c in codes):
            self.coverage["rate_limit"] = "untested"
            self.coverage_reasons["rate_limit"] = f"目標沒有 POST /login（HTTP {codes[0]}）"
        elif 429 not in codes:
            self.add("vibesec.g5.missing-rate-limit", "warning", "登入端點 25 次連續請求未見 429（缺 Rate Limiting / Captcha）")
            self.coverage["rate_limit"] = "fail"
        else:
            self.coverage["rate_limit"] = "pass"

    def merge_zap(self) -> None:
        zap = self.request.zap
        if zap is None:
            unavailable_reason = "沒有 ZAP 彙整結果（reports/g5-zap.json：FileNotFoundError）"
            for scan_name in ZAP_SCANS:
                self.coverage[scan_name] = "untested"
                self.coverage_reasons[scan_name] = unavailable_reason
            return
        if isinstance(zap, ZapUnavailable):
            for scan_name in ZAP_SCANS:
                self.coverage[scan_name] = "untested"
                self.coverage_reasons[scan_name] = zap.reason
            return
        try:
            staged_cov: dict[str, str] = {}
            staged_reasons: dict[str, str] = {}
            for cov_name, cov_item in zap["coverage"].items():
                if not isinstance(cov_item, dict) or cov_item.get("state") not in _VALID_COV_STATES:
                    raise ValueError("zap coverage")
                staged_cov[str(cov_name)] = str(cov_item["state"])
                if cov_item.get("reason"):
                    staged_reasons[str(cov_name)] = str(cov_item["reason"])
            staged_rules: dict[str, dict[str, typing.Any]] = {}
            for rid, rule_obj in zap["rules"].items():
                if not isinstance(rid, str) or not rid or not isinstance(rule_obj, dict):
                    raise ValueError("zap rules")
                staged_rules[rid] = rule_obj
            staged_results: list[dict[str, typing.Any]] = []
            for item in zap["results"]:
                if not isinstance(item, dict) or not isinstance(item.get("ruleId"), str) or not item["ruleId"]:
                    raise ValueError("zap result")
                props = item.get("properties")
                if not isinstance(props, dict) or props.get("policy_tier") not in _VALID_TIERS:
                    raise ValueError("zap policy_tier")
                staged_results.append(item)
            staged_tools: list[dict[str, typing.Any]] = []
            for tool_item in zap.get("tools") or ():
                if not isinstance(tool_item, dict) or not isinstance(tool_item.get("name"), str) or not isinstance(tool_item.get("state"), str):
                    raise ValueError("zap tools")
                staged_tools.append(tool_item)
        except Exception as e:
            for scan_name in ZAP_SCANS:
                self.coverage[scan_name] = "untested"
                self.coverage_reasons[scan_name] = f"沒有 ZAP 彙整結果（reports/g5-zap.json：{type(e).__name__}）"
            return

        self.coverage.update(staged_cov)
        self.coverage_reasons.update(staged_reasons)
        for rid, rule_obj in staged_rules.items():
            self.rules.setdefault(rid, rule_obj)
        self.results.extend(staged_results)
        self.zap_tools = staged_tools

    def build_outcome(
        self, mode: str, started: datetime.datetime, incomplete_reason: str | None
    ) -> tuple[G5Outcome, dict[str, str]]:
        sarif = gate_result.sarif({"name": TOOL_NAME, "version": TOOL_VERSION}, list(self.rules.values()), self.results)
        blocking = sum(1 for r in self.results if r["properties"]["policy_tier"] == "blocking")
        advisory = sum(1 for r in self.results if r["properties"]["policy_tier"] == "advisory")

        def cov_reason(cid: str, st: str) -> str | None:
            if cid in self.coverage_reasons:
                return self.coverage_reasons[cid]
            if st == "untested":
                return "缺 token 或目標限制，未能實測"
            if st == "not_applicable":
                return "此目標不適用該檢查"
            return None

        run = _gate_run(mode, started, EXEC_ORDER)
        run.tool(TOOL_NAME, "ran", version=TOOL_VERSION, exit_code=0, output_ref=self.request.sarif_ref)
        for t in self.zap_tools:
            run.tool(
                t["name"],
                t["state"],
                version=t.get("version"),
                exit_code=t.get("exit_code"),
                output_ref=t.get("output_ref"),
                duration_seconds=t.get("duration_seconds"),
            )
        for cid, st in self.coverage.items():
            run.cover(cid, st, cov_reason(cid, st))
        run.count(blocking=blocking, advisory=advisory)
        for prob in _problems(incomplete_reason, self.tokens.has_a, self.tokens.has_b):
            run.problem(prob)
        gate = run.result()

        findings = tuple(
            G5Finding(
                rule_id=str(r["ruleId"]),
                policy_tier=str(r["properties"]["policy_tier"]),
                level=str(r.get("level") or "warning"),
                message=str((r.get("message") or {}).get("text") or ""),
                source=str(r["properties"].get("source") or TOOL_NAME),
            )
            for r in self.results
            if r.get("level") != "note"
        )
        full_cov = types.MappingProxyType({c["control_id"]: c["state"] for c in gate["coverage"]})
        return G5Outcome(gate=gate, sarif=sarif, findings=findings, coverage=full_cov), dict(self.coverage)


def _execute_probes(
    request: G5Request, *, transport: TargetTransport | None = None
) -> tuple[G5Outcome, dict[str, str]]:
    started = request.started_at or datetime.datetime.now(datetime.timezone.utc)
    policy, problem = load_policy(request.policy_root)
    mode = effective_mode(policy)

    if not request.target_url:
        run = _gate_run(mode, started, (*CHECKS, *ZAP_SCANS))
        run.tool(TOOL_NAME, "missing", version=TOOL_VERSION, exit_code=0, output_ref=request.sarif_ref)
        run.problem("VIBESEC_TARGET_URL 未設定；未送出任何探針")
        gate = run.result()
        out = G5Outcome(
            gate=gate,
            sarif=None,
            findings=(),
            coverage=types.MappingProxyType({c["control_id"]: c["state"] for c in gate["coverage"]}),
        )
        return out, {}

    base_url = request.target_url.rstrip("/")
    if problem or policy is None:
        reason = problem or "blocking-policy 無法讀取"
        run = _gate_run(mode, started, (*CHECKS, *ZAP_SCANS))
        run.tool(TOOL_NAME, "error", version=TOOL_VERSION)
        for cid in (*CHECKS, *ZAP_SCANS):
            run.cover(cid, "untested", reason)
        run.problem(f"{reason}；未送出任何探針")
        gate = run.result()
        out = G5Outcome(
            gate=gate,
            sarif=None,
            findings=(),
            coverage=types.MappingProxyType({c["control_id"]: c["state"] for c in gate["coverage"]}),
        )
        return out, {}

    session = _ProbeSession(request, policy, base_url)
    auth_or_denied = authorize_target(
        base_url,
        root=request.policy_root,
        transport=transport,
        user_agent=USER_AGENT,
    )
    incomplete_reason: str | None = None
    auth: AuthorizedTarget | None = None
    if isinstance(auth_or_denied, TargetDenied):
        reachable = False
        incomplete_reason = f"目標未通過授權檢查（config/targets.yaml）：{auth_or_denied.reason}；未送出任何探針"
    else:
        auth = auth_or_denied
        status, _ = session.send(auth, "/openapi.json")
        reachable = status is not None
        if not reachable:
            incomplete_reason = f"目標 {base_url} 無法連線"

    if reachable and auth is not None:
        session.check_swagger(auth)
        session.check_graphql(auth)
        session.check_cors(auth)
        session.check_stacktrace(auth)
        session.check_jwt_none(auth)
        session.check_jwt_confusion(auth)
        session.check_bola(auth)
        session.check_ssrf(auth)
        session.check_session(auth)
        session.check_rate_limit(auth)
    else:
        for skipped_cid in ("jwt_alg_none", "jwt_alg_confusion", "bola_idor", "session_check"):
            session.coverage[skipped_cid] = "untested"
    session.merge_zap()
    return session.build_outcome(mode, started, incomplete_reason)


def run_probes(request: G5Request, *, transport: TargetTransport | None = None) -> G5Outcome:
    """執行 G5 黑箱探針並回傳純值 G5Outcome（無檔案與環境變數副作用）。"""
    return _execute_probes(request, transport=transport)[0]


def _read_token_file(token_dir: str, name: str) -> str | None:
    if not token_dir:
        return None
    f = pathlib.Path(token_dir) / name
    if not f.is_file():
        return None
    val = f.read_text(encoding="utf-8").strip()
    return val or None


def _load_zap_file(path: pathlib.Path) -> typing.Mapping[str, typing.Any] | ZapUnavailable:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("zap root")
        return data
    except Exception as e:
        return ZapUnavailable(f"沒有 ZAP 彙整結果（{path}：{type(e).__name__}）")


def main() -> int:
    """命令列薄殼：讀環境變數與暫存檔 → run_probes → 寫出 g5-gate.json 與寫出／刪除 g5-api-probes.sarif。"""
    started = datetime.datetime.now(datetime.timezone.utc)
    reports = pathlib.Path("reports")
    reports.mkdir(exist_ok=True)
    policy_root = pathlib.Path(os.environ.get("VIBESEC_CONFIG", "vibesec.yaml")).resolve().parent
    target_url = os.environ.get("VIBESEC_TARGET_URL")
    token_dir = os.environ.get("VIBESEC_TOKEN_DIR", "")
    tokens = ProbeTokens(
        token_a=_read_token_file(token_dir, "a") if os.environ.get("HAS_A") == "true" else None,
        token_b=_read_token_file(token_dir, "b") if os.environ.get("HAS_B") == "true" else None,
    )
    zap_arg = _load_zap_file(reports / "g5-zap.json") if target_url else None

    outcome, recorded_cov = _execute_probes(
        G5Request(
            target_url=target_url,
            policy_root=policy_root,
            tokens=tokens,
            zap=zap_arg,
            sarif_ref=SARIF_REF,
            started_at=started,
        )
    )
    sarif_path = reports / "g5-api-probes.sarif"
    gate_path = reports / "g5-gate.json"
    if outcome.sarif is None:
        gate_result.remove_stale(sarif_path)
        gate_path.write_text(json.dumps(outcome.gate, ensure_ascii=False, indent=2), encoding="utf-8")
        if not target_url:
            print("G5 api-probes: status=incomplete（VIBESEC_TARGET_URL 未設定）")
        else:
            reason = (outcome.gate.get("status_reason") or "").split("；未送出任何探針", 1)[0]
            print(f"G5 api-probes: status=incomplete（{reason}）")
        return 0

    sarif_path.write_text(json.dumps(outcome.sarif, ensure_ascii=False, indent=2), encoding="utf-8")
    gate_path.write_text(json.dumps(outcome.gate, ensure_ascii=False, indent=2), encoding="utf-8")
    fc = outcome.gate["findings_count"]
    print(f"G5 api-probes: status={outcome.gate['status']} blocking={fc['blocking']} advisory={fc['advisory']}")
    print(json.dumps(recorded_cov, ensure_ascii=False))
    return 0


def selftest() -> list[str]:
    """精簡離線自我測試：純編碼／DER SPKI 驗證、控制清單對齊與 CLI 刪舊 SARIF 煙霧測試（完整真值表見 tests/test_g5_probes.py）。"""
    import io, tempfile
    from vibesec_policy import tree_copy

    fails: list[str] = []
    if b64url(b"\xff\xff") != "__8" or b64url(b"") != "":
        fails.append("b64url 應為無填充 urlsafe base64")
    hs = b64url(json.dumps({"alg": "HS256"}).encode())
    if _token_alg(f"{hs}.x.y") != "HS256" or _token_alg("not-a-jwt") != "":
        fails.append("_token_alg 應回大寫 alg，壞 token 回空字串")
    try:
        n, e = (0xC0DE_1234_5678_90AB_CDEF << 1024) | 0xF00D, 65537
        pem = _spki_pem(n, e)
        if not (pem.startswith(b"-----BEGIN PUBLIC KEY-----\n") and pem.rstrip().endswith(b"-----END PUBLIC KEY-----")):
            fails.append("_spki_pem 應輸出 PEM 封裝的 SubjectPublicKeyInfo")
        der = base64.b64decode(b"".join(pem.split(b"\n")[1:-2]))
        if der[0] != 0x30:
            fails.append("_spki_pem DER 最外層應為 SEQUENCE")

        def tlv(b: bytes, idx: int) -> tuple[int, bytes, int]:
            tag, ln, idx = b[idx], b[idx + 1], idx + 2
            if ln & 0x80:
                width = ln & 0x7F
                ln = int.from_bytes(b[idx : idx + width], "big")
                idx += width
            return tag, b[idx : idx + ln], idx + ln

        _, spki, _ = tlv(der, 0)
        _, _, j = tlv(spki, 0)
        t, bits, _ = tlv(spki, j)
        _, rsapub, _ = tlv(bits[1:], 0)
        tn, nb, nxt = tlv(rsapub, 0)
        te, eb, _ = tlv(rsapub, nxt)
        if (t, tn, te) != (0x03, 0x02, 0x02) or int.from_bytes(nb, "big") != n or int.from_bytes(eb, "big") != e:
            fails.append("_spki_pem 的 DER 解回的 n／e 應與輸入一致")
        if nb[0] != 0x00:
            fails.append("_spki_pem 應為最高位元為 1 的 modulus 補 0x00")
    except Exception as ex:
        fails.append(f"_spki_pem 應可產生合法 DER：{ex}")

    if sorted(EXEC_ORDER) != sorted((*CHECKS, *ZAP_SCANS)) or len(set(EXEC_ORDER)) != len(EXEC_ORDER):
        fails.append(f"EXEC_ORDER 應與 CHECKS＋ZAP_SCANS 是同一組控制（得到 {EXEC_ORDER}）")
    declared = ((yaml.safe_load((DEFAULT_ROOT / "vibesec.yaml").read_text(encoding="utf-8")) or {}).get("gates") or {}).get(
        "g5_dast_api", {}
    ).get("checks")
    if list(CHECKS) != list(declared or []):
        fails.append(f"CHECKS 應與 vibesec.yaml gates.g5_dast_api.checks 相同（得到 {CHECKS}、{declared}）")

    # CLI 薄殼煙霧測試：固定 mode 副本，缺 VIBESEC_TARGET_URL 時刪掉舊 SARIF 並寫出 incomplete g5-gate.json
    cwd0 = os.getcwd()
    env0 = dict(os.environ)
    try:
        with tree_copy("mode: shadow") as pinned_root, tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
            os.chdir(d)
            (pathlib.Path(d) / "reports").mkdir()
            stale = pathlib.Path(d) / "reports/g5-api-probes.sarif"
            stale.write_text('{"stale": true}', encoding="utf-8")
            os.environ.clear()
            os.environ["VIBESEC_CONFIG"] = str(pinned_root / "vibesec.yaml")
            rc = main()
            gate_file = pathlib.Path(d) / "reports/g5-gate.json"
            if rc != 0 or stale.exists() or not gate_file.is_file():
                fails.append(f"CLI 缺目標時應 exit 0、刪舊 SARIF 並寫出 g5-gate.json（rc={rc}, stale={stale.exists()}）")
    finally:
        os.chdir(cwd0)
        os.environ.clear()
        os.environ.update(env0)
    return fails


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        _fails = selftest()
        print("selftest 通過" if not _fails else f"selftest 失敗 {len(_fails)} 項")
        for _f in _fails:
            print("FAIL", _f)
        sys.exit(1 if _fails else 0)
    sys.exit(main())
