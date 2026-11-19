"""G5 黑箱 API 探針（scripts/g5_api_probes.py）純值介面與 10 項檢查真值表測試。"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
import urllib.parse
from unittest import mock

import yaml
from jsonschema import Draft202012Validator

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import g5_api_probes as g5  # noqa: E402
import gate_result  # noqa: E402
import target_guard as tg  # noqa: E402
from vibesec_policy import POLICY_UNREADABLE, broken_policy_root, tree_copy  # noqa: E402
from tests import fakes  # noqa: E402

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
GATE_SCHEMA = Draft202012Validator(
    json.loads((REPO_ROOT / "schemas/gate-result.schema.json").read_text(encoding="utf-8"))
)
AUTHORIZED_URL = "http://127.0.0.1:8000"

_DEFAULT_PATHS = (
    "/openapi.json",
    "/docs",
    "/redoc",
    "/swagger",
    "/swagger.json",
    "/graphql",
    "/me",
    "/api/me",
    "/profile",
    "/users/me",
    "/account",
    "/users",
    "/admin/users",
    "/",
    "/__vibesec_nonexistent__/%ff",
    "/api/items",
    "/items",
    "/api/orders",
    "/orders",
    "/api/documents",
    "/documents",
    "/fetch",
    "/api/fetch",
    "/import",
    "/api/import",
    "/proxy",
    "/url",
    "/login",
    "/.well-known/openid-configuration",
    "/.well-known/jwks.json",
    "/jwks.json",
)


def _make_jwt(header: dict, payload: dict, sig: str = "sig") -> str:
    h = g5.b64url(json.dumps(header).encode("utf-8"))
    p = g5.b64url(json.dumps(payload).encode("utf-8"))
    return f"{h}.{p}.{sig}"


def _ssrf_fetch_routes(handler) -> dict:
    """為 FakeTargetTransport 展開 /fetch 的 GET query 與 POST 路由鍵。"""
    targets = (
        "http://169.254.169.254/latest/meta-data/",
        f"{AUTHORIZED_URL}/openapi.json",
    )
    routes: dict = {("POST", "/fetch"): handler, "/fetch?vibesec_unrelated=x": handler}
    for param in ("url", "uri", "target", "endpoint"):
        for dest in targets:
            routes[f"/fetch?{urllib.parse.urlencode({param: dest})}"] = handler
    return routes


class PreProbeAndContractTests(unittest.TestCase):
    def test_no_mutable_module_globals_and_rule_control_covers_catalog(self):
        legacy_globals = (
            "URL",
            "TA",
            "TB",
            "HAS_A",
            "HAS_B",
            "POLICY",
            "REPORTS",
            "results",
            "rules",
            "coverage",
            "coverage_reasons",
            "JWKS_SKIPPED",
            "OPENER",
        )
        for name in legacy_globals:
            self.assertFalse(hasattr(g5, name), f"不應殘留模組層可變全域或私有 opener：{name}")
        self.assertNotIn("_recorded_coverage", g5.G5Outcome.__dataclass_fields__, "G5Outcome 不應含私有內部欄位")

        cwe_map = yaml.safe_load((REPO_ROOT / "config/catalogs/cwe-map.yaml").read_text(encoding="utf-8")) or {}
        g5_rules = {rid for rid in (cwe_map.get("rules") or {}) if rid.startswith("vibesec.g5.")}
        self.assertEqual(set(g5.RULE_CONTROL.keys()), g5_rules)
        self.assertEqual(set(g5.RULE_CONTROL.values()), set(g5.CHECKS))

    def test_whitespace_only_probe_tokens_are_normalized_to_absent(self):
        toks = g5.ProbeTokens(token_a="  \n\t ", token_b="")
        self.assertIsNone(toks.token_a)
        self.assertIsNone(toks.token_b)
        self.assertFalse(toks.has_a)
        self.assertFalse(toks.has_b)

        with tree_copy("mode: shadow") as root:
            out = g5.run_probes(
                g5.G5Request(target_url="http://unauthorized.example", policy_root=root, tokens=toks),
                transport=fakes.FakeTargetTransport(),
            )
        self.assertIn("has_a=False, has_b=False", out.gate["status_reason"])

    def test_missing_target_url_and_unreadable_policy_fail_closed_with_zero_requests(self):
        transport = fakes.FakeTargetTransport({("GET", "/openapi.json"): (200, {})})
        declared_order = [*g5.CHECKS, *g5.ZAP_SCANS]

        with tree_copy("mode: shadow") as shadow_tree, tree_copy("") as modeless_tree:
            missing = g5.run_probes(g5.G5Request(target_url=None, policy_root=shadow_tree), transport=transport)
            self.assertIsNone(missing.sarif)
            self.assertEqual(missing.findings, ())
            self.assertEqual(missing.gate["status"], "incomplete")
            self.assertEqual(missing.gate["mode"], "shadow")
            self.assertIn("VIBESEC_TARGET_URL 未設定；未送出任何探針", missing.gate["status_reason"])
            self.assertEqual(
                [(c["control_id"], c["state"]) for c in missing.gate["coverage"]],
                [(k, "untested") for k in declared_order],
            )
            self.assertEqual(
                missing.gate["tools"],
                [gate_result.tool(g5.TOOL_NAME, "missing", version=g5.TOOL_VERSION, exit_code=0, output_ref=g5.SARIF_REF)],
            )
            self.assertEqual(list(GATE_SCHEMA.iter_errors(missing.gate)), [])

            missing_modeless = g5.run_probes(g5.G5Request(target_url="", policy_root=modeless_tree), transport=transport)
            self.assertEqual(missing_modeless.gate["mode"], "enforce")
            self.assertTrue(missing_modeless.gate["status_reason"].startswith("VIBESEC_TARGET_URL 未設定；未送出任何探針"))

            unreadable_mode = g5.run_probes(
                g5.G5Request(target_url=AUTHORIZED_URL, policy_root=modeless_tree),
                transport=transport,
            )
            self.assertIsNone(unreadable_mode.sarif)
            self.assertEqual(unreadable_mode.gate["status"], "incomplete")
            self.assertEqual(unreadable_mode.gate["mode"], "enforce")
            self.assertIn(POLICY_UNREADABLE, unreadable_mode.gate["status_reason"])
            self.assertIn("未送出任何探針", unreadable_mode.gate["status_reason"])
            self.assertEqual([c["control_id"] for c in unreadable_mode.gate["coverage"]], declared_order)
            self.assertEqual(
                unreadable_mode.gate["tools"],
                [gate_result.tool(g5.TOOL_NAME, "error", version=g5.TOOL_VERSION)],
            )

        with broken_policy_root() as broken_root:
            broken = g5.run_probes(g5.G5Request(target_url=AUTHORIZED_URL, policy_root=broken_root), transport=transport)
            self.assertIsNone(broken.sarif)
            self.assertEqual(broken.gate["status"], "incomplete")
            self.assertEqual(broken.gate["findings_count"], {"blocking": 0, "advisory": 0})
            self.assertEqual([c["control_id"] for c in broken.gate["coverage"]], declared_order)
            self.assertTrue(
                all(
                    c["state"] == "untested" and (c["reason"] or "").startswith(POLICY_UNREADABLE + "（")
                    for c in broken.gate["coverage"]
                )
            )
            self.assertEqual(list(GATE_SCHEMA.iter_errors(broken.gate)), [])

        self.assertEqual(transport.calls, [])

    def test_rejected_url_unreachable_target_mode_isolation_and_zap_subresult_merge(self):
        transport = fakes.FakeTargetTransport({("GET", "/openapi.json"): (200, {})})

        with tree_copy("mode: enforce") as enforce_tree, mock.patch.dict(os.environ, {"VIBESEC_MODE": "shadow"}):
            denied = g5.run_probes(
                g5.G5Request(target_url="http://unauthorized.example", policy_root=enforce_tree),
                transport=transport,
            )
        self.assertEqual(denied.gate["mode"], "enforce")
        self.assertEqual(denied.gate["status"], "incomplete")
        self.assertIn("目標未通過授權檢查（config/targets.yaml）", denied.gate["status_reason"])
        self.assertEqual([c["control_id"] for c in denied.gate["coverage"]], list(g5.EXEC_ORDER))
        self.assertIsNotNone(denied.sarif)
        self.assertEqual(transport.calls, [])

        zap_payload = {
            "coverage": {
                "zap_api_scan": {"state": "fail", "reason": None},
                "zap_baseline": {"state": "pass", "reason": None},
            },
            "rules": {
                "zap:40018": {
                    "id": "zap:40018",
                    "name": "zap:40018",
                    "shortDescription": {"text": "SQL Injection"},
                    "defaultConfiguration": {"level": "warning"},
                    "properties": {"policy_tier": "advisory"},
                }
            },
            "results": [
                {
                    "ruleId": "zap:40018",
                    "level": "warning",
                    "message": {"text": "ZAP 40018 SQL Injection"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": ".github/workflows/staging-blackbox.yml"}}}],
                    "properties": {"policy_tier": "advisory", "source": "zap-api-scan"},
                }
            ],
            "tools": [{"name": "zap-api-scan", "state": "ran", "version": "2.16.1", "exit_code": 0}],
        }
        with tree_copy("mode: shadow") as shadow_root:
            dead_transport = fakes.FakeTargetTransport()
            unreachable = g5.run_probes(
                g5.G5Request(target_url=AUTHORIZED_URL, policy_root=shadow_root, zap=zap_payload),
                transport=dead_transport,
            )
            self.assertEqual(len(dead_transport.calls), 1)
            self.assertEqual(unreachable.gate["status"], "incomplete")
            self.assertIn(f"目標 {AUTHORIZED_URL} 無法連線", unreachable.gate["status_reason"])
            self.assertEqual(unreachable.coverage["zap_api_scan"], "fail")
            self.assertEqual(unreachable.coverage["zap_baseline"], "pass")
            self.assertEqual(len(unreachable.findings), 1)
            self.assertEqual(unreachable.findings[0].rule_id, "zap:40018")
            self.assertEqual(unreachable.findings[0].source, "zap-api-scan")
            self.assertEqual([t["name"] for t in unreachable.gate["tools"]], [g5.TOOL_NAME, "zap-api-scan"])
            self.assertEqual(list(GATE_SCHEMA.iter_errors(unreachable.gate)), [])

            # ZAP 子結果缺 policy_tier 或格式損壞時，必須原子性回退並記為 untested（不得硬編預設 advisory 或殘留部分規則）
            for bad_label, bad_zap in (
                (
                    "missing_policy_tier",
                    {
                        **zap_payload,
                        "results": [{"ruleId": "zap:40018", "level": "warning", "message": {"text": "x"}, "properties": {}}],
                    },
                ),
                (
                    "non_dict_result_and_bad_tools",
                    {
                        **zap_payload,
                        "results": ["not-a-dict"],
                        "tools": 123,
                    },
                ),
            ):
                with self.subTest(bad_zap=bad_label):
                    try:
                        bad_out = g5.run_probes(
                            g5.G5Request(target_url="http://unauthorized.example", policy_root=shadow_root, zap=bad_zap),
                            transport=transport,
                        )
                    except Exception as exc:  # noqa: BLE001
                        self.fail(f"損壞的 ZAP 子結果應 fail-closed 轉 untested，實際拋出 {type(exc).__name__}: {exc}")
                    self.assertEqual(bad_out.coverage["zap_api_scan"], "untested")
                    self.assertEqual(bad_out.coverage["zap_baseline"], "untested")
                    self.assertEqual(bad_out.findings, ())
                    self.assertEqual(bad_out.sarif["runs"][0]["results"], [])
                    self.assertEqual(bad_out.sarif["runs"][0]["tool"]["driver"]["rules"], [])

            zap_unavail = g5.run_probes(
                g5.G5Request(target_url="http://unauthorized.example", policy_root=shadow_root, zap=g5.ZapUnavailable("ZAP 缺席")),
                transport=transport,
            )
            self.assertEqual(zap_unavail.control("zap_api_scan")["reason"], "ZAP 缺席")


class _ProbeTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._policy_cm = tree_copy("mode: shadow")
        cls.policy_root = cls._policy_cm.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls._policy_cm.__exit__(None, None, None)

    def _probe(self, overrides=None, *, tokens=g5.ProbeTokens(), policy_root=None):
        routes = {p: (404, {}) for p in _DEFAULT_PATHS}
        if overrides:
            routes.update(overrides)
        transport = fakes.FakeTargetTransport(routes)
        out = g5.run_probes(
            g5.G5Request(
                target_url=AUTHORIZED_URL,
                policy_root=policy_root or self.policy_root,
                tokens=tokens,
            ),
            transport=transport,
        )
        self.assertEqual(list(GATE_SCHEMA.iter_errors(out.gate)), [])
        return out, transport


class SurfaceAndSsrfProbeTests(_ProbeTestBase):
    def test_swagger_exposed_truth_table(self):
        fail_out, _ = self._probe({"/docs": (200, b"<html>Swagger UI</html>")})
        self.assertEqual(fail_out.coverage["swagger_exposed"], "fail")
        self.assertIn("vibesec.g5.swagger-exposed", {f.rule_id for f in fail_out.findings})

        pass_out, _ = self._probe({"/docs": (404, {}), "/openapi.json": (404, {})})
        self.assertEqual(pass_out.coverage["swagger_exposed"], "pass")
        self.assertNotIn("vibesec.g5.swagger-exposed", {f.rule_id for f in pass_out.findings})

        calls = {"openapi": 0}

        def drop_after_ping(req: tg.TransportRequest):
            if req.url.endswith("/openapi.json") and calls["openapi"] == 0:
                calls["openapi"] += 1
                return (404, {})
            return tg.TransportError(url=req.url, reason="請求失敗（ConnectionResetError）")

        untested_out, _ = self._probe(
            {p: drop_after_ping for p in ("/openapi.json", "/docs", "/redoc", "/swagger", "/swagger.json")}
        )
        self.assertEqual(untested_out.coverage["swagger_exposed"], "untested")
        self.assertIn("所有文件路徑的請求都失敗", untested_out.control("swagger_exposed")["reason"])

    def test_graphql_introspection_truth_table(self):
        cases = (
            ("fail_schema", (200, {"data": {"__schema": {"types": []}}}), "fail"),
            ("pass_disabled_400", (400, {"errors": [{"message": "introspection disabled"}]}), "pass"),
            ("pass_data_without_schema", (200, {"data": {"viewer": None}}), "pass"),
            ("na_404", (404, {}), "not_applicable"),
            ("na_405", (405, {}), "not_applicable"),
            ("untested_401", (401, {}), "untested"),
            ("untested_html_200", (200, b"<html></html>", {"Content-Type": "text/html"}), "untested"),
            ("untested_drop", tg.TransportError(url=f"{AUTHORIZED_URL}/graphql", reason="請求失敗（TimeoutError）"), "untested"),
        )
        for label, spec, want in cases:
            with self.subTest(case=label):
                out, _ = self._probe({("POST", "/graphql"): spec})
                self.assertEqual(out.coverage["graphql_introspection"], want)
                if want in ("untested", "not_applicable"):
                    self.assertTrue(out.control("graphql_introspection")["reason"])

    def test_cors_reflect_origin_truth_table_blocking_precedence_and_off_origin_bearer_guard(self):
        reflect_hdrs = {
            "Access-Control-Allow-Origin": "https://vibesec-cors-probe.invalid",
            "Access-Control-Allow-Credentials": "true",
        }
        fail_out, _ = self._probe({"/me": (200, {}, reflect_hdrs)})
        self.assertEqual(fail_out.coverage["cors_reflect_origin"], "fail")
        self.assertEqual(fail_out.gate["status"], "fail")
        self.assertGreaterEqual(fail_out.gate["findings_count"]["blocking"], 1)
        self.assertIn("另有未完成項目", fail_out.gate["status_reason"])

        pass_out, _ = self._probe({"/me": (401, {})})
        self.assertEqual(pass_out.coverage["cors_reflect_origin"], "pass")

        untested_out, _ = self._probe({"/": (404, {})})
        self.assertEqual(untested_out.coverage["cors_reflect_origin"], "untested")
        self.assertTrue(untested_out.control("cors_reflect_origin")["reason"])

        # 當 protected_paths 含非同源路徑且提供 token_a 時，CORS 探針不得對非同源位址送出請求或外洩 Bearer 憑證
        with tree_copy("mode: shadow") as custom_root:
            cfg_path = custom_root / "vibesec.yaml"
            cfg_path.write_text(
                cfg_path.read_text(encoding="utf-8").replace(
                    'protected_paths: ["/me", "/users", "/admin/users"]',
                    'protected_paths: ["http://evil.example/api", "@evil.example/api", "//evil.example/api", "/me"]',
                ),
                encoding="utf-8",
            )
            cors_out, transport = self._probe(
                {"/me": (401, {})},
                tokens=g5.ProbeTokens(token_a="tok-cors-sensitive"),
                policy_root=custom_root,
            )
        self.assertEqual(cors_out.coverage["cors_reflect_origin"], "pass")
        self.assertTrue(all("evil.example" not in c.url for c in transport.calls))

    def test_debug_stacktrace_truth_table_and_openapi_off_origin_interception(self):
        direct_fail, _ = self._probe({"/__vibesec_nonexistent__/%ff": (500, b"Traceback (most recent call last):\n  boom")})
        self.assertEqual(direct_fail.coverage["debug_stacktrace"], "fail")
        self.assertIn("vibesec.g5.debug-stacktrace", {f.rule_id for f in direct_fail.findings})

        openapi_spec = {
            "paths": {
                "http://evil.example/steal": {"post": {}},
                "@evil.example/steal": {"post": {}},
                "//evil.example/steal": {"post": {}},
                "/api/compute": {"post": {}},
            }
        }
        post_fail, transport = self._probe(
            {
                "/openapi.json": (200, openapi_spec),
                "/__vibesec_nonexistent__/%ff": (404, {"detail": "Not Found"}),
                ("POST", "/api/compute"): (500, b'File "/app/main.py", line 10'),
            },
            tokens=g5.ProbeTokens(token_a="tok-a"),
        )
        self.assertEqual(post_fail.coverage["debug_stacktrace"], "fail")
        self.assertTrue(all("evil.example" not in c.url for c in transport.calls))

        pass_out, _ = self._probe({"/__vibesec_nonexistent__/%ff": (404, {"detail": "Not Found"})})
        self.assertEqual(pass_out.coverage["debug_stacktrace"], "pass")

        drop_out, _ = self._probe(
            {
                "/__vibesec_nonexistent__/%ff": tg.TransportError(
                    url=f"{AUTHORIZED_URL}/__vibesec_nonexistent__/%ff",
                    reason="請求失敗（ConnectionResetError）",
                )
            }
        )
        self.assertEqual(drop_out.coverage["debug_stacktrace"], "untested")
        self.assertEqual(drop_out.control("debug_stacktrace")["reason"], "錯誤誘發請求都沒有得到 HTTP 回應")

    def test_ssrf_metadata_and_loopback_canary_truth_table(self):
        def meta_vuln(req: tg.TransportRequest):
            raw = urllib.parse.unquote(req.url) + (req.body or b"").decode("utf-8", "replace")
            if "169.254.169.254" in raw:
                return (200, b"ami-id: ami-12345678")
            return (404, {})

        meta_out, _ = self._probe(_ssrf_fetch_routes(meta_vuln))
        self.assertEqual(meta_out.coverage["ssrf_metadata"], "fail")
        self.assertIn("vibesec.g5.ssrf-metadata", {f.rule_id for f in meta_out.findings})

        def echo_only(req: tg.TransportRequest):
            raw = urllib.parse.unquote(req.url) + (req.body or b"").decode("utf-8", "replace")
            if "169.254.169.254" in raw:
                return (200, {"requested": "http://169.254.169.254/latest/meta-data/"})
            return (404, {})

        echo_out, _ = self._probe(_ssrf_fetch_routes(echo_only))
        self.assertEqual(echo_out.coverage["ssrf_metadata"], "untested")
        self.assertIn("未見 metadata 內容", echo_out.control("ssrf_metadata")["reason"])

        def internal_vuln(req: tg.TransportRequest):
            raw = urllib.parse.unquote(req.url) + (req.body or b"").decode("utf-8", "replace")
            if "127.0.0.1:8000/openapi.json" in raw:
                return (200, b'{"openapi":"3.1.0"}')
            if "url=" in req.url or '"url"' in raw:
                return (403, {"detail": "metadata blocked"})
            return (422, {"detail": "missing url"})

        internal_out, _ = self._probe(_ssrf_fetch_routes(internal_vuln))
        self.assertEqual(internal_out.coverage["ssrf_metadata"], "fail")
        self.assertIn("vibesec.g5.ssrf-internal-fetch", {f.rule_id for f in internal_out.findings})

        blind_400, _ = self._probe(_ssrf_fetch_routes(lambda _req: (400, {"detail": "bad request"})))
        self.assertEqual(blind_400.coverage["ssrf_metadata"], "untested")

        def targeted_block(req: tg.TransportRequest):
            body_txt = (req.body or b"").decode("utf-8", "replace")
            if "url=" in req.url or '"url"' in body_txt:
                return (400, {"detail": "private IP disallowed"})
            return (422, {"detail": "missing url"})

        pass_out, _ = self._probe(_ssrf_fetch_routes(targeted_block))
        self.assertEqual(pass_out.coverage["ssrf_metadata"], "pass")


class AuthBolaSessionRateLimitProbeTests(_ProbeTestBase):
    def test_jwt_alg_none_truth_table(self):
        legit = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "alice"})

        def me_handler(mode: str):
            def handle(req: tg.TransportRequest):
                auth = req.headers.get("Authorization") or ""
                if mode == "no_protected":
                    return (404, {})
                if auth == f"Bearer {legit}":
                    return (200, {"id": "u1"})
                if auth.startswith("Bearer ") and auth.endswith("."):
                    return (200, {"id": "u1"}) if mode == "accepts" else ((500, {}) if mode == "err500" else (401, {}))
                return (401, {})

            return handle

        for mode, want in (("accepts", "fail"), ("rejects", "pass"), ("no_protected", "untested"), ("err500", "untested")):
            with self.subTest(mode=mode):
                out, _ = self._probe({"/me": me_handler(mode)}, tokens=g5.ProbeTokens(token_a=legit))
                self.assertEqual(out.coverage["jwt_alg_none"], want)
                if want == "untested":
                    self.assertTrue(out.control("jwt_alg_none")["reason"])
                if want == "fail":
                    self.assertIn("vibesec.g5.jwt-alg-none", {f.rule_id for f in out.findings})

    def test_jwt_alg_confusion_truth_table_and_oidc_interception(self):
        hs_tok = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "alice"})
        na_out, _ = self._probe(tokens=g5.ProbeTokens(token_a=hs_tok))
        self.assertEqual(na_out.coverage["jwt_alg_confusion"], "not_applicable")
        self.assertIn("HS*", na_out.control("jwt_alg_confusion")["reason"])

        rsa_n = (0xC0DE_1234_5678_90AB << 512) | 0x1111
        rsa_e = 65537
        pem = g5._spki_pem(rsa_n, rsa_e)
        jwk = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "k-rsa",
                    "n": g5.b64url(rsa_n.to_bytes((rsa_n.bit_length() + 7) // 8, "big")),
                    "e": g5.b64url(rsa_e.to_bytes(3, "big")),
                }
            ]
        }
        rs_tok = _make_jwt({"alg": "RS256", "typ": "JWT", "kid": "k-rsa"}, {"sub": "alice"})
        _, p_b64, _ = rs_tok.split(".")
        hs_hdr = g5.b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8"))
        expected_sig = g5.b64url(hmac.new(pem, f"{hs_hdr}.{p_b64}".encode("utf-8"), hashlib.sha256).digest())
        expected_forged = f"{hs_hdr}.{p_b64}.{expected_sig}"

        # 透過同源 OIDC jwks_uri 取得公鑰後，涵蓋 fail、pass 與端點 500／無受保護端點的 untested
        for mode, want in (("accepts", "fail"), ("rejects", "pass"), ("forged_500", "untested"), ("no_protected", "untested")):
            with self.subTest(rsa_mode=mode):
                def me_rsa(req: tg.TransportRequest, cur=mode):
                    if cur == "no_protected":
                        return (404, {})
                    auth = req.headers.get("Authorization") or ""
                    if auth == f"Bearer {rs_tok}":
                        return (200, {"sub": "alice"})
                    if auth == f"Bearer {expected_forged}":
                        return (200, {"sub": "alice"}) if cur == "accepts" else ((500, {}) if cur == "forged_500" else (401, {}))
                    return (401, {})

                out, _ = self._probe(
                    {
                        "/.well-known/openid-configuration": (200, {"jwks_uri": f"{AUTHORIZED_URL}/custom-jwks"}),
                        "/custom-jwks": (200, jwk),
                        "/me": me_rsa,
                    },
                    tokens=g5.ProbeTokens(token_a=rs_tok),
                )
                self.assertEqual(out.coverage["jwt_alg_confusion"], want)
                if want == "untested":
                    self.assertTrue(out.control("jwt_alg_confusion")["reason"])
                if want == "fail":
                    self.assertIn("vibesec.g5.jwt-alg-confusion", {f.rule_id for f in out.findings})

        # OIDC jwks_uri 指向非同源位址：傳輸層收到 0 筆跨來源呼叫，記為 untested 且 note 不列入 findings
        off_oidc, transport = self._probe(
            {"/.well-known/openid-configuration": (200, {"jwks_uri": "http://evil.example/jwks.json"})},
            tokens=g5.ProbeTokens(token_a=rs_tok),
        )
        self.assertEqual(off_oidc.coverage["jwt_alg_confusion"], "untested")
        self.assertIn("非授權來源", off_oidc.control("jwt_alg_confusion")["reason"])
        self.assertTrue(all("evil.example" not in c.url for c in transport.calls))
        self.assertNotIn("vibesec.g5.jwt-alg-confusion", {f.rule_id for f in off_oidc.findings})
        sarif_levels = [
            r["level"] for r in off_oidc.sarif["runs"][0]["results"] if r["ruleId"] == "vibesec.g5.jwt-alg-confusion"
        ]
        self.assertEqual(sarif_levels, ["note"])

    def test_bola_idor_truth_table(self):
        toks = g5.ProbeTokens(token_a="tok-alice", token_b="tok-bob")

        def item_routes(bob_status: int):
            def list_items(req: tg.TransportRequest):
                return (200, [{"id": "ord-7"}]) if req.headers.get("Authorization") == "Bearer tok-alice" else (200, [])

            def get_item(req: tg.TransportRequest):
                auth = req.headers.get("Authorization")
                if auth == "Bearer tok-alice":
                    return (200, {"id": "ord-7", "owner": "alice"})
                if auth == "Bearer tok-bob":
                    return (bob_status, {"id": "ord-7"})
                return (401, {})

            return {"/api/orders": list_items, "/api/orders/ord-7": get_item}

        fail_out, _ = self._probe(item_routes(200), tokens=toks)
        self.assertEqual(fail_out.coverage["bola_idor"], "fail")
        self.assertIn("vibesec.g5.bola-cross-account", {f.rule_id for f in fail_out.findings})

        pass_out, _ = self._probe(item_routes(403), tokens=toks)
        self.assertEqual(pass_out.coverage["bola_idor"], "pass")

        untested_500, _ = self._probe(item_routes(500), tokens=toks)
        self.assertEqual(untested_500.coverage["bola_idor"], "untested")

        single_tok, _ = self._probe(item_routes(200), tokens=g5.ProbeTokens(token_a="tok-alice"))
        self.assertEqual(single_tok.coverage["bola_idor"], "untested")

    def test_session_check_truth_table(self):
        fail_out, _ = self._probe({"/me": (401, {}), "/users": (401, {}), "/admin/users": (200, [])})
        self.assertEqual(fail_out.coverage["session_check"], "fail")
        self.assertIn("vibesec.g5.missing-session-check", {f.rule_id for f in fail_out.findings})

        pass_out, _ = self._probe({"/me": (401, {}), "/users": (403, {}), "/admin/users": (401, {})})
        self.assertEqual(pass_out.coverage["session_check"], "pass")

        untested_404, _ = self._probe({"/me": (401, {}), "/users": (404, {}), "/admin/users": (401, {})})
        self.assertEqual(untested_404.coverage["session_check"], "untested")
        self.assertIn("回應非 401/403", untested_404.control("session_check")["reason"])

        with tree_copy("mode: shadow") as root:
            cfg_path = root / "vibesec.yaml"
            cfg_path.write_text(
                cfg_path.read_text(encoding="utf-8").replace(
                    'protected_paths: ["/me", "/users", "/admin/users"]',
                    "protected_paths: []",
                ),
                encoding="utf-8",
            )
            empty_out, _ = self._probe(policy_root=root)
            self.assertEqual(empty_out.coverage["session_check"], "untested")
            self.assertIn("protected_paths", empty_out.control("session_check")["reason"])

    def test_rate_limit_truth_table(self):
        fail_out, _ = self._probe({("POST", "/login"): (401, {"detail": "bad credentials"})})
        self.assertEqual(fail_out.coverage["rate_limit"], "fail")
        self.assertIn("vibesec.g5.missing-rate-limit", {f.rule_id for f in fail_out.findings})

        counter = {"n": 0}

        def throttled(_req: tg.TransportRequest):
            counter["n"] += 1
            return (429, {"detail": "slow down"}) if counter["n"] > 10 else (401, {"detail": "bad credentials"})

        pass_out, _ = self._probe({("POST", "/login"): throttled})
        self.assertEqual(pass_out.coverage["rate_limit"], "pass")

        no_login, _ = self._probe({("POST", "/login"): (404, {})})
        self.assertEqual(no_login.coverage["rate_limit"], "untested")
        self.assertIn("目標沒有 POST /login", no_login.control("rate_limit")["reason"])

        dropped_login, _ = self._probe(
            {
                ("POST", "/login"): tg.TransportError(
                    url=f"{AUTHORIZED_URL}/login",
                    reason="請求失敗（ConnectionResetError）",
                )
            }
        )
        self.assertEqual(dropped_login.coverage["rate_limit"], "untested")
        self.assertEqual(dropped_login.control("rate_limit")["reason"], "POST /login 的請求全部失敗")

    def test_cli_main_removes_stale_sarif_and_handles_empty_token_files(self):
        cwd0 = os.getcwd()
        env0 = dict(os.environ)
        try:
            with broken_policy_root() as broken_root, tempfile.TemporaryDirectory() as d:
                os.chdir(d)
                (pathlib.Path(d) / "reports").mkdir()
                stale = pathlib.Path(d) / "reports/g5-api-probes.sarif"
                stale.write_text('{"stale": true}', encoding="utf-8")
                os.environ.clear()
                os.environ.update(
                    {
                        "VIBESEC_TARGET_URL": "http://unauthorized.example",
                        "VIBESEC_CONFIG": str(broken_root / "vibesec.yaml"),
                    }
                )
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = g5.main()
                self.assertEqual(rc, 0)
                self.assertFalse(stale.exists())
                gate = json.loads((pathlib.Path(d) / "reports/g5-gate.json").read_text(encoding="utf-8"))
                self.assertEqual(gate["status"], "incomplete")
                self.assertEqual(list(GATE_SCHEMA.iter_errors(gate)), [])

            with tempfile.TemporaryDirectory() as d:
                os.chdir(d)
                (pathlib.Path(d) / "a").write_text("   \n", encoding="utf-8")
                os.environ.clear()
                os.environ.update(
                    {
                        "VIBESEC_TARGET_URL": "http://unauthorized.example",
                        "VIBESEC_CONFIG": str( self.policy_root / "vibesec.yaml"),
                        "VIBESEC_TOKEN_DIR": d,
                        "HAS_A": "true",
                    }
                )
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = g5.main()
                self.assertEqual(rc, 0)
                gate = json.loads((pathlib.Path(d) / "reports/g5-gate.json").read_text(encoding="utf-8"))
                self.assertIn("has_a=False", gate["status_reason"])
        finally:
            os.chdir(cwd0)
            os.environ.clear()
            os.environ.update(env0)


if __name__ == "__main__":
    unittest.main()
