"""受測服務授權與同源傳輸層（scripts/target_guard.py）。 / Authorized target transport tests."""
from __future__ import annotations

import gc
import http.server
import os
import pathlib
import socket
import sys
import tempfile
import threading
import time
import unittest
import warnings
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import target_guard as tg  # noqa: E402
from tests import fakes  # noqa: E402


class ParseOriginTests(unittest.TestCase):
    def test_valid_http_and_https_origins_normalize_case_and_default_ports(self):
        self.assertEqual(tg.parse_origin("http://127.0.0.1:8000/api/items?x=1"), ("http", "127.0.0.1", 8000))
        self.assertEqual(tg.parse_origin("HTTP://LOCALHOST/chat"), ("http", "localhost", 80))
        self.assertEqual(tg.parse_origin("https://API.Staging.Example.com/v1"), ("https", "api.staging.example.com", 443))
        self.assertEqual(tg.parse_origin("https://api.staging.example.com:8443/"), ("https", "api.staging.example.com", 8443))
        self.assertEqual(tg.parse_origin("http://[::1]:8000/"), ("http", "::1", 8000))
        # 既有規則保留主機尾點（不做隱式去尾點正規化）
        self.assertEqual(tg.parse_origin("http://127.0.0.1.:8000/"), ("http", "127.0.0.1.", 8000))
        origin = tg.parse_origin("https://api.staging.example.com")
        self.assertIsNotNone(origin)
        self.assertEqual((origin.scheme, origin.host, origin.port), ("https", "api.staging.example.com", 443))

    def test_suspicious_or_non_http_urls_return_none(self):
        invalid = (
            None,
            "",
            "ftp://127.0.0.1:8000/",
            "file:///etc/passwd",
            "//127.0.0.1:8000/x",
            "/relative/path",
            "http://user:pw@127.0.0.1:8000/",
            "http://127.0.0.1:8000@evil.example.com/",
            "http://127.0.0.1:8000 /x",
            "http://127.0.0.1:8000\t/x",
            "http://127.0.0.1:8000\r\n/x",
            "http://127.0.0.1:8000\\@evil.example.com/",
            "http://ｅvil.example.com/",
            "http://127.0.0.1%3a8000/",
            "http://127.0.0.1:0/",
            "https://127.0.0.1:0/",
            "http://127.0.0.1:99999/",
            "http://:8000/",
        )
        for bad in invalid:
            with self.subTest(url=bad):
                self.assertIsNone(tg.parse_origin(bad))


class AuthorizeTargetTests(unittest.TestCase):
    def _write_targets_cfg(self, root: pathlib.Path, content: str) -> None:
        (root / "config").mkdir(parents=True, exist_ok=True)
        (root / "config/targets.yaml").write_text(content, encoding="utf-8")

    def test_authorized_target_cannot_be_instantiated_forged_or_subclassed(self):
        with self.assertRaises(TypeError):
            tg.AuthorizedTarget()
        with self.assertRaises(TypeError):
            tg.AuthorizedTarget(
                object(),
                base_url="http://127.0.0.1:8000",
                origin=tg.Origin("http", "127.0.0.1", 8000),
                transport=None,
                user_agent="ua",
            )
        with self.assertRaises(TypeError):
            type("ForgedTarget", (tg.AuthorizedTarget,), {})
        bypassed = object.__new__(tg.AuthorizedTarget)
        try:
            bypassed.request("/health")
        except TypeError:
            pass
        except Exception as exc:  # noqa: BLE001
            self.fail(f"object.__new__ 繞過建構子時應拋 TypeError，實際拋 {type(exc).__name__}: {exc}")
        else:
            self.fail("object.__new__ 繞過建構子時不得成功發送請求")

    def test_unlisted_query_fragment_port_zero_or_broken_config_returns_target_denied_with_zero_requests(self):
        transport = fakes.FakeTargetTransport({("GET", "http://127.0.0.1:8000/x"): (200, b"ok")})
        rejected_urls = (
            "",
            "https://example.com",
            "http://169.254.169.254/latest/meta-data/",
            "http://user:pw@127.0.0.1:8000",
            "ftp://127.0.0.1:8000",
            "http://127.0.0.1:0",
            "http://127.0.0.1:8000?env=staging",
            "http://127.0.0.1:8000/?",
            "http://127.0.0.1:8000#section",
            "http://127.0.0.1:8000/#",
            "http://127.0.0.1:8000/a b",
            "http://127.0.0.1:8000\\x",
        )
        for bad in rejected_urls:
            with self.subTest(url=bad):
                res = tg.authorize_target(bad, transport=transport)
                self.assertIsInstance(res, tg.TargetDenied)
                self.assertFalse(res.config_problem)
                self.assertTrue(res.reason)
        self.assertEqual(transport.calls, [])

        with tempfile.TemporaryDirectory() as d:
            empty_root = pathlib.Path(d)
            missing = tg.authorize_target("http://127.0.0.1:8000", root=empty_root, transport=transport)
            self.assertIsInstance(missing, tg.TargetDenied)
            self.assertTrue(missing.config_problem)
            self.assertIn("目標允許清單無法讀取", missing.reason)

            self._write_targets_cfg(empty_root, "allowed_hosts: not-a-list\n")
            corrupt = tg.authorize_target("http://127.0.0.1:8000", root=empty_root, transport=transport)
            self.assertIsInstance(corrupt, tg.TargetDenied)
            self.assertTrue(corrupt.config_problem)
            self.assertIn("目標允許清單無法讀取", corrupt.reason)
        self.assertEqual(transport.calls, [])

    def test_allowed_url_mints_authorized_target_preserving_path_prefix_and_origin(self):
        transport = fakes.FakeTargetTransport()
        target = tg.authorize_target("  http://127.0.0.1:8000/v1/  ", transport=transport, user_agent="vibesec-test/1")
        self.assertIsInstance(target, tg.AuthorizedTarget)
        self.assertEqual(target.base_url, "http://127.0.0.1:8000/v1")
        self.assertEqual(target.origin, tg.Origin("http", "127.0.0.1", 8000))
        self.assertEqual(transport.calls, [])


class RequestGateAndFakeTransportTests(unittest.TestCase):
    def test_off_origin_paths_and_urls_return_off_origin_before_bearer_or_transport(self):
        transport = fakes.FakeTargetTransport({("GET", "http://127.0.0.1/me"): (200, {"id": 1})})
        target = tg.authorize_target("http://127.0.0.1", transport=transport)
        self.assertIsInstance(target, tg.AuthorizedTarget)

        off_origin_inputs = (
            "@evil.example.com/me",
            "//evil.example.com/me",
            "http://evil.example.com/me",
            "http://127.0.0.1:8001/me",
            "http://127.0.0.1:0/me",
            "https://127.0.0.1/me",
            "http://127.0.0.1./me",
            "http://localhost/me",
            "http://127.0.0.1@evil.example.com/me",
            "file:///etc/passwd",
            "relative-without-slash",
            "/me with space",
            "/me\\backslash",
            "",
        )
        for bad in off_origin_inputs:
            with self.subTest(path=bad):
                res = target.request(bad, bearer_token="tok-sensitive-a")
                self.assertIsInstance(res, tg.OffOrigin)
                self.assertTrue(res.reason)
                self.assertNotIn("tok-sensitive-a", res.reason)
        self.assertEqual(transport.calls, [], "非同源請求在呼叫底層傳輸前即須攔截，傳輸層收到 0 次呼叫")

    def test_same_origin_request_attaches_bearer_headers_json_and_resolves_prefix(self):
        transport = fakes.FakeTargetTransport(
            {
                ("POST", "http://127.0.0.1:8000/v1/graphql"): (
                    200,
                    {"data": {"ok": True}},
                    {"Content-Type": "application/json", "X-RateLimit-Remaining": "9"},
                ),
                ("GET", "http://127.0.0.1:8000/.well-known/jwks.json"): (200, b'{"keys":[]}'),
                ("GET", "http://127.0.0.1:8000/v1/__vibesec_nonexistent__/%ff"): (404, b"\xffnot-utf8"),
            }
        )
        target = tg.authorize_target("http://127.0.0.1:8000/v1/", transport=transport, user_agent="vibesec-g5/1.0")

        r1 = target.request(
            "/graphql",
            method="POST",
            json_body={"query": "{__typename}"},
            headers={"Origin": "https://probe.invalid"},
            bearer_token="tok-alice",
            timeout=9.0,
        )
        self.assertIsInstance(r1, tg.HttpResponse)
        self.assertEqual(r1.status, 200)
        self.assertFalse(r1.truncated)
        self.assertGreaterEqual(r1.elapsed_ms, 0)
        self.assertEqual(r1.json(), {"data": {"ok": True}})
        self.assertEqual(r1.header("x-ratelimit-remaining"), "9")
        self.assertEqual(r1.headers.get("CONTENT-TYPE"), "application/json")
        self.assertIn("x-ratelimit-remaining", r1.headers)

        sent = transport.calls[0]
        self.assertEqual((sent.method, sent.url, sent.timeout), ("POST", "http://127.0.0.1:8000/v1/graphql", 9.0))
        self.assertEqual(sent.headers["User-Agent"], "vibesec-g5/1.0")
        self.assertEqual(sent.headers["Authorization"], "Bearer tok-alice")
        self.assertEqual(sent.headers["Content-Type"], "application/json")
        self.assertEqual(sent.headers["Origin"], "https://probe.invalid")

        r2 = target.request("HTTP://127.0.0.1:8000/.well-known/jwks.json")
        self.assertIsInstance(r2, tg.HttpResponse)
        self.assertEqual(r2.json(), {"keys": []})
        self.assertNotIn("Authorization", transport.calls[1].headers)

        r3 = target.request("/__vibesec_nonexistent__/%ff")
        self.assertIsInstance(r3, tg.HttpResponse)
        self.assertEqual(r3.status, 404)
        self.assertIn("not-utf8", r3.text)
        self.assertIsNone(r3.json())

    def test_truncated_response_and_unscripted_route_fail_closed(self):
        transport = fakes.FakeTargetTransport(
            {("GET", "http://127.0.0.1:8000/big"): (200, b'{"ok": 1}' + b" " * 100)}
        )
        target = tg.authorize_target("http://127.0.0.1:8000", transport=transport)

        big = target.request("/big", max_bytes=16)
        self.assertIsInstance(big, tg.HttpResponse)
        self.assertEqual(len(big.body), 16)
        self.assertTrue(big.truncated)
        self.assertIsNone(big.json(), "被截斷的回應即使前綴恰為合法 JSON 也必須回傳 None（fail-closed）")

        unscripted = target.request("/not-scripted")
        self.assertIsInstance(unscripted, tg.TransportError)
        self.assertTrue(unscripted.reason)
        self.assertEqual(len(transport.calls), 2)

    def test_mutually_exclusive_body_args_and_invalid_max_bytes_raise_value_error(self):
        target = tg.authorize_target("http://127.0.0.1:8000", transport=fakes.FakeTargetTransport())
        with self.assertRaises(ValueError):
            target.request("/chat", method="POST", body=b"{}", json_body={"a": 1})
        with self.assertRaises(ValueError):
            target.request("/chat", max_bytes=0)


class UrllibLoopbackContractTests(unittest.TestCase):
    def setUp(self):
        self._warnings_cm = warnings.catch_warnings(record=True)
        self._caught_warnings = self._warnings_cm.__enter__()
        warnings.simplefilter("always", ResourceWarning)

        self.canary_hits: list[tuple[str, str | None]] = []
        self.proxy_hits: list[str] = []
        self.post_hits: list[tuple[str, bytes, str | None]] = []
        outer = self

        class CanaryHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                outer.canary_hits.append((self.path, self.headers.get("Authorization")))
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

        class ProxyHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                outer.proxy_hits.append(self.path)
                self.send_response(502)
                self.send_header("Content-Length", "5")
                self.end_headers()
                self.wfile.write(b"proxy")

            def do_CONNECT(self):
                outer.proxy_hits.append(self.path)
                self.send_response(502)
                self.end_headers()

        self.canary = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CanaryHandler)
        self.proxy = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
        canary_port = self.canary.server_address[1]

        redirect_codes = {"/redirect/301": 301, "/redirect/302": 302, "/redirect/307": 307, "/redirect/308": 308}
        status_codes = {"/status/400": 400, "/status/401": 401, "/status/404": 404, "/status/422": 422, "/status/500": 500}
        byte_sizes = {"/bytes/64": 64, "/bytes/100": 100}
        tarpit_codes = {"/tarpit/200": 200, "/tarpit/422": 422}

        class TargetHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _reply(self, code: int, body: bytes, extra_headers: dict[str, str] | None = None):
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for h_name, h_val in (extra_headers or {}).items():
                    self.send_header(h_name, h_val)
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path in redirect_codes:
                    code = redirect_codes[self.path]
                    self._reply(code, b'{"redirect":true}', {"Location": f"http://127.0.0.1:{canary_port}/leaked"})
                    return
                if self.path in status_codes:
                    code = status_codes[self.path]
                    self._reply(code, f'{{"code":{code},"detail":"err-{code}"}}'.encode(), {"X-VibeSec-Probe": f"S-{code}"})
                    return
                if self.path in byte_sizes:
                    size = byte_sizes[self.path]
                    self._reply(200, (b"0123456789abcdef" * ((size // 16) + 1))[:size])
                    return
                if self.path == "/error-bytes/100":
                    self._reply(422, b"E" * 100, {"X-Error-Kind": "Oversize"})
                    return
                if self.path in tarpit_codes:
                    code = tarpit_codes[self.path]
                    self.send_response(code)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", "1000000")
                    self.end_headers()
                    try:
                        self.wfile.write(b"T" * 100)
                        self.wfile.flush()
                        time.sleep(0.5)
                    except OSError:
                        pass
                    return
                self._reply(200, b'{"ok":true}')

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                outer.post_hits.append((self.path, raw, self.headers.get("Authorization")))
                self._reply(200, b'{"posted":true}')

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
        for srv in (self.canary, self.proxy, self.server):
            threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        for srv in (self.server, self.proxy, self.canary):
            srv.shutdown()
            srv.server_close()
        gc.collect()
        resource_warnings = [w for w in self._caught_warnings if issubclass(w.category, ResourceWarning)]
        self._warnings_cm.__exit__(None, None, None)
        self.assertEqual(resource_warnings, [], f"不得遺留未關閉的串流／socket：{resource_warnings}")

    def test_redirects_301_302_307_308_are_not_followed_and_canary_gets_zero_hits(self):
        target = tg.authorize_target(self.base_url)
        self.assertIsInstance(target, tg.AuthorizedTarget)
        for code in (301, 302, 307, 308):
            with self.subTest(code=code):
                resp = target.request(f"/redirect/{code}", bearer_token="tok-do-not-leak")
                self.assertIsInstance(resp, tg.HttpResponse)
                self.assertEqual(resp.status, code)
                self.assertIn(f":{self.canary.server_address[1]}/leaked", resp.header("location") or "")
        self.assertEqual(self.canary_hits, [], "3xx 重新導向目標必須收到 0 次請求，且不得外洩 Authorization")

    def test_environment_proxies_are_ignored_even_without_no_proxy(self):
        proxy_url = f"http://127.0.0.1:{self.proxy.server_address[1]}"
        clean_env = {
            name: val
            for name, val in os.environ.items()
            if name.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
        }
        for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
            clean_env[name] = proxy_url
        with mock.patch.dict(os.environ, clean_env, clear=True):
            target = tg.authorize_target(self.base_url)
            self.assertIsInstance(target, tg.AuthorizedTarget)
            resp = target.request("/ok")
        self.assertIsInstance(resp, tg.HttpResponse)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.json(), {"ok": True})
        self.assertEqual(self.proxy_hits, [], "生產 UrllibTransport 不得採用環境變數代理")

    def test_4xx_5xx_bodies_headers_and_post_payload_roundtrip_without_raising(self):
        target = tg.authorize_target(self.base_url)
        for code in (400, 401, 404, 422, 500):
            with self.subTest(code=code):
                resp = target.request(f"/status/{code}")
                self.assertIsInstance(resp, tg.HttpResponse)
                self.assertEqual(resp.status, code)
                self.assertEqual(resp.json(), {"code": code, "detail": f"err-{code}"})
                self.assertEqual(resp.header("x-vibesec-probe"), f"S-{code}")
                self.assertFalse(resp.truncated)
        post_resp = target.request("/echo", method="POST", json_body={"hello": "world"}, bearer_token="tok-b")
        self.assertIsInstance(post_resp, tg.HttpResponse)
        self.assertEqual(post_resp.json(), {"posted": True})
        self.assertEqual(self.post_hits, [("/echo", b'{"hello": "world"}', "Bearer tok-b")])

    def test_max_bytes_boundary_and_truncation_on_2xx_and_4xx(self):
        target = tg.authorize_target(self.base_url)

        exact = target.request("/bytes/64", max_bytes=64)
        self.assertIsInstance(exact, tg.HttpResponse)
        self.assertEqual(len(exact.body), 64)
        self.assertFalse(exact.truncated)

        over = target.request("/bytes/100", max_bytes=64)
        self.assertIsInstance(over, tg.HttpResponse)
        self.assertEqual(len(over.body), 64)
        self.assertEqual(over.body, (b"0123456789abcdef" * 5)[:64])
        self.assertTrue(over.truncated)
        self.assertIsNone(over.json())

        err_over = target.request("/error-bytes/100", max_bytes=32)
        self.assertIsInstance(err_over, tg.HttpResponse)
        self.assertEqual(err_over.status, 422)
        self.assertEqual(err_over.body, b"E" * 32)
        self.assertTrue(err_over.truncated)
        self.assertEqual(err_over.header("x-error-kind"), "Oversize")

        for code in (200, 422):
            with self.subTest(tarpit_code=code):
                tarpit = target.request(f"/tarpit/{code}", max_bytes=32, timeout=0.2)
                self.assertIsInstance(tarpit, tg.HttpResponse)
                self.assertEqual(tarpit.status, code)
                self.assertEqual(tarpit.body, b"T" * 32)
                self.assertTrue(tarpit.truncated)

    def test_closed_port_protocol_errors_non_http_schemes_and_tls_verification(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            closed_port = sock.getsockname()[1]
        dead_target = tg.authorize_target(f"http://127.0.0.1:{closed_port}")
        self.assertIsInstance(dead_target, tg.AuthorizedTarget)
        dead = dead_target.request("/health", timeout=2.0)
        self.assertIsInstance(dead, tg.TransportError)
        self.assertGreaterEqual(dead.elapsed_ms, 0)
        self.assertTrue(dead.reason)

        # 非 ASCII 路徑或含換行標頭於底層編碼／協定檢查失敗時，必須轉為 TransportError 而非未捕捉崩潰
        live_target = tg.authorize_target(self.base_url)
        for label, call in (
            ("non_ascii_path", lambda: live_target.request("/api/使用者")),
            ("crlf_header", lambda: live_target.request("/ok", headers={"X-Inject": "a\r\nb"})),
            ("non_latin1_bearer", lambda: live_target.request("/ok", bearer_token="憑證")),
        ):
            with self.subTest(case=label):
                try:
                    bad_req = call()
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"{label} 不得拋出未處理例外，實際拋 {type(exc).__name__}: {exc}")
                self.assertIsInstance(bad_req, tg.TransportError)

        # 僅安裝 HTTP／HTTPS 處理器：file://、ftp:// 一律拒絕為 TransportError，不讀本機檔案
        adapter = tg.UrllibTransport()
        for scheme_url in ("file:///etc/hostname", "ftp://example.invalid/x"):
            with self.subTest(url=scheme_url):
                res = adapter.send(
                    tg.TransportRequest(
                        method="GET",
                        url=scheme_url,
                        headers={"User-Agent": "vibesec-test"},
                        body=None,
                        timeout=1.0,
                        max_bytes=1024,
                    )
                )
                self.assertIsInstance(res, tg.TransportError)
                self.assertIn("unknown url type", res.reason)

        # 透過公開介面驗證 HTTPS 與 SSL_CERT_FILE TLS 設定被採用（非 TLS 端點與不存在的 CA 憑證檔皆 fail-closed）
        https_url = f"https://127.0.0.1:{self.server.server_address[1]}"
        https_target = tg.authorize_target(https_url)
        self.assertIsInstance(https_target, tg.AuthorizedTarget)
        tls_fail = https_target.request("/ok", timeout=2.0)
        self.assertIsInstance(tls_fail, tg.TransportError)

        with tempfile.TemporaryDirectory() as d, mock.patch.dict(
            os.environ, {"SSL_CERT_FILE": str(pathlib.Path(d) / "missing-ca.pem")}, clear=False
        ):
            bad_ca_res = https_target.request("/ok", timeout=2.0)
        self.assertIsInstance(bad_ca_res, tg.TransportError)


if __name__ == "__main__":
    unittest.main()
