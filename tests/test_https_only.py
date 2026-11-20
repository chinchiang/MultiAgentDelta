"""HTTPS 傳輸層（scripts/https_only.py）。 / HTTPS-only transport.

從 g1_slopcheck.py 的 selftest 搬來 http_json 的案例（#263，#260 的 S2）：暫時性錯誤重試後成功、404 不重試、
一直失敗就拋出、經 http:// proxy 重試時每次都是同一種錯誤。另補上重試分類、退避時間、每次嘗試新建 Request、
只接受 HTTPS 與憑證驗證的契約。傳輸層的替身（腳本化的回應）放在這裡，不放生產程式。
"""
import contextlib
import http.client
import json
import os
import pathlib
import socket
import ssl
import sys
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import https_only as ho  # noqa: E402
from fakes import FakeTransport, http_error  # noqa: E402


OK = b'{"ok": 1}'


class GetJson(unittest.TestCase):
    URL = "https://registry.example.invalid/pkg"

    def run_get(self, script, retries=2, backoff=1.0, timeout=8):
        transport, sleeps = FakeTransport(script), []
        try:
            result = ho.get_json(self.URL, timeout=timeout, retries=retries, backoff=backoff, transport=transport, sleep=sleeps.append)
        except Exception as e:  # noqa: BLE001  斷言要看實際丟出的例外
            result = e
        return result, transport, sleeps

    def test_success_is_parsed_with_one_attempt(self):
        result, t, sleeps = self.run_get([OK])
        self.assertEqual(result, {"ok": 1})
        self.assertEqual(len(t.calls), 1)
        self.assertEqual(sleeps, [])

    def test_truncation_and_connection_reset_are_retried(self):
        # 從 g1_slopcheck selftest 搬來：傳輸截斷、連線中斷 → 重試後成功
        result, t, _ = self.run_get([http.client.IncompleteRead(b"x", 5), ConnectionResetError(), OK])
        self.assertEqual(result, {"ok": 1})
        self.assertEqual(len(t.calls), 3)

    def test_404_is_not_retried(self):
        # 從 g1_slopcheck selftest 搬來
        result, t, _ = self.run_get([http_error(404)])
        self.assertIsInstance(result, urllib.error.HTTPError)
        self.assertEqual(result.code, 404)
        self.assertEqual(len(t.calls), 1)

    def test_giving_up_raises_the_last_error(self):
        # 從 g1_slopcheck selftest 搬來：重試用完仍失敗 → 拋出（呼叫端記未完成）
        result, t, _ = self.run_get([TimeoutError()] * 3, retries=2)
        self.assertIsInstance(result, TimeoutError)
        self.assertEqual(len(t.calls), 3)

    def test_http_status_classification(self):
        # 429 與 5xx 是暫時性的；其他 4xx 立即拋出
        for code, retried in ((429, True), (500, True), (502, True), (503, True), (599, True),
                              (400, False), (401, False), (403, False), (404, False), (410, False), (499, False)):
            with self.subTest(code=code):
                result, t, _ = self.run_get([http_error(code), OK])
                if retried:
                    self.assertEqual(result, {"ok": 1})
                    self.assertEqual(len(t.calls), 2)
                else:
                    self.assertIsInstance(result, urllib.error.HTTPError)
                    self.assertEqual(result.code, code)
                    self.assertEqual(len(t.calls), 1)

    def test_transient_http_error_is_raised_as_http_error_when_retries_run_out(self):
        result, t, _ = self.run_get([http_error(503)] * 3)
        self.assertIsInstance(result, urllib.error.HTTPError)
        self.assertEqual(result.code, 503)
        self.assertEqual(len(t.calls), 3)

    def test_url_error_and_os_error_are_retried(self):
        for exc in (urllib.error.URLError("dns"), OSError("boom"), http.client.RemoteDisconnected("bye")):
            with self.subTest(exc=type(exc).__name__):
                result, t, _ = self.run_get([exc, OK])
                self.assertEqual(result, {"ok": 1})
                self.assertEqual(len(t.calls), 2)

    def test_truncated_or_undecodable_body_is_retried(self):
        # 本文被截斷（JSON 不完整）或不是 UTF-8，與連線中斷一樣是暫時性的
        result, t, _ = self.run_get([b'{"ok"', b"\xff\xfe", OK])
        self.assertEqual(result, {"ok": 1})
        self.assertEqual(len(t.calls), 3)

    def test_invalid_utf8_is_never_silently_dropped(self):
        # 完整 JSON 後面夾帶壞位元組也算失敗（重試），不能悄悄丟掉壞位元組後當成功
        result, t, _ = self.run_get([b'{"ok": 1}\xff', OK])
        self.assertEqual(result, {"ok": 1})
        self.assertEqual(len(t.calls), 2)
        result, t, _ = self.run_get([b'{"ok": 1}\xff'] * 3)
        self.assertIsInstance(result, ValueError)
        self.assertEqual(len(t.calls), 3)

    def test_unexpected_exceptions_are_not_swallowed(self):
        # 程式本身的錯誤（不是網路問題）不重試、不吞掉
        result, t, _ = self.run_get([KeyError("bug"), OK])
        self.assertIsInstance(result, KeyError)
        self.assertEqual(len(t.calls), 1)

    def test_backoff_grows_and_does_not_sleep_after_the_last_attempt(self):
        result, t, sleeps = self.run_get([TimeoutError()] * 3, retries=2, backoff=1.5)
        self.assertIsInstance(result, TimeoutError)
        self.assertEqual(sleeps, [1.5, 3.0])

    def test_no_retries(self):
        result, t, sleeps = self.run_get([TimeoutError(), OK], retries=0)
        self.assertIsInstance(result, TimeoutError)
        self.assertEqual((len(t.calls), sleeps), (1, []))

    def test_timeout_and_url_reach_the_transport_on_every_attempt(self):
        _, t, _ = self.run_get([TimeoutError(), TimeoutError(), OK], timeout=3)
        self.assertEqual(t.calls, [(self.URL, 3)] * 3)


class FakeOpener:
    def __init__(self, body=OK):
        self.body, self.reqs, self.timeouts, self.closed = body, [], [], 0

    def open(self, req, timeout=None):
        self.reqs.append(req)
        self.timeouts.append(timeout)
        outer = self

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                outer.closed += 1
                return False

            def read(self):
                return outer.body
        return Resp()


class UrllibAdapter(unittest.TestCase):
    def test_every_attempt_builds_a_new_request(self):
        # 從 g1_slopcheck selftest 搬來：ProxyHandler 會改寫傳入的 Request，重用同一個物件時重試會失敗
        opener = FakeOpener()
        t = ho.UrllibHttpsOnly(user_agent="ua/1", opener_factory=lambda: opener)
        for _ in range(3):
            self.assertEqual(t.get("https://a.invalid/x", 5), OK)
        self.assertEqual(len({id(r) for r in opener.reqs}), 3)
        self.assertEqual(opener.closed, 3, "每次嘗試都要關閉回應")

    def test_user_agent_and_timeout_are_passed_through(self):
        opener = FakeOpener()
        ho.UrllibHttpsOnly(user_agent="vibesec-g1/0.1", opener_factory=lambda: opener).get("https://a.invalid/x", 7)
        self.assertEqual(opener.reqs[0].get_header("User-agent"), "vibesec-g1/0.1")
        self.assertEqual(opener.reqs[0].full_url, "https://a.invalid/x")
        self.assertEqual(opener.timeouts, [7])

    def test_only_https_is_accepted(self):
        # 只裝 HTTPS：http://、file://、ftp:// 一律 URLError，不碰網路也不讀本機檔案
        t = ho.UrllibHttpsOnly(user_agent="ua/1")
        for url in ("http://example.invalid/x", "file:///etc/hostname", "ftp://example.invalid/x"):
            with self.subTest(url=url):
                with self.assertRaises(urllib.error.URLError) as cm:
                    t.get(url, 1)
                # 是「沒有這種協定的處理器」，不是連線或名稱解析失敗（那代表裝了不該裝的處理器）
                self.assertIn("unknown url type", str(cm.exception))

    def test_invalid_url_fails_fast_without_retrying(self):
        # 從 g1_slopcheck.http_json 搬來的行為：Request 建在 try 之外，URL 本身不合法（確定的程式錯誤）立即拋出，
        # 不重試、不睡覺；例外型別仍是 ValueError、訊息不變
        calls, sleeps = [], []

        class Counting:
            def __init__(self):
                self.inner = ho.UrllibHttpsOnly(user_agent="ua/1")

            def get(self, url, timeout):
                calls.append(url)
                return self.inner.get(url, timeout)

        with self.assertRaises(ValueError) as cm:
            ho.get_json("foo", timeout=1, retries=2, backoff=1.0, transport=Counting(), sleep=sleeps.append)
        self.assertIn("unknown url type", str(cm.exception))
        self.assertEqual((len(calls), sleeps), (1, []))

    def test_tls_context_verifies_certificates_and_hostnames(self):
        ctx = ho.tls_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)

    def test_http_proxy_attempts_all_fail_with_the_same_error(self):
        # 從 g1_slopcheck selftest 搬來：真的經過 http:// proxy（本機已關閉的埠 → 連線被拒）。
        # 每次嘗試都必須是同一種錯誤，不能在重試時變成「unknown url type: http」（Request 被 ProxyHandler 改寫後重用的症狀）
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            dead = s.getsockname()[1]
        env = {k: v for k, v in os.environ.items() if k.lower() not in ("https_proxy", "http_proxy", "all_proxy", "no_proxy")}
        env["https_proxy"] = f"http://127.0.0.1:{dead}"
        reasons = []

        class Recording:
            def __init__(self):
                self.inner = ho.UrllibHttpsOnly(user_agent="ua/1")

            def get(self, url, timeout):
                try:
                    return self.inner.get(url, timeout)
                except urllib.error.URLError as e:
                    reasons.append(type(e.reason).__name__)
                    raise

        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(urllib.error.URLError) as cm:
                ho.get_json("https://registry.npmjs.org/left-pad", timeout=2, retries=2, backoff=0, transport=Recording())
        self.assertNotIn("unknown url type", str(cm.exception))
        # 要守的性質是「三次嘗試都是同一種錯誤」；不寫死是哪一種（沒有 loopback 的沙盒裡可能不是 ConnectionRefusedError）
        self.assertEqual(len(reasons), 3, "三次嘗試都真的發出去")
        self.assertEqual(len(set(reasons)), 1, f"每次嘗試的錯誤型別應相同：{reasons}")


if __name__ == "__main__":
    unittest.main()
