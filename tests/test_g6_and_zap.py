"""G6 觀測、G6 成本探針與 ZAP 彙整遷移至共用授權傳輸與來源解析（#290，#287 的 S2）。"""
from __future__ import annotations

import contextlib
import inspect
import io
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import g5_zap  # noqa: E402
import g6_cost_probe  # noqa: E402
import g6_observe  # noqa: E402
import target_guard as tg  # noqa: E402
from vibesec_policy import Policy  # noqa: E402
from tests import fakes  # noqa: E402


class G6ObserveTests(unittest.TestCase):
    BASE = "http://127.0.0.1:8000"

    def _require_transport_seam(self) -> None:
        self.assertIn("transport", inspect.signature(g6_observe.observe).parameters, "g6_observe.observe 應支援注入 transport")

    @staticmethod
    def _chat_handler(mode: str):
        def handle(req: tg.TransportRequest):
            payload = json.loads((req.body or b"{}").decode("utf-8"))
            tools = payload.get("tools") or []
            events = [{"tool": t, "executed": True, "human_approved": False} for t in tools]
            usage = {"input_tokens": 10, "output_tokens": 2, "total_tokens": 12}
            if mode == "redirect":
                return (307, b"", {"Location": "http://127.0.0.1:9999/chat"})
            if mode == "truncated":
                return tg.HttpResponse(status=200, body=b'{"tool_events": [], "reply": "SECRET-REPLY"}', truncated=True)
            body = {
                "vuln": {"reply": "SECRET-REPLY", "tool_events": events, "usage": usage},
                "patched": {"reply": "SECRET-REPLY", "tool_events": [{**e, "executed": False} for e in events], "usage": usage},
                "no_telemetry": {"reply": "SECRET-REPLY"},
            }[mode]
            return (200, body)

        return handle

    def test_load_probes_filters_transform_vars_and_includes_tool_probes(self):
        probes = g6_observe.load_probes()
        self.assertTrue(any(p["tools"] for p in probes))
        self.assertFalse(any(len(p["prompt"]) > 20000 for p in probes))

    def test_observe_states_usage_rollup_and_never_stores_reply_text(self):
        self._require_transport_seam()
        probes = g6_observe.load_probes()
        for mode, want in (
            ("vuln", "fail"),
            ("patched", "pass"),
            ("no_telemetry", "untested"),
            ("redirect", "untested"),
            ("truncated", "untested"),
        ):
            with self.subTest(mode=mode):
                transport = fakes.FakeTargetTransport({("POST", "/chat"): self._chat_handler(mode)})
                res = g6_observe.observe(self.BASE, timeout=10, transport=transport)
                self.assertEqual(res["result"]["state"], want, res["result"])
                self.assertNotIn("SECRET-REPLY", json.dumps(res, ensure_ascii=False))
                self.assertEqual(len(transport.calls), len(probes))
                self.assertEqual(transport.calls[0].headers.get("User-Agent"), "vibesec-g6-observe")
                self.assertEqual(transport.calls[0].headers.get("X-VibeSec-Run"), "g6-observe")

        vuln_transport = fakes.FakeTargetTransport({("POST", "/chat"): self._chat_handler("vuln")})
        vuln_res = g6_observe.observe(self.BASE, timeout=10, transport=vuln_transport)
        self.assertEqual(vuln_res["result"]["usage"]["probes_with_usage"], len(probes))
        self.assertEqual(vuln_res["result"]["usage"]["total_tokens"], 12 * len(probes))

    def test_unlisted_target_off_origin_path_missing_config_and_transport_failure_fail_closed(self):
        self._require_transport_seam()
        transport = fakes.FakeTargetTransport({("POST", "/chat"): self._chat_handler("patched")})

        # 未授權目標：零請求
        denied = g6_observe.observe("http://example.com", timeout=5, transport=transport)
        self.assertEqual(denied["result"]["state"], "untested")
        self.assertTrue(denied["denied"])
        self.assertEqual(transport.calls, [])

        # 基準 URL 含 query：零請求
        query_denied = g6_observe.observe("http://127.0.0.1:8000?env=dev", timeout=5, transport=transport)
        self.assertEqual(query_denied["result"]["state"], "untested")
        self.assertTrue(query_denied["denied"])
        self.assertEqual(transport.calls, [])

        # 非同源路徑混淆（@host、//host、跨埠）：零請求
        for bad_path in ("@example.com/chat", "//example.com/chat", "http://127.0.0.1:8001/chat"):
            with self.subTest(path=bad_path):
                off = g6_observe.observe(self.BASE, path=bad_path, timeout=5, transport=transport)
                self.assertEqual(off["result"]["state"], "untested")
                self.assertIn("非授權來源", off["denied"] or "")
                self.assertEqual(off["probes"], [])
        self.assertEqual(transport.calls, [])

        # 允許清單缺席：零請求
        with tempfile.TemporaryDirectory() as d:
            missing_cfg = g6_observe.observe(self.BASE, timeout=5, root=pathlib.Path(d), transport=transport)
            self.assertEqual(missing_cfg["result"]["state"], "untested")
            self.assertIn("目標允許清單無法讀取", missing_cfg["denied"] or "")
        self.assertEqual(transport.calls, [])

        # 連線失敗（未腳本化路徑回傳 TransportError）：untested
        dead_transport = fakes.FakeTargetTransport()
        conn_fail = g6_observe.observe(self.BASE, timeout=3, transport=dead_transport)
        self.assertEqual(conn_fail["result"]["state"], "untested")
        self.assertTrue(all(p.get("error") for p in conn_fail["probes"]))

    def test_cli_writes_observations_json_on_denied_target(self):
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "g6-obs.json"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = g6_observe.main(["--target", "http://example.com", "--out", str(out)])
            self.assertEqual(rc, 0)
            saved = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(saved["result"]["state"], "untested")
            self.assertTrue(saved["denied"])


class G6CostProbeTests(unittest.TestCase):
    BASE = "http://127.0.0.1:8000"

    def _require_transport_seam(self) -> None:
        self.assertIn("transport", inspect.signature(g6_cost_probe.probe).parameters, "g6_cost_probe.probe 應支援注入 transport")

    def test_cost_probe_status_matrix_and_never_stores_echoed_input(self):
        self._require_transport_seam()
        cases = (
            ("reject_413", (413, b'{"detail":"too long"}'), "pass"),
            ("reject_429", (429, b'{"detail":"rate limit"}'), "pass"),
            ("accept_200", (200, b'{"reply":"AAAAAAAA"}'), "fail"),
            ("truncated_200", tg.HttpResponse(status=200, body=b'{"reply":"AAAAAAAA"', truncated=True), "fail"),
            ("usage_ok", (200, b'{"reply":"ok","usage":{"input_tokens":4000,"output_tokens":100}}'), "pass"),
            ("usage_big", (200, b'{"reply":"ok","usage":{"total_tokens":60000}}'), "fail"),
            ("auth_401", (401, b"{}"), "untested"),
            ("auth_403", (403, b"{}"), "untested"),
            ("redirect_307", (307, b"", {"Location": "http://127.0.0.1:9999/chat"}), "untested"),
            ("error_500", (500, b"{}"), "untested"),
            (
                "pyd_len",
                (
                    422,
                    b'{"detail":[{"type":"string_too_long","loc":["body","message"],'
                    b'"msg":"String should have at most 4000 characters","input":"AAAAAAAA"}]}',
                ),
                "pass",
            ),
            (
                "pyd_missing",
                (
                    422,
                    b'{"detail":[{"type":"missing","loc":["body","prompt"],'
                    b'"msg":"Field required","input":{"message":"AAAAAAAA"}}]}',
                ),
                "untested",
            ),
            ("bad_400", (400, b'{"detail":"invalid session_id"}'), "untested"),
            ("len_400", (400, b'{"error":"message too long"}'), "pass"),
        )
        for name, spec, want in cases:
            with self.subTest(case=name):
                transport = fakes.FakeTargetTransport({("POST", "/chat"): spec})
                res = g6_cost_probe.probe(self.BASE, chars=10000, timeout=10, transport=transport)
                self.assertEqual(res["state"], want, res)
                self.assertNotIn("AAAA", json.dumps(res, ensure_ascii=False))
                self.assertEqual(len(transport.calls), 1)
                self.assertEqual(transport.calls[0].headers.get("User-Agent"), "vibesec-g6-cost-probe")

    def test_unlisted_target_off_origin_path_missing_config_and_transport_failure_fail_closed(self):
        self._require_transport_seam()
        transport = fakes.FakeTargetTransport({("POST", "/chat"): (413, b'{"detail":"too long"}')})

        unlisted = g6_cost_probe.probe("http://example.com", chars=10, timeout=5, transport=transport)
        self.assertEqual(unlisted["state"], "untested")
        self.assertIn("目標未通過授權檢查", unlisted["reason"] or "")
        self.assertEqual(transport.calls, [])

        for bad_path in ("@example.com/chat", "//example.com/chat", "http://127.0.0.1:8001/chat"):
            with self.subTest(path=bad_path):
                off = g6_cost_probe.probe(self.BASE, path=bad_path, chars=10, timeout=5, transport=transport)
                self.assertEqual(off["state"], "untested")
                self.assertIn("非授權來源", off["reason"] or "")
        self.assertEqual(transport.calls, [])

        with tempfile.TemporaryDirectory() as d:
            missing_cfg = g6_cost_probe.probe(self.BASE, chars=10, timeout=5, root=pathlib.Path(d), transport=transport)
            self.assertEqual(missing_cfg["state"], "untested")
            self.assertTrue((missing_cfg["reason"] or "").startswith("目標允許清單無法讀取："))
        self.assertEqual(transport.calls, [])

        dead = g6_cost_probe.probe(self.BASE, chars=10, timeout=3, transport=fakes.FakeTargetTransport())
        self.assertEqual(dead["state"], "untested")
        self.assertIsNotNone(dead["evidence"]["elapsed_ms"])
        self.assertNotIn("AAAA", json.dumps(dead, ensure_ascii=False))

    def test_cli_writes_cost_json_on_denied_target(self):
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "g6-cost.json"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = g6_cost_probe.main(["--target", "http://example.com", "--chars", "10", "--out", str(out)])
            self.assertEqual(rc, 0)
            saved = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(saved["state"], "untested")


class G5ZapOriginTests(unittest.TestCase):
    ROOT = pathlib.Path(__file__).resolve().parents[1]
    TARGET = "http://127.0.0.1:8000"
    CONF = {"40018": "FAIL"}
    IMPL: dict[str, str] = {}
    SQLI = {"pluginid": "40018", "alert": "SQL Injection", "riskcode": "3"}

    def _run_convert(self, tmp_dir: pathlib.Path, site_names: list[str], *, target: str | None = TARGET) -> dict:
        sites = [{"@name": name, "alerts": [self.SQLI]} for name in site_names]
        rep = tmp_dir / "zap-api.json"
        rep.write_text(json.dumps({"@version": "2.16.1", "site": sites}), encoding="utf-8")
        return g5_zap.convert({"api": rep, "baseline": None}, self.CONF, self.IMPL, Policy(self.ROOT), target=target)

    def test_convert_filters_sites_with_shared_parse_origin_and_same_origin(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = pathlib.Path(d)
            for label, names, tgt, want_state, want_hits in (
                ("exact_match", [self.TARGET], self.TARGET, "fail", 1),
                ("case_and_slash", ["HTTP://127.0.0.1:8000/"], self.TARGET, "fail", 1),
                ("default_https_port", ["https://staging.example:443"], "https://staging.example", "fail", 1),
                ("mixed_sites_only_target_counted", [self.TARGET, "https://cdn.example"], self.TARGET, "fail", 1),
                ("different_host", ["http://evil.example"], self.TARGET, "untested", 0),
                ("different_port", ["http://127.0.0.1:9000"], self.TARGET, "untested", 0),
                ("different_scheme", ["https://127.0.0.1:8000"], self.TARGET, "untested", 0),
                ("missing_target", [self.TARGET], None, "untested", 0),
            ):
                with self.subTest(case=label):
                    res = self._run_convert(tmp, names, target=tgt)
                    self.assertEqual(res["coverage"]["zap_api_scan"]["state"], want_state)
                    self.assertEqual(len(res["results"]), want_hits)
                    if label == "missing_target":
                        self.assertIn("沒有可解析的授權目標", res["coverage"]["zap_api_scan"]["reason"] or "")

    def test_credential_backslash_or_port_zero_confusion_is_rejected_by_shared_origin_rules(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = pathlib.Path(d)
            confused_sites = (
                "http://evil.example@127.0.0.1:8000",
                "http://user:pw@127.0.0.1:8000",
                "http://127.0.0.1:8000\\@evil.example",
                "http://127.0.0.1:0",
            )
            for bad_site in confused_sites:
                with self.subTest(site=bad_site):
                    res = self._run_convert(tmp, [bad_site], target=self.TARGET)
                    self.assertEqual(res["coverage"]["zap_api_scan"]["state"], "untested")
                    self.assertEqual(res["results"], [])

            for bad_target in confused_sites:
                with self.subTest(target=bad_target):
                    res = self._run_convert(tmp, [self.TARGET], target=bad_target)
                    self.assertEqual(res["coverage"]["zap_api_scan"]["state"], "untested")
                    self.assertIn("沒有可解析的授權目標", res["coverage"]["zap_api_scan"]["reason"] or "")
                    self.assertEqual(res["results"], [])


if __name__ == "__main__":
    unittest.main()
