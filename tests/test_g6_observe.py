"""G6 觀測層（scripts/g6_observe.py）遷移至共用授權傳輸測試。 / G6 observation layer tests."""
from __future__ import annotations

import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import g6_observe  # noqa: E402
import target_guard as tg  # noqa: E402
from tests import fakes  # noqa: E402


class G6ObserveTests(unittest.TestCase):
    BASE = "http://127.0.0.1:8000"

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

    def test_rejected_urls_off_origin_paths_missing_config_and_transport_failure_fail_closed(self):
        transport = fakes.FakeTargetTransport({("POST", "/chat"): self._chat_handler("patched")})

        # 未經授權的位址與含 query 的基準位址：零請求
        for rejected_url in ("http://example.com", "http://127.0.0.1:8000?env=dev"):
            with self.subTest(url=rejected_url):
                denied = g6_observe.observe(rejected_url, timeout=5, transport=transport)
                self.assertEqual(denied["result"]["state"], "untested")
                self.assertTrue(denied["denied"])
        self.assertEqual(transport.calls, [])

        # 非同源路徑混淆（含空 probes 清單與缺 tests_path 的前置順序）：零請求且優先回報非授權來源
        for bad_path in ("@example.com/chat", "//example.com/chat", "http://127.0.0.1:8001/chat"):
            with self.subTest(path=bad_path):
                off = g6_observe.observe(self.BASE, path=bad_path, timeout=5, transport=transport)
                self.assertEqual(off["result"]["state"], "untested")
                self.assertIn("非授權來源", off["denied"] or "")
                self.assertEqual(off["probes"], [])

        empty_probes_off = g6_observe.observe(self.BASE, probes=[], path="@example.com/chat", timeout=5, transport=transport)
        self.assertIn("非授權來源", empty_probes_off["denied"] or "")

        missing_tests_off = g6_observe.observe(
            self.BASE,
            path="@example.com/chat",
            timeout=5,
            tests_path=pathlib.Path("/nonexistent/tests.yaml"),
            transport=transport,
        )
        self.assertIn("非授權來源", missing_tests_off["denied"] or "")
        self.assertEqual(transport.calls, [])

        # 目標設定檔（targets.yaml）缺席：零請求
        with tempfile.TemporaryDirectory() as d:
            missing_cfg = g6_observe.observe(self.BASE, timeout=5, root=pathlib.Path(d), transport=transport)
            self.assertEqual(missing_cfg["result"]["state"], "untested")
            self.assertIn("目標允許清單無法讀取", missing_cfg["denied"] or "")
        self.assertEqual(transport.calls, [])

        # 連線失敗：untested
        conn_fail = g6_observe.observe(self.BASE, timeout=3, transport=fakes.FakeTargetTransport())
        self.assertEqual(conn_fail["result"]["state"], "untested")
        self.assertTrue(all(p.get("error") for p in conn_fail["probes"]))

    def test_cli_writes_observations_json_when_url_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "g6-obs.json"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = g6_observe.main(["--target", "http://example.com", "--out", str(out)])
            self.assertEqual(rc, 0)
            saved = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(saved["result"]["state"], "untested")
            self.assertTrue(saved["denied"])


if __name__ == "__main__":
    unittest.main()
