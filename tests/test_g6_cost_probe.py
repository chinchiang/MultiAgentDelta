"""G6 成本探針（scripts/g6_cost_probe.py）遷移至共用授權傳輸測試。 / G6 cost probe tests."""
from __future__ import annotations

import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import g6_cost_probe  # noqa: E402
import target_guard as tg  # noqa: E402
from tests import fakes  # noqa: E402


class G6CostProbeTests(unittest.TestCase):
    BASE = "http://127.0.0.1:8000"

    def test_cost_probe_status_matrix_and_never_stores_echoed_input(self):
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

    def test_rejected_url_off_origin_path_missing_config_and_transport_failure_fail_closed(self):
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

    def test_cli_writes_cost_json_when_url_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "g6-cost.json"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = g6_cost_probe.main(["--target", "http://example.com", "--chars", "10", "--out", str(out)])
            self.assertEqual(rc, 0)
            saved = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(saved["state"], "untested")


if __name__ == "__main__":
    unittest.main()
