"""G5 ZAP 彙整（scripts/g5_zap.py）共用來源解析與同源過濾測試。 / G5 ZAP origin filtering tests."""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import g5_zap  # noqa: E402
from vibesec_policy import Policy  # noqa: E402


class G5ZapOriginTests(unittest.TestCase):
    ROOT = pathlib.Path(__file__).resolve().parents[1]
    AUTHORIZED_URL = "http://127.0.0.1:8000"
    CONF = {"40018": "FAIL"}
    IMPL: dict[str, str] = {}
    SQLI = {"pluginid": "40018", "alert": "SQL Injection", "riskcode": "3"}

    def _run_convert(self, tmp_dir: pathlib.Path, site_names: list[str], *, target_arg: str | None = AUTHORIZED_URL) -> dict:
        sites = [{"@name": name, "alerts": [self.SQLI]} for name in site_names]
        rep = tmp_dir / "zap-api.json"
        rep.write_text(json.dumps({"@version": "2.16.1", "site": sites}), encoding="utf-8")
        return g5_zap.convert({"api": rep, "baseline": None}, self.CONF, self.IMPL, Policy(self.ROOT), target=target_arg)

    def test_confused_or_malformed_origins_are_rejected_by_shared_parse_origin_and_same_origin(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = pathlib.Path(d)
            confused_urls = (
                "http://evil.example@127.0.0.1:8000",
                "http://user:pw@127.0.0.1:8000",
                "http://127.0.0.1:8000\\@evil.example",
                "http://127.0.0.1%3a8000",
                "http://ｅvil.example",
                "http://127.0.0.1:0",
            )
            for bad_site in confused_urls:
                with self.subTest(site=bad_site):
                    res = self._run_convert(tmp, [bad_site], target_arg=self.AUTHORIZED_URL)
                    self.assertEqual(res["coverage"]["zap_api_scan"]["state"], "untested")
                    self.assertEqual(res["results"], [])

            for rejected_url in (None, *confused_urls):
                with self.subTest(target_arg=rejected_url):
                    res = self._run_convert(tmp, [self.AUTHORIZED_URL], target_arg=rejected_url)
                    self.assertEqual(res["coverage"]["zap_api_scan"]["state"], "untested")
                    self.assertIn("沒有可解析的授權目標", res["coverage"]["zap_api_scan"]["reason"] or "")
                    self.assertEqual(res["results"], [])


if __name__ == "__main__":
    unittest.main()
