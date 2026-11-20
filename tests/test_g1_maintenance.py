"""G1 維護狀態檢查遷移至共用 HTTPS 傳輸層測試（#272）。

驗證：
1. g1_maintenance 已移除重複的 _https_only_opener，預設把 UrllibHttpsOnly(user_agent=TOOL_NAME) 與 (30, 2, 1.0) 交給 https_only.get_json（非 HTTPS 與 http:// proxy 行為由 tests/test_https_only.py 把關共用層）。
2. fetch_deps_dev 維持 30 秒逾時、最多嘗試 3 次（retries=2、退避 1.0s／2.0s），正確編碼套件名稱、404 回 None 不重試、其他失敗轉拋 FetchError。
3. run 與 check_run 支援注入腳本化的傳輸層替身（transport），端到端驗證命中與 fail-closed 未完成路徑。
"""
from __future__ import annotations

import datetime
import http.client
import inspect
import io
import json
import pathlib
import sys
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import g1_maintenance as gm  # noqa: E402
import https_only as ho  # noqa: E402
from fakes import FakeTransport, RoutedTransport, http_error  # noqa: E402
from vibesec_policy import temp_policy_root  # noqa: E402


def _ver(v: str, at: str, *, default: bool = False, dep: bool = False, reason: str = "") -> dict:
    return {
        "versionKey": {"version": v},
        "publishedAt": at,
        "isDefault": default,
        "isDeprecated": dep,
        "deprecatedReason": reason,
    }


class G1MaintenanceTransportTests(unittest.TestCase):
    @staticmethod
    def _call_fetch(*args, **kwargs):
        try:
            return gm.fetch_deps_dev(*args, **kwargs)
        except Exception as e:  # noqa: BLE001 — 讓非預期的例外轉為斷言 FAIL 而非 ERROR
            return e

    def test_duplicate_https_opener_is_removed_and_default_wires_https_only(self) -> None:
        self.assertFalse(hasattr(gm, "_https_only_opener"), "g1_maintenance 不應再保留重複的 _https_only_opener")
        if "transport" not in inspect.signature(gm.fetch_deps_dev).parameters:
            self.fail("fetch_deps_dev 尚未支援注入 transport 並改用 https_only")
        captured: dict[str, object] = {}

        def fake_get_json(url, *, timeout, retries, backoff, transport, sleep=None):
            captured.update(url=url, timeout=timeout, retries=retries, backoff=backoff, transport=transport)
            return {"versions": []}

        with mock.patch.object(ho, "get_json", side_effect=fake_get_json):
            self.assertEqual(gm.fetch_deps_dev("pypi", "requests"), {"versions": []})
        self.assertIsInstance(captured["transport"], ho.UrllibHttpsOnly)
        self.assertEqual(captured["transport"].user_agent, gm.TOOL_NAME)
        self.assertEqual((captured["timeout"], captured["retries"], captured["backoff"]), (30, 2, 1.0))

    def test_fetch_deps_dev_preserves_30s_timeout_3_attempts_backoff_and_url_encoding(self) -> None:
        if "transport" not in inspect.signature(gm.fetch_deps_dev).parameters:
            self.fail("fetch_deps_dev 尚未支援注入 transport")
        sleeps: list[float] = []
        tp = FakeTransport([
            http_error(503),
            http.client.IncompleteRead(b"{", 10),
            {"versions": [_ver("1.0.0", "2026-01-01T00:00:00Z", default=True)]},
        ])
        data = gm.fetch_deps_dev("npm", "@acme/pkg", transport=tp, sleep=sleeps.append)
        self.assertEqual(len(data["versions"]), 1)
        self.assertEqual(
            tp.calls,
            [("https://api.deps.dev/v3/systems/npm/packages/%40acme%2Fpkg", 30)] * 3,
        )
        self.assertEqual(sleeps, [1.0, 2.0])

        # 429 一樣重試後成功
        tp_429 = FakeTransport([http_error(429), {"versions": []}])
        self.assertEqual(gm.fetch_deps_dev("maven", "org.x:lib", transport=tp_429, sleep=lambda _: None), {"versions": []})
        self.assertEqual(tp_429.calls[0][0], "https://api.deps.dev/v3/systems/maven/packages/org.x%3Alib")
        self.assertEqual(len(tp_429.calls), 2)

        # 3 次嘗試皆失敗 → 拋出 FetchError（供 run 記為 deps.dev 查詢失敗：FetchError）
        for label, errs in (
            ("503", [http_error(503), http_error(503), http_error(503)]),
            ("timeout", [TimeoutError("slow"), TimeoutError("slow"), TimeoutError("slow")]),
            ("incomplete_read", [http.client.IncompleteRead(b"x", 2)] * 3),
        ):
            with self.subTest(failure=label):
                fail_sleeps: list[float] = []
                tp_fail = FakeTransport([*errs, {"versions": []}])
                with self.assertRaises(gm.FetchError):
                    gm.fetch_deps_dev("pypi", "requests", transport=tp_fail, sleep=fail_sleeps.append)
                self.assertEqual(len(tp_fail.calls), 3)
                self.assertEqual(fail_sleeps, [1.0, 2.0])

    def test_fetch_deps_dev_returns_none_on_404_and_fails_fast_on_other_4xx(self) -> None:
        if "transport" not in inspect.signature(gm.fetch_deps_dev).parameters:
            self.fail("fetch_deps_dev 尚未支援注入 transport")
        sleeps: list[float] = []
        tp_404 = FakeTransport([http_error(404)])
        self.assertIsNone(self._call_fetch("pypi", "no-such-pkg", transport=tp_404, sleep=sleeps.append))
        self.assertEqual((len(tp_404.calls), sleeps), (1, []))

        tp_403 = FakeTransport([http_error(403)])
        with self.assertRaises(gm.FetchError) as cm:
            gm.fetch_deps_dev("pypi", "forbidden-pkg", transport=tp_403, sleep=sleeps.append)
        self.assertIn("HTTP 403", str(cm.exception))
        self.assertEqual((len(tp_403.calls), sleeps), (1, []))

    def test_run_and_check_run_accept_scripted_transport_end_to_end(self) -> None:
        if "transport" not in inspect.signature(gm.check_run).parameters:
            self.fail("check_run／run 尚未支援注入 transport")
        recent = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
        routes_ok = {
            "https://api.deps.dev/v3/systems/pypi/packages/old-pkg": {
                "versions": [_ver("0.9.0", "2019-01-01T00:00:00Z", default=True)]
            },
            "https://api.deps.dev/v3/systems/npm/packages/%40acme%2Fdep": {
                "versions": [
                    _ver("1.0.0", recent, dep=True, reason="replaced"),
                    _ver("2.0.0", recent, default=True),
                ]
            },
            "https://api.deps.dev/v3/systems/pypi/packages/fresh-pkg": {
                "versions": [_ver("1.0.0", recent, default=True)]
            },
        }
        with temp_policy_root() as pr, tempfile.TemporaryDirectory() as d:
            sbom = pathlib.Path(d, "sbom.cdx.json")
            sarif = pathlib.Path(d, "out.sarif")
            out_json = pathlib.Path(d, "out.json")
            sbom.write_text(
                json.dumps({
                    "components": [
                        {"purl": "pkg:pypi/old-pkg@0.9.0"},
                        {"purl": "pkg:npm/%40acme/dep@1.0.0"},
                        {"purl": "pkg:npm/%40acme/dep@1.0.0"},
                        {"purl": "pkg:pypi/fresh-pkg@1.0.0"},
                    ]
                }),
                encoding="utf-8",
            )
            # 1) 直接以 run(..., transport=...) 驗證接縫
            tp_run = RoutedTransport(routes_ok)
            run_summary, run_hits = gm.run(sbom, own=set(), transport=tp_run)
            self.assertEqual(run_summary["status"], "pass")
            self.assertEqual(len(tp_run.calls), 3, "重複 purl 只應查詢傳輸層一次")
            self.assertEqual(sorted(h["name"] for h in run_hits), ["@acme/dep", "old-pkg"])

            # 2) 以 check_run(args, transport=...).execute(...) 驗證完整生命週期（對齊 #246 測試注入慣例）
            args = gm.parse_args(["--sbom", str(sbom), "--sarif", str(sarif), "--json", str(out_json)])
            tp = RoutedTransport(routes_ok)
            with redirect_stdout(io.StringIO()):
                rc = gm.check_run(args, transport=tp).execute(policy_root=pr, sarif_path=args.sarif, json_path=args.json)
            self.assertEqual(rc, 0)
            self.assertEqual(len(tp.calls), 3)
            summary = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(summary["status"], "pass")
            self.assertEqual(len(json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"]), 2)

            # 3) 404 與傳輸失敗 → 退出碼 2（incomplete），刪掉舊 SARIF，且 unresolved 原因維持原字樣
            sbom.write_text(
                json.dumps({"components": [{"purl": "pkg:pypi/ghost@1.0.0"}, {"purl": "pkg:pypi/down@1.0.0"}]}),
                encoding="utf-8",
            )
            tp_bad = RoutedTransport({
                "https://api.deps.dev/v3/systems/pypi/packages/ghost": http_error(404),
                "https://api.deps.dev/v3/systems/pypi/packages/down": urllib.error.URLError("offline"),
            })
            with redirect_stdout(io.StringIO()), mock.patch.object(gm.time, "sleep", lambda _: None):
                rc_bad = gm.check_run(args, transport=tp_bad).execute(
                    policy_root=pr, sarif_path=args.sarif, json_path=args.json
                )
            self.assertEqual(rc_bad, 2)
            self.assertFalse(sarif.exists(), "incomplete 時應刪除舊 SARIF")
            bad_summary = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(bad_summary["status"], "incomplete")
            reasons = {u["purl"]: u["reason"] for u in bad_summary["unresolved"]}
            self.assertEqual(
                reasons,
                {
                    "pkg:pypi/ghost@1.0.0": "deps.dev 查無此套件",
                    "pkg:pypi/down@1.0.0": "deps.dev 查詢失敗：FetchError",
                },
            )


if __name__ == "__main__":
    unittest.main()
