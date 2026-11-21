"""CI 比對工具契約測試（scripts/compare_ci.py）：gh CLI 最低版本檢查（#274）。"""
import contextlib
import io
import json
import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import compare_ci as cc  # noqa: E402


def _minimal_api_responder(args: list[str]) -> str:
    path = next(a for a in args if a.startswith("repos/{owner}/{repo}"))
    if m := re.search(r"/pulls/(\d+)$", path):
        return ("a" * 40 if m[1] == "250" else "b" * 40) + "\n"
    if "/check-runs" in path:
        return "\n".join(
            json.dumps({"name": n, "app": "github-actions", "status": "completed", "conclusion": "success"})
            for n in ("VibeSec Summary", "倉庫驗證（validate.py）", "G1 供應鏈與 Slopsquatting")
        )
    if "/status?" in path:
        return ""
    if m := re.search(r"head_sha=(\w)", path):
        run_id = 1 if m[1] == "a" else 2
        return json.dumps({
            "id": run_id,
            "name": "VibeSec PR Gates",
            "path": ".github/workflows/pr-gates.yml",
            "event": "pull_request",
            "status": "completed",
            "created_at": "2026-11-20T09:00:00Z",
        })
    if m := re.search(r"/runs/(\d+)/jobs", path):
        rid = int(m[1])
        if rid == 9:
            return json.dumps({"id": 9, "name": "G1 全量供應鏈掃描", "status": "completed"})
        base_id = 10 * rid
        return "\n".join(
            json.dumps({"id": base_id + i, "name": n, "status": "completed"})
            for i, n in enumerate(("VibeSec Summary", "倉庫驗證（validate.py）", "G1 供應鏈與 Slopsquatting"), 1)
        )
    if "nightly-full.yml" in path:
        return json.dumps({"id": 9, "created_at": "2026-11-20T02:00:00Z", "status": "completed"})
    if m := re.search(r"/jobs/(\d+)/logs", path):
        jid = int(m[1])
        if jid == 9:
            return "2026-11-20T02:01:00Z 已知漏洞（非 KEV，advisory）：10 筆\n"
        slot = jid % 10
        if slot == 1:
            return (
                "2026-11-20T09:01:00Z | 閘門 | 狀態 | blocking | advisory | 說明 |\n"
                "2026-11-20T09:01:01Z |---|---|---|---|---|\n"
                "2026-11-20T09:01:02Z | G1 | `pass` | 0 | 10 |  |\n"
            )
        if slot == 2:
            return "\n".join(
                f"2026-11-20T09:01:0{i}Z 通過 391 項；警告 0；錯誤 0" for i in range(3)
            )
        if slot == 3:
            return (
                "2026-11-20T09:01:00Z G1 slopcheck：無相依清單或規則檔變更，略過。\n"
                "2026-11-20T09:01:01Z 已知漏洞（非 KEV，advisory）：10 筆\n"
                "2026-11-20T09:01:02Z KEV：檢查 20 筆 grype 結果，命中 0 筆\n"
            )
    raise AssertionError(f"未預期的 gh 呼叫：{args}")


def _gh_stub(version_out: str | Exception, calls: list[list[str]]):
    def gh(args: list[str]) -> str:
        calls.append(list(args))
        if args == ["--version"]:
            if isinstance(version_out, Exception):
                raise version_out
            return version_out
        return _minimal_api_responder(args)

    return gh


class CompareCiGhVersionTests(unittest.TestCase):
    def _run_main(self, argv: list[str], gh) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cc.main(argv, gh=gh)
        return rc, out.getvalue(), err.getvalue()

    def test_parse_gh_version_orders_semver_prerelease_build_metadata_and_rejects_invalid(self):
        if not hasattr(cc, "parse_gh_version"):
            self.fail("compare_ci 尚未定義 parse_gh_version")
        v_104 = cc.parse_gh_version(
            "gh version 2.104.0 (2026-11-12)\nhttps://github.com/cli/cli/releases/tag/v2.104.0\n"
        )
        self.assertEqual((v_104.major, v_104.minor, v_104.patch, v_104.is_release), (2, 104, 0, True))
        v_exact = cc.parse_gh_version("gh version 2.97.0 (2026-07-31)\n")
        v_build = cc.parse_gh_version("gh version 2.97.0+dfsg1 (2026-07-31)\n")
        v_rc = cc.parse_gh_version("gh version 2.97.0-rc1 (2026-07-30)\n")
        self.assertEqual(v_exact, v_build, "SemVer 建置中繼資料（+dfsg1）應與正式版等序")
        self.assertLess(v_rc, v_exact, "SemVer 預發佈版（2.97.0-rc1）應低於正式版 2.97.0")
        self.assertEqual(v_rc.raw, "2.97.0-rc1")

        for invalid in (
            "",
            "2.104.0",
            "gh version unknown",
            "git version 2.47.0",
            "wrapper banner\ngh version 2.104.0 (2026-11-12)\n",
        ):
            with self.subTest(raw=invalid):
                with self.assertRaises(cc.InputError):
                    cc.parse_gh_version(invalid)

    def test_old_prerelease_or_unparseable_gh_exits_2_with_upgrade_message_before_any_api_call(self):
        for label, ver_out, expected_token in (
            ("回報案例 2.62.0", "gh version 2.62.0 (2024-11-14)\n", "2.62.0"),
            ("緊鄰門檻下界 2.96.9", "gh version 2.96.9 (2026-07-02)\n", "2.96.9"),
            ("預發佈版 2.97.0-rc1", "gh version 2.97.0-rc1 (2026-07-30)\n", "2.97.0-rc1"),
            ("主版本過舊 1.99.0", "gh version 1.99.0 (2021-08-01)\n", "1.99.0"),
            ("輸出無法判讀", "gh version custom-dev-build\n", "2.97.0"),
            ("首行非 gh version 之多行輸出", "noise\ngh version 2.104.0 (2026-11-12)\n", "noise"),
        ):
            with self.subTest(case=label):
                calls: list[list[str]] = []
                rc, out, _err = self._run_main(["250", "--baseline", "249"], _gh_stub(ver_out, calls))
                self.assertEqual(rc, 2, f"{label}：out={out!r}")
                self.assertEqual(calls, [["--version"]], f"{label}：只查 --version，不得發出任何 gh api 請求")
                self.assertIn("無法比對：", out)
                self.assertIn(expected_token, out)
                self.assertIn("2.97.0", out)
                self.assertIn("升級", out)

    def test_missing_gh_binary_exits_2_and_bad_cli_args_still_exit_4_without_calling_gh(self):
        calls: list[list[str]] = []
        missing = cc.InputError("無法執行 gh：FileNotFoundError: [Errno 2] No such file or directory: 'gh'")
        rc, out, _err = self._run_main(["250", "--baseline", "249"], _gh_stub(missing, calls))
        self.assertEqual(rc, 2)
        self.assertIn("無法比對：", out)
        self.assertEqual(calls, [["--version"]])

        bad_calls: list[list[str]] = []
        rc_bad, _out, _err = self._run_main(["250"], _gh_stub("gh version 2.104.0\n", bad_calls))
        self.assertEqual(rc_bad, 4)
        self.assertEqual(bad_calls, [], "用法錯誤時不應呼叫 gh")

    def test_minimum_build_metadata_and_newer_gh_versions_check_version_first_and_proceed(self):
        for ver in ("2.97.0", "2.97.0+dfsg1", "2.98.0-rc1", "2.104.0", "3.0.0"):
            with self.subTest(version=ver):
                calls: list[list[str]] = []
                rc, out, _err = self._run_main(
                    ["250", "--baseline", "249"],
                    _gh_stub(f"gh version {ver} (2026-11-12)\n", calls),
                )
                self.assertEqual(rc, 0, out)
                self.assertEqual(calls[0], ["--version"], "啟動時應先檢查 gh --version")
                self.assertGreater(len(calls), 1)
                self.assertIn("## 結論", out)


if __name__ == "__main__":
    unittest.main()
