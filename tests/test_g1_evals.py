"""G1 評測執行器與快篩深模組邊界契約測試（#267，#260 的 S6）。

透過公開接縫驗證：
1. 快篩模組邊界契約：g1_slopcheck 與 g1_screen 不對外匯出內部判定函式與控制對照表，run_evals 不以 importlib 取內部符號。
2. run_evals 的 G1 快篩執行器（G1FixtureRunner、SlopcheckRunner、RulesFileRunner）經 screen(Request, Env) 執行正反例與未完成 fail-closed。
"""
from __future__ import annotations

import importlib.util
import inspect
import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import g1_registry as gr  # noqa: E402
import g1_screen as gs  # noqa: E402
import g1_slopcheck as sc  # noqa: E402
import run_evals  # noqa: E402
from vibesec_policy import broken_policy_root, tree_copy  # noqa: E402

OLD = "2020-01-01T00:00:00Z"


class G1ModuleBoundaryTests(unittest.TestCase):
    def test_screening_internals_are_not_exported_and_incomplete_check_uses_catalog(self) -> None:
        private_syms = ("CONTROL_OF", "cooldown_finding", "install_hook_finding")
        for sym in (*private_syms, "cfg"):
            self.assertFalse(hasattr(sc, sym), f"g1_slopcheck 不應再暴露相容匯出 {sym}")
        self.assertEqual(sc.__all__, ["ROOT", "main", "selftest"])

        self.assertTrue(hasattr(gs, "__all__"), "g1_screen 應明確定義公開介面 __all__")
        for sym in private_syms:
            self.assertFalse(hasattr(gs, sym), f"g1_screen 不應再以公開屬性名稱保留內部符號 {sym}")
        for sym in (*private_syms, "cfg"):
            self.assertNotIn(sym, getattr(gs, "__all__", ()), f"g1_screen.__all__ 不應包含內部符號 {sym}")
        for pub in ("Request", "Env", "Outcome", "build_env", "default_env", "resolve_scope", "screen"):
            self.assertIn(pub, getattr(gs, "__all__", ()))

        inc = {"status": "incomplete", "status_reason": "控制未實測"}
        self.assertIsNone(
            run_evals.slopcheck_incomplete(
                {**inc, "incomplete_checks": [], "untested_controls": ["VS-G1-INSTALL-HOOK"]},
                {"expected": {"rule_id": "vibesec.g1.cooldown-violation"}},
            )
        )
        self.assertIsNotNone(
            run_evals.slopcheck_incomplete(
                {**inc, "incomplete_checks": [], "untested_controls": ["VS-G1-COOLDOWN"]},
                {"expected": {"rule_id": "vibesec.g1.cooldown-violation"}},
            )
        )
        self.assertIsNotNone(
            run_evals.slopcheck_incomplete(
                {"status": "fail", "status_reason": "有阻擋也有逾時", "incomplete_checks": ["npm registry 逾時"]},
                {"expected": {"rule_id": "vibesec.g1.cooldown-violation"}},
            ),
            "即使因其他套件有 blocking 而 status=fail，只要檢查本身有未完成原因就必須回報無法判定",
        )
        unknown_rule = "vibesec.g1." + "no-such-rule"
        for untested in (["VS-G1-INSTALL-HOOK"], []):
            self.assertIsNotNone(
                run_evals.slopcheck_incomplete(
                    {**inc, "incomplete_checks": [], "untested_controls": untested},
                    {"expected": {"rule_id": unknown_rule}},
                ),
                f"目錄中查不到的規則在 status=incomplete（untested={untested}）時必須 fail-closed 回報無法判定",
            )


class RunEvalsG1ScreenTests(unittest.TestCase):
    def test_g1_fixture_runner_executes_cases_through_screen_and_fails_closed(self) -> None:
        if "policy_root" not in inspect.signature(run_evals.G1FixtureRunner.__init__).parameters:
            self.fail("G1FixtureRunner 尚未改為接收 policy_root 並經 screen 執行")

        orig_spec = importlib.util.spec_from_file_location

        def forbid_g1_importlib(name: str, location=None, *args, **kwargs):
            if any(tok in str(name) or tok in str(location or "") for tok in ("g1_slopcheck", "g1_screen")):
                raise AssertionError(f"評測不應再以 importlib 載入快篩模組：{name} ({location})")
            return orig_spec(name, location, *args, **kwargs)

        expected_hits = {
            "g1-cooldown-neg-01": set(),
            "g1-cooldown-pos-01": {"vibesec.g1.cooldown-violation"},
            "g1-postinstall-neg-01": set(),
            "g1-postinstall-pos-01": {"vibesec.g1.postinstall-egress"},
        }
        cases = {cid: run_evals.load_yaml(ROOT / f"evals/cases/g1/{cid}.yaml") for cid in expected_hits}

        with tree_copy("mode: shadow") as policy_root, mock.patch.object(
            importlib.util, "spec_from_file_location", side_effect=forbid_g1_importlib
        ):
            runner = run_evals.G1FixtureRunner(policy_root=policy_root)
            for cid, want in expected_hits.items():
                self.assertIsNone(runner.handles(cases[cid]))
                hits, err = runner.run(cases[cid])
                self.assertIsNone(err, msg=f"{cid} 不應回報錯誤：{err}")
                self.assertEqual(hits, want, msg=f"{cid} 命中規則不符")

            empty_entries_case = {
                "id": "empty-manifest",
                "gate": "G1",
                "input": {"kind": "manifest", "ecosystem": "pypi", "added": ["# comment only"], "published_hours_ago": 2400},
                "expected": {"rule_id": "vibesec.g1.cooldown-violation", "should_flag": False},
            }
            e_hits, e_err = runner.run(empty_entries_case)
            self.assertIsNone(e_hits, "清單未解析出任何套件條目時，反例不得靜默通過為 TN")
            self.assertTrue(e_err)

        pos_hook = cases["g1-postinstall-pos-01"]
        neg_hook = cases["g1-postinstall-neg-01"]
        for label, root_ctx in (("broken_policy", broken_policy_root), ("modeless_policy", lambda: tree_copy(""))):
            with self.subTest(case=label), root_ctx() as bad_root:
                bad_runner = run_evals.G1FixtureRunner(policy_root=bad_root)
                hits, err = bad_runner.run(pos_hook)
                self.assertIsNone(hits)
                self.assertTrue(err)

        with tree_copy("mode: shadow") as missing_cfg_root:
            (missing_cfg_root / "config/slopsquat/cooldown.yaml").unlink()
            cfg_runner = run_evals.G1FixtureRunner(policy_root=missing_cfg_root)
            hits, err = cfg_runner.run(neg_hook)
            self.assertIsNone(hits, "缺 cooldown.yaml 時反例不得靜默通過為 TN")
            self.assertTrue(err)

    def test_slopcheck_and_rules_file_runners_execute_in_process_via_screen(self) -> None:
        for cls in (run_evals.SlopcheckRunner, run_evals.RulesFileRunner):
            params = inspect.signature(cls.__init__).parameters
            if "registry" not in params or "policy_root" not in params:
                self.fail(f"{cls.__name__} 尚未改為接收 registry 與 policy_root 並經同行程 screen 執行")

        slop_cases = {
            cid: run_evals.load_yaml(ROOT / f"evals/cases/g1/{cid}.yaml")
            for cid in (
                "g1-lowdl-neg-01",
                "g1-lowdl-pos-01",
                "g1-slopsquat-neg-01",
                "g1-slopsquat-neg-02",
                "g1-slopsquat-pos-01",
                "g1-slopsquat-pos-02",
            )
        }
        rule_cases = {
            cid: run_evals.load_yaml(ROOT / f"evals/cases/g1/{cid}.yaml")
            for cid in ("g1-rulesfile-neg-01", "g1-rulesfile-pos-01")
        }

        self.assertEqual(
            run_evals.SlopcheckRunner(network=False).handles(slop_cases["g1-lowdl-neg-01"]),
            "--no-network：slopcheck 需要 registry",
        )
        self.assertEqual(
            run_evals.RulesFileRunner(network=False).handles(rule_cases["g1-rulesfile-neg-01"]),
            "--no-network：規則檔掃描需要 registry",
        )

        reg = gr.FakeRegistry({
            ("npm", "express", "4.19.2"): gr.Found(gr.Facts("npm", "express", "4.19.2", OLD, {}, 500_000)),
            ("npm", "ascii-cats", "1.1.1"): gr.Found(gr.Facts("npm", "ascii-cats", "1.1.1", OLD, {}, 5)),
            ("npm", "axios", "1.7.2"): gr.Found(gr.Facts("npm", "axios", "1.7.2", OLD, {}, 500_000)),
            ("pypi", "hpack", "4.0.0"): gr.Found(gr.Facts("pypi", "hpack", "4.0.0", OLD, None, None)),
            ("npm", "axois", "0.0.1-security"): gr.Found(gr.Facts("npm", "axois", "0.0.1-security", OLD, {}, 50)),
            ("pypi", "huggingface-cli", "0.1.0"): gr.NotFound(),
            ("pypi", "requests", None): gr.Found(gr.Facts("pypi", "requests", "2.32.3", OLD, None, None)),
            ("pypi", "fastapi-auth-helperz", None): gr.NotFound(),
        })

        with tree_copy("mode: shadow") as policy_root, mock.patch.object(
            run_evals.subprocess, "run", side_effect=AssertionError("G1 快篩執行器不應啟動子行程")
        ):
            for runner, suite in (
                (run_evals.SlopcheckRunner(network=True, registry=reg, policy_root=policy_root), slop_cases),
                (run_evals.RulesFileRunner(network=True, registry=reg, policy_root=policy_root), rule_cases),
            ):
                for cid, case in suite.items():
                    self.assertIsNone(runner.handles(case))
                    hits, err = runner.run(case)
                    self.assertIsNone(err, msg=f"{cid} 不應回報錯誤：{err}")
                    self.assertEqual(case["expected"]["rule_id"] in (hits or set()), case["expected"]["should_flag"], msg=cid)

            down_reg = gr.FakeRegistry({
                ("npm", "axios", "1.7.2"): gr.Unavailable("HTTP 503"),
                ("pypi", "requests", None): gr.Unavailable("逾時"),
            })
            for down_runner, neg_case in (
                (run_evals.SlopcheckRunner(network=True, registry=down_reg, policy_root=policy_root), slop_cases["g1-slopsquat-neg-01"]),
                (run_evals.RulesFileRunner(network=True, registry=down_reg, policy_root=policy_root), rule_cases["g1-rulesfile-neg-01"]),
            ):
                d_hits, d_err = down_runner.run(neg_case)
                self.assertIsNone(d_hits, f"{down_runner.name} 遇 registry 查詢失敗時反例必須為 incomplete 而非 TN")
                self.assertTrue(d_err)

        with broken_policy_root() as bad_root:
            for runner, case in (
                (run_evals.SlopcheckRunner(network=True, registry=reg, policy_root=bad_root), slop_cases["g1-lowdl-pos-01"]),
                (run_evals.RulesFileRunner(network=True, registry=reg, policy_root=bad_root), rule_cases["g1-rulesfile-pos-01"]),
            ):
                b_hits, b_err = runner.run(case)
                self.assertIsNone(b_hits)
                self.assertTrue(b_err)


if __name__ == "__main__":
    unittest.main()
