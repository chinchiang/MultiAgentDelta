"""G1 評測執行器遷移至 screen 測試（#267，#260 的 S6）。

驗證：
1. 快篩不再對外公開 cooldown_finding、install_hook_finding、CONTROL_OF，且 run_evals 不再以 importlib 載入 g1_slopcheck。
2. G1FixtureRunner 以 FakeRegistry 餵合成 Facts 經由 screen 跑 evals/cases/g1 的案例，政策讀不到時 fail-closed 回報未完成。
3. SlopcheckRunner 與 RulesFileRunner 經 screen 執行（可注入 FakeRegistry 離線實測），registry 無法查詢或規則未登錄時 fail-closed。
"""
from __future__ import annotations

import inspect
import json
import pathlib
import subprocess
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import g1_registry as gr  # noqa: E402
import g1_screen as gs  # noqa: E402
import g1_slopcheck as sc  # noqa: E402
import run_evals  # noqa: E402
from vibesec_policy import broken_policy_root, tree_copy  # noqa: E402

OLD = "2020-01-01T00:00:00Z"


class RunEvalsG1MigrationTests(unittest.TestCase):
    def test_internal_g1_symbols_are_not_exported_and_fixture_runner_drops_importlib(self) -> None:
        for sym in ("cooldown_finding", "install_hook_finding", "CONTROL_OF"):
            self.assertFalse(hasattr(sc, sym), f"g1_slopcheck 不應再對外公開 {sym}")
            self.assertFalse(hasattr(gs, sym), f"g1_screen 不應再對外公開 {sym}")
        runner = run_evals.G1FixtureRunner()
        self.assertFalse(hasattr(runner, "mod"), "G1FixtureRunner 不應再以 importlib 載入 g1_slopcheck 模組")

    def test_g1_fixture_runner_executes_cases_via_screen_and_fails_closed_on_unreadable_policy(self) -> None:
        if "policy_root" not in inspect.signature(run_evals.G1FixtureRunner).parameters:
            self.fail("G1FixtureRunner 尚未支援 policy_root 並改走 screen")
        expected_hits = {
            "g1-cooldown-neg-01": set(),
            "g1-cooldown-pos-01": {"vibesec.g1.cooldown-violation"},
            "g1-postinstall-neg-01": set(),
            "g1-postinstall-pos-01": {"vibesec.g1.postinstall-egress"},
        }
        with tree_copy("mode: shadow") as policy_root:
            runner = run_evals.G1FixtureRunner(policy_root=policy_root)
            for cid, want in expected_hits.items():
                case = run_evals.load_yaml(ROOT / f"evals/cases/g1/{cid}.yaml")
                self.assertIsNone(runner.handles(case), cid)
                hits, err = runner.run(case)
                self.assertIsNone(err, f"{cid} 不應回報未完成：{err}")
                self.assertEqual(hits, want, cid)

            # npm 範圍前綴（^）與 PyPI extras（[socks]）皆與 parse_manifest 對齊，不會因鍵不一致而記 incomplete
            base_cd = run_evals.load_yaml(ROOT / "evals/cases/g1/g1-cooldown-pos-01.yaml")
            for eco, spec, hours, want in (
                ("npm", "@acme/custom-sdk@^1.2.0", 2, {"vibesec.g1.cooldown-violation"}),
                ("pypi", "requests[socks]==2.32.3", 2400, set()),
            ):
                syn = dict(base_cd, input={"kind": "manifest", "ecosystem": eco, "added": [spec], "published_hours_ago": hours})
                self.assertEqual(runner.run(syn), (want, None), spec)

        sample = run_evals.load_yaml(ROOT / "evals/cases/g1/g1-cooldown-pos-01.yaml")
        for label, bad_ctx in (("broken_policy", broken_policy_root), ("modeless_policy", lambda: tree_copy(""))):
            with self.subTest(policy=label), bad_ctx() as bad_root:
                bad_runner = run_evals.G1FixtureRunner(policy_root=bad_root)
                hits, err = bad_runner.run(sample)
                self.assertIsNone(hits)
                self.assertTrue(err)

    def test_slopcheck_and_rules_file_runners_run_via_screen_and_fail_closed_on_unavailable_or_unknown_rule(self) -> None:
        if "registry" not in inspect.signature(run_evals.SlopcheckRunner).parameters:
            self.fail("SlopcheckRunner／RulesFileRunner 尚未改走 screen 並支援注入 registry")
        with tree_copy("mode: shadow") as policy_root:
            # 1) SlopcheckRunner：正常命中與反例、以及 registry Unavailable → incomplete
            lowdl_pos = run_evals.load_yaml(ROOT / "evals/cases/g1/g1-lowdl-pos-01.yaml")
            lowdl_neg = run_evals.load_yaml(ROOT / "evals/cases/g1/g1-lowdl-neg-01.yaml")
            reg_ok = gr.FakeRegistry({
                ("npm", "ascii-cats", "1.1.1"): gr.Found(gr.Facts("npm", "ascii-cats", "1.1.1", OLD, {}, 12)),
                ("npm", "express", "4.19.2"): gr.Found(gr.Facts("npm", "express", "4.19.2", OLD, {}, 500_000)),
            })
            slop_runner = run_evals.SlopcheckRunner(network=True, policy_root=policy_root, registry=reg_ok)
            self.assertEqual(slop_runner.run(lowdl_pos), ({"vibesec.g1.low-download-package"}, None))
            self.assertEqual(slop_runner.run(lowdl_neg), (set(), None))

            slop_unavail = run_evals.SlopcheckRunner(
                network=True, policy_root=policy_root,
                registry=gr.FakeRegistry({
                    ("npm", "ghost-pkg", "1.0.0"): gr.NotFound(),
                    ("npm", "express", "4.19.2"): gr.Unavailable("HTTP 503"),
                }),
            )
            mixed_case = dict(
                lowdl_neg,
                input={"kind": "manifest", "ecosystem": "npm", "added": ["ghost-pkg@1.0.0", "express@4.19.2"]},
            )
            hits_u, err_u = slop_unavail.run(mixed_case)
            self.assertIsNone(hits_u)
            self.assertIn("slopcheck incomplete", err_u or "")

            # 2) RulesFileRunner：查無此套件改名 rules-file-unknown-package；PyPI 已知套件雖 VS-G1-INSTALL-HOOK 未實測仍可判 TN
            rf_pos = run_evals.load_yaml(ROOT / "evals/cases/g1/g1-rulesfile-pos-01.yaml")
            rf_neg = run_evals.load_yaml(ROOT / "evals/cases/g1/g1-rulesfile-neg-01.yaml")
            rf_reg = gr.FakeRegistry({
                ("pypi", "fastapi-auth-helperz", None): gr.NotFound(),
                ("pypi", "requests", None): gr.Found(gr.Facts("pypi", "requests", "2.32.3", OLD, None, None)),
            })
            rf_runner = run_evals.RulesFileRunner(network=True, policy_root=policy_root, registry=rf_reg)
            self.assertEqual(rf_runner.run(rf_pos), ({"vibesec.g1.rules-file-unknown-package"}, None))
            self.assertEqual(rf_runner.run(rf_neg), (set(), None))

            # 範圍失敗（to_stdout() 為 None）時 _G1RunnerEnv.run 一樣 fail-closed 回報未完成
            hits_scope, err_scope = slop_runner.g1.run(
                gs.Request(target="/nonexistent/vibesec-target-dir"),
                lowdl_neg,
            )
            self.assertIsNone(hits_scope)
            self.assertIn("slopcheck incomplete", err_scope or "")

        # 政策檔損毀時 SlopcheckRunner／RulesFileRunner 一樣 fail-closed
        with broken_policy_root() as bad_root:
            for bad_r, sample_c in (
                (run_evals.SlopcheckRunner(network=True, policy_root=bad_root, registry=gr.FakeRegistry()), lowdl_neg),
                (run_evals.RulesFileRunner(network=True, policy_root=bad_root, registry=gr.FakeRegistry()), rf_neg),
            ):
                h, e = bad_r.run(sample_c)
                self.assertIsNone(h)
                self.assertTrue(e)

        # 3) slopcheck_incomplete：不在 cwe-map 目錄的規則、缺 untested_controls 或本規則控制未實測時皆 fail-closed
        unknown_rule = "vibesec.g1." + "unregistered-rule"
        for bad_out, bad_rule in (
            ({"status": "incomplete", "status_reason": "VS-G1-INSTALL-HOOK 未實測",
              "incomplete_checks": [], "untested_controls": ["VS-G1-INSTALL-HOOK"]}, unknown_rule),
            ({"status": "incomplete", "status_reason": "缺欄位", "incomplete_checks": []}, "vibesec.g1.cooldown-violation"),
            ({"status": "incomplete", "status_reason": "VS-G1-INSTALL-HOOK 未實測",
              "incomplete_checks": [], "untested_controls": ["VS-G1-INSTALL-HOOK"]}, "vibesec.g1.postinstall-egress"),
        ):
            self.assertIsNotNone(run_evals.slopcheck_incomplete(bad_out, {"expected": {"rule_id": bad_rule}}))

    def test_integration_g1_registry_timeout_runs_slopcheck_as_subprocess_via_proxy(self) -> None:
        case = run_evals.load_yaml(ROOT / "evals/cases/g1/g1-slopsquat-incomplete-01.yaml")
        runner = run_evals.IntegrationRunner()
        self.assertIsNone(runner.handles(case))
        captured: dict[str, object] = {}

        def fake_subprocess_run(cmd, **kwargs):
            captured["cmd"] = list(cmd)
            captured["env"] = dict(kwargs.get("env") or {})
            gate_idx = cmd.index("--gate") + 1
            pathlib.Path(cmd[gate_idx]).write_text(
                json.dumps({"gate": "G1", "status": "incomplete", "status_reason": "registry timeout"}),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(
                cmd, 2, stdout=json.dumps({"gate": "G1", "status": "incomplete", "findings": []}), stderr=""
            )

        with mock.patch.object(run_evals.subprocess, "run", side_effect=fake_subprocess_run):
            hits, err, gate = runner.run(case)
        self.assertIsNone(err)
        self.assertEqual(hits, set())
        self.assertEqual(gate["status"], "incomplete")
        self.assertEqual(captured["cmd"][1], str(run_evals.SLOPCHECK))
        self.assertTrue(str(captured["env"].get("HTTPS_PROXY", "")).startswith("https://127.0.0.1:"))


if __name__ == "__main__":
    unittest.main()
