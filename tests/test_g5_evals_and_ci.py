from __future__ import annotations

import json
import pathlib
import sys
import unittest
from unittest import mock
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import ci_invariants  # noqa: E402
import g5_api_probes  # noqa: E402
import run_evals  # noqa: E402
from vibesec_policy import broken_policy_root, tree_copy  # noqa: E402
from tests.fakes import FakeTargetTransport  # noqa: E402


class _StubVulnapp:
    def __init__(self, mode: str, url: str) -> None:
        self.mode = mode
        self.url = url

    def ensure(self) -> str | None:
        return None


class G5CiWiringTests(unittest.TestCase):
    def test_staging_blackbox_workflow_runs_trusted_g5_probes_without_override(self) -> None:
        wf_path = ROOT / ".github/workflows/staging-blackbox.yml"
        raw = wf_path.read_text(encoding="utf-8")
        self.assertNotIn("VIBESEC_G5_PROBES", raw)
        wf = yaml.safe_load(raw) or {}
        self.assertEqual(ci_invariants.g5_probes_wiring(wf), [])


class RunEvalsG5MigrationTests(unittest.TestCase):
    def test_run_evals_uses_rule_control_and_drops_duplicate_g5_coverage(self) -> None:
        self.assertFalse(hasattr(run_evals, "G5_COVERAGE"))
        self.assertIs(getattr(run_evals, "RULE_CONTROL", None), g5_api_probes.RULE_CONTROL)

        neg_case = {
            "id": "bola-neg",
            "gate": "G5",
            "expected": {"rule_id": "vibesec.g5.bola-cross-account", "should_flag": False},
        }
        self.assertEqual(run_evals.g5_negative_check(neg_case, set(), None, {"bola_idor": "pass"}), (set(), None))
        hits, err = run_evals.g5_negative_check(neg_case, set(), None, {"bola_idor": "untested"})
        self.assertIsNone(hits)
        self.assertTrue(err)

    def test_vulnapp_runner_g5_logs_in_and_runs_probes_in_process(self) -> None:
        def make_transport(patched: bool) -> FakeTargetTransport:
            def login_handler(req):
                payload = json.loads((req.body or b"{}").decode("utf-8"))
                who = payload.get("username")
                if who == "alice" and payload.get("password") == "alice-pass":
                    return (200, {"access_token": "tok-a"})
                if who == "bob" and payload.get("password") == "bob-pass":
                    return (200, {"token": "tok-b"})
                return (429, {"detail": "rate limited"}) if patched else (401, {"detail": "bad"})

            def users1_handler(req):
                auth = req.headers.get("Authorization", "")
                if auth == "Bearer tok-a":
                    return (200, {"id": 1, "owner": "alice"})
                if auth == "Bearer tok-b":
                    return (403, {"detail": "forbidden"}) if patched else (200, {"id": 1, "owner": "alice"})
                return (401, {})

            return FakeTargetTransport(
                {
                    ("POST", "/login"): login_handler,
                    "/openapi.json": (401, {}) if patched else (200, {"openapi": "3.1.0"}),
                    "/me": lambda req: (200, {"id": 1}) if req.headers.get("Authorization") == "Bearer tok-a" else (401, {}),
                    "/users/1": users1_handler,
                }
            )

        pos_case = {
            "id": "bola-pos",
            "gate": "G5",
            "input": {"target_app": "vulnapp"},
            "expected": {"rule_id": "vibesec.g5.bola-cross-account", "should_flag": True},
        }
        neg_case = {
            "id": "bola-neg",
            "gate": "G5",
            "input": {"target_app": "vulnapp-patched"},
            "expected": {"rule_id": "vibesec.g5.bola-cross-account", "should_flag": False},
        }

        with tree_copy("mode: shadow") as policy_root, mock.patch.object(
            run_evals, "_workflow_step", side_effect=AssertionError("G5 不應再擷取 workflow bash")
        ):
            vuln_tx = make_transport(patched=False)
            vuln_runner = run_evals.VulnappRunner(
                {"vulnapp": _StubVulnapp("", "http://127.0.0.1:8000")},
                transport=vuln_tx,
                policy_root=policy_root,
            )
            hits, err = vuln_runner.run(pos_case)
            self.assertIsNone(err)
            self.assertIn("vibesec.g5.bola-cross-account", hits or set())
            first_two = [json.loads((c.body or b"{}").decode("utf-8")).get("username") for c in vuln_tx.calls[:2]]
            self.assertEqual(first_two, ["alice", "bob"])

            patched_tx = make_transport(patched=True)
            patched_runner = run_evals.VulnappRunner(
                {"vulnapp-patched": _StubVulnapp("patched", "http://127.0.0.1:8000")},
                transport=patched_tx,
                policy_root=policy_root,
            )
            neg_hits, neg_err = patched_runner.run(neg_case)
            self.assertIsNone(neg_err)
            self.assertEqual(neg_hits, set())

            denied_tx = FakeTargetTransport()
            denied_runner = run_evals.VulnappRunner(
                {"vulnapp": _StubVulnapp("", "http://unauthorized.example")},
                transport=denied_tx,
                policy_root=policy_root,
            )
            d_hits, d_err = denied_runner.run(pos_case)
            self.assertIsNone(d_hits)
            self.assertTrue(d_err)
            self.assertEqual(len(denied_tx.calls), 0)

        for label, root_ctx in (("broken_policy", broken_policy_root), ("modeless_policy", lambda: tree_copy(""))):
            with self.subTest(case=label), root_ctx() as bad_root:
                bad_tx = make_transport(patched=False)
                bad_runner = run_evals.VulnappRunner(
                    {"vulnapp": _StubVulnapp("", "http://127.0.0.1:8000")},
                    transport=bad_tx,
                    policy_root=bad_root,
                )
                b_hits, b_err = bad_runner.run(pos_case)
                self.assertIsNone(b_hits)
                self.assertTrue(b_err)

    def test_integration_runner_g5_scenarios_execute_in_process_without_workflow_step(self) -> None:
        case_405 = run_evals.load_yaml(ROOT / "evals/cases/g5/g5-ssrf-incomplete-01.yaml")
        case_off = run_evals.load_yaml(ROOT / "evals/cases/g5/g5-jwksorigin-incomplete-01.yaml")

        with tree_copy("mode: shadow") as policy_root, mock.patch.object(
            run_evals, "_workflow_step", side_effect=AssertionError("G5 整合情境不應再擷取 workflow bash")
        ):
            runner = run_evals.IntegrationRunner(policy_root=policy_root)
            for case in (case_405, case_off):
                self.assertIsNone(runner.handles(case))
                hits, err, gate = runner.run(case)
                self.assertIsNone(err, msg=f"{case['id']} 出現錯誤：{err}")
                ok, detail = run_evals.check_gate(case, hits or set(), gate)
                self.assertTrue(ok, msg=f"{case['id']} 閘門檢查未過：{detail}")


if __name__ == "__main__":
    unittest.main()
