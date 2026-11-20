"""G1 快篩薄命令列入口契約測試（scripts/g1_slopcheck.py:main，#266 後半）。

驗證 main 作為唯一有副作用的薄殼：解析旗標、載入政策（讀不到走 Outcome.unreadable）、呼叫 screen、
寫出標準輸出／標準錯誤結果行／SARIF（無 SARIF 檢視時刪除舊檔）／閘門結果，並回傳 Outcome.exit_code。
"""
import contextlib
from datetime import date
import inspect
import io
import json
import pathlib
import re
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import g1_git as gg  # noqa: E402
import g1_registry as gr  # noqa: E402
import g1_screen as gs  # noqa: E402
import g1_slopcheck as sc  # noqa: E402
import gate_result  # noqa: E402
from fakes import FakeGit  # noqa: E402
from gitrepo import TempRepo, isolated_git_environment  # noqa: E402
from vibesec_policy import POLICY_UNREADABLE, Policy, broken_policy_root, set_mode_line, temp_policy_root  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
GATE_SCHEMA = Draft202012Validator(json.loads((ROOT / "schemas/gate-result.schema.json").read_text(encoding="utf-8")))
OLD = "2020-01-01T00:00:00Z"


class ThinCliContract(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.D = pathlib.Path(self._tmp.name).resolve()

    def test_main_accepts_injected_env_directly_and_writes_sarif_gate_stdout_and_stderr(self):
        if "env" not in inspect.signature(sc.main).parameters:
            self.fail("g1_slopcheck.main 尚未收斂為可直接接收 env= 的薄入口")
        (self.D / "package.json").write_text('{"dependencies": {"express": "4.21.2"}}\n', encoding="utf-8")
        reg = gr.FakeRegistry({("npm", "express", "4.21.2"): gr.Found(gr.Facts("npm", "express", "4.21.2", OLD, {}, 50_000))})
        env = gs.build_env(Policy(ROOT, project_root=self.D), git=FakeGit(), registry=reg, today=date(2026, 10, 1))
        gate_p, sarif_p = self.D / "g1-gate.json", self.D / "g1.sarif"
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sc.main(["g1_slopcheck.py", "--target", str(self.D), "--manifest", "package.json",
                            "--gate", str(gate_p), "--sarif", str(sarif_p)], env=env)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue()), {"gate": "G1", "findings": []})
        self.assertEqual(err.getvalue(), "\n✅ G1 快篩通過。\n")
        self.assertTrue(sarif_p.is_file())
        gate_doc = json.loads(gate_p.read_text(encoding="utf-8"))
        self.assertEqual(list(GATE_SCHEMA.iter_errors(gate_doc)), [])
        self.assertEqual(gate_doc["status"], "pass")

    def test_scope_failure_removes_stale_sarif_writes_incomplete_gate_and_prints_no_stdout(self):
        gate_p, sarif_p = self.D / "g1-gate.json", self.D / "g1.sarif"
        sarif_p.write_text('{"stale": true}', encoding="utf-8")
        reg = gr.FakeRegistry()
        env = gs.build_env(Policy(ROOT, project_root=None),
                           git=FakeGit(staged=gg.GitFailure("git 無法執行（FileNotFoundError）")), registry=reg)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sc.main(["g1_slopcheck.py", "--target", str(self.D), "--staged",
                            "--gate", str(gate_p), "--sarif", str(sarif_p)], env=env)
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("--staged 取不到暫存區變更", err.getvalue())
        self.assertFalse(sarif_p.exists(), "範圍失敗未執行掃描時應刪除上一次留下的舊 SARIF")
        gate_doc = json.loads(gate_p.read_text(encoding="utf-8"))
        self.assertEqual((gate_doc["status"], gate_doc["scope"]), ("incomplete", "diff"))
        self.assertIsNone(gate_doc["tools"][0]["output_ref"])
        self.assertEqual(reg.calls, [])

    def test_non_directory_target_removes_stale_sarif_and_writes_incomplete_gate(self):
        gate_p, sarif_p = self.D / "g1-gate.json", self.D / "g1.sarif"
        sarif_p.write_text('{"stale": true}', encoding="utf-8")
        reg = gr.FakeRegistry()
        env = gs.build_env(Policy(ROOT, project_root=None), git=FakeGit(), registry=reg)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sc.main(["g1_slopcheck.py", "--target", str(self.D / "no-such-dir"),
                            "--gate", str(gate_p), "--sarif", str(sarif_p)], env=env)
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("不是目錄", err.getvalue())
        self.assertFalse(sarif_p.exists())
        gate_doc = json.loads(gate_p.read_text(encoding="utf-8"))
        self.assertEqual(gate_doc["status"], "incomplete")
        self.assertIsNone(gate_doc["tools"][0]["output_ref"])
        self.assertEqual(reg.calls, [])

    def _assert_unreadable_gate(self, gate_doc):
        self.assertEqual(list(GATE_SCHEMA.iter_errors(gate_doc)), [])
        self.assertEqual((gate_doc.get("status"), gate_doc.get("mode")), ("incomplete", "enforce"))
        self.assertTrue((gate_doc.get("status_reason") or "").startswith(POLICY_UNREADABLE + "（"), gate_doc.get("status_reason"))
        self.assertEqual(gate_doc.get("findings_count"), {"blocking": 0, "advisory": 0})
        self.assertEqual(gate_doc.get("tools"), [gate_result.tool(gs.TOOL_NAME, "error", version=gs.TOOL_VERSION)])
        cov = [(c["control_id"], c["state"], (c["reason"] or "").startswith(POLICY_UNREADABLE)) for c in gate_doc.get("coverage") or ()]
        self.assertEqual(cov, [
            ("VS-G1-SLOPSQUAT", "untested", True),
            ("VS-G1-COOLDOWN", "untested", True),
            ("VS-G1-INSTALL-HOOK", "untested", True),
            ("VS-G1-SBOM", "pending", False),
            ("ASVS5-V15.2", "pending", False),
        ])

    def test_unreadable_policy_writes_unreadable_gate_removes_stale_sarif_and_never_queries_registry(self):
        (self.D / "package.json").write_text('{"dependencies": {"express": "4.21.2"}}\n', encoding="utf-8")
        reg = gr.FakeRegistry()
        gate_p, sarif_p = self.D / "g1-gate.json", self.D / "g1.sarif"
        sarif_p.write_text('{"stale": true}', encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with broken_policy_root() as pr, contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sc.main(["g1_slopcheck.py", "--target", str(self.D), "--manifest", "package.json",
                            "--gate", str(gate_p), "--sarif", str(sarif_p)], policy_root=pr, registry=reg)
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn(POLICY_UNREADABLE, err.getvalue())
        self.assertFalse(sarif_p.exists())
        self.assertEqual(reg.calls, [])
        gate_doc = json.loads(gate_p.read_text(encoding="utf-8"))
        self._assert_unreadable_gate(gate_doc)
        iso = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00$")
        self.assertRegex(gate_doc.get("started_at") or "", iso)
        self.assertRegex(gate_doc.get("finished_at") or "", iso)

    def test_cli_flags_help_rules_file_changed_files_and_base_are_wired(self):
        for flag in ("--help", "-h"):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = sc.main(["g1_slopcheck.py", flag])
            self.assertEqual(code, 0)
            self.assertIn("用法", out.getvalue())
            self.assertNotIn('"findings"', out.getvalue())

        (self.D / "AGENTS.md").write_text("Run `pip install totally-nonexistent-pkg`.\n", encoding="utf-8")
        (self.D / "package.json").write_text('{"dependencies": {"express": "4.21.2", "axois": "1.0.0"}}\n', encoding="utf-8")
        lst = self.D / "changed.txt"
        lst.write_text("package.json\n", encoding="utf-8")
        reg = gr.FakeRegistry({
            ("pypi", "totally-nonexistent-pkg", None): gr.NotFound(),
            ("npm", "axois", "1.0.0"): gr.Found(gr.Facts("npm", "axois", "1.0.0", OLD, {}, 50_000)),
        })
        git = FakeGit(files={("base123", "package.json"): '{"dependencies": {"express": "4.21.2"}}\n'})
        env = gs.build_env(Policy(ROOT, project_root=self.D), git=git, registry=reg, today=date(2026, 10, 1))
        gate_p = self.D / "g1-gate.json"
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sc.main(["g1_slopcheck.py", "--target", str(self.D), "--rules-file", "AGENTS.md",
                            "--changed-files", str(lst), "--base", "base123", "--gate", str(gate_p)], env=env)
        self.assertEqual(code, 1)
        doc = json.loads(out.getvalue())
        rules = {f["rule_id"] for f in doc["findings"]}
        self.assertIn("vibesec.g1.rules-file-unknown-package", rules)
        self.assertEqual(sorted(reg.calls), [("npm", "axois", "1.0.0"), ("pypi", "totally-nonexistent-pkg", None)],
                         "base 已有的 express 不重查，新增的 axois 與規則檔套件皆被掃描")
        gate_doc = json.loads(gate_p.read_text(encoding="utf-8"))
        self.assertEqual((gate_doc["scope"], gate_doc["diff_base"]), ("diff", "base123"))

    def test_risk_tier_typo_and_mode_matrix_fail_closed_from_cli(self):
        # 搬自快篩主檔 selftest（舊案例 #90–#95）：risk_tier 打錯省略欄位且不拋例外；mode 9 種情境逐一驗證
        isolated_git_environment(self)
        with temp_policy_root() as pr:
            vbp = pr / "vibesec.yaml"
            text, n = re.subn(r"(?m)^risk_tier:.*$", "risk_tier: l3", vbp.read_text(encoding="utf-8"), count=1)
            self.assertEqual(n, 1, "前置檢查：vibesec.yaml 必須有最上層 risk_tier")
            vbp.write_text(text, encoding="utf-8")
            gp = self.D / "tier-gate.json"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = sc.main(["g1_slopcheck.py", "--manifest", str(ROOT / "requirements-ci.in"), "--gate", str(gp)],
                               policy_root=pr)
            g_tier = json.loads(gp.read_text(encoding="utf-8"))
            self.assertEqual((code, g_tier["status"]), (2, "incomplete"))
            self.assertNotIn("risk_tier", g_tier)

        with TempRepo() as repo, temp_policy_root() as pr:
            repo.write("package.json", json.dumps({"dependencies": {"express": "4.21.2"}}))
            repo.commit()
            vbp = pr / "vibesec.yaml"
            real_text = vbp.read_text(encoding="utf-8")

            def with_mode_line(mode_line):
                def apply():
                    vbp.write_text(real_text, encoding="utf-8")
                    set_mode_line(vbp, mode_line)
                return apply

            cases = [
                ("缺席", with_mode_line(""), True),
                ("x", with_mode_line("mode: x"), True),
                ("Enforce", with_mode_line("mode: Enforce"), True),
                ("空字串", with_mode_line('mode: ""'), True),
                ("shadow", with_mode_line("mode: shadow"), False),
                ("enforce", with_mode_line("mode: enforce"), False),
                ("整個檔缺席", lambda: vbp.unlink(missing_ok=True), False),
                ("整個檔語法錯誤", lambda: vbp.write_text("gates: [\n", encoding="utf-8"), False),
                ("整個檔不是 mapping", lambda: vbp.write_text("- a\n", encoding="utf-8"), False),
            ]
            for label, prepare_vibesec, mentions_mode in cases:
                with self.subTest(mode=label):
                    gp, sp = self.D / "mode-gate.json", self.D / "mode.sarif"
                    prepare_vibesec()
                    gp.unlink(missing_ok=True)
                    sp.write_text('{"stale": true}', encoding="utf-8")
                    reg = gr.FakeRegistry({
                        ("npm", "express", "4.21.2"): gr.Found(gr.Facts("npm", "express", "4.21.2", OLD, {}, 10 ** 6)),
                    })
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        code = sc.main(["g1_slopcheck.py", "--target", str(repo.dir), "--gate", str(gp), "--sarif", str(sp)],
                                       policy_root=pr, registry=reg)
                    g = json.loads(gp.read_text(encoding="utf-8"))
                    if label in ("shadow", "enforce"):
                        self.assertEqual((code, g.get("status"), g.get("mode")), (0, "pass", label))
                        self.assertEqual(reg.calls, [("npm", "express", "4.21.2")])
                        continue
                    self.assertEqual(code, 2)
                    self._assert_unreadable_gate(g)
                    if mentions_mode:
                        self.assertIn("mode", g.get("status_reason") or "")
                    self.assertEqual(reg.calls, [])
                    self.assertFalse(sp.exists())


if __name__ == "__main__":
    unittest.main()
