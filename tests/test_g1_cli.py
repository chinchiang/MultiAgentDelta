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
from vibesec_policy import POLICY_UNREADABLE, Policy, broken_policy_root  # noqa: E402

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
        self.assertEqual(reg.calls, [])

    def test_unreadable_policy_writes_unreadable_gate_removes_stale_sarif_and_never_queries_registry(self):
        (self.D / "package.json").write_text('{"dependencies": {"express": "4.21.2"}}\n', encoding="utf-8")
        gate_p, sarif_p = self.D / "g1-gate.json", self.D / "g1.sarif"
        sarif_p.write_text('{"stale": true}', encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with broken_policy_root() as pr, contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sc.main(["g1_slopcheck.py", "--target", str(self.D), "--manifest", "package.json",
                            "--gate", str(gate_p), "--sarif", str(sarif_p)], policy_root=pr)
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn(POLICY_UNREADABLE, err.getvalue())
        self.assertFalse(sarif_p.exists())
        gate_doc = json.loads(gate_p.read_text(encoding="utf-8"))
        self.assertEqual(list(GATE_SCHEMA.iter_errors(gate_doc)), [])
        self.assertEqual(gate_doc["status"], "incomplete")
        self.assertEqual(gate_doc["tools"], [gate_result.tool("vibesec-slopcheck", "error", version="2.0.0")])


if __name__ == "__main__":
    unittest.main()
