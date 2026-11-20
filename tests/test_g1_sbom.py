"""G1 SBOM 核對（scripts/g1_sbom.py）：requirements 的 -r 包含邊界契約（#270）。"""
import contextlib
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import g1_sbom  # noqa: E402
from gitrepo import TempRepo, isolated_git_environment  # noqa: E402
from vibesec_policy import Policy, temp_policy_root  # noqa: E402


def _bom(*purls: str) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [{"type": "library", "name": p, "version": "x", "purl": p} for p in purls],
    }


def _fake_syft(doc: dict):
    return lambda tree, out, binary: json.loads(json.dumps(doc))


def _write_syft_script(path: pathlib.Path, doc: dict) -> pathlib.Path:
    payload = json.dumps(doc)
    path.write_text(
        "#!/bin/sh\n"
        'for a; do case $a in cyclonedx-json=*) printf \'%s\' \'' + payload + '\' > "${a#cyclonedx-json=}";; esac; done\n',
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def _base_gate() -> dict:
    return {
        "gate": "G1",
        "status": "pass",
        "status_reason": None,
        "mode": "shadow",
        "risk_tier": "L3",
        "scope": "full",
        "diff_base": None,
        "commit": None,
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:00Z",
        "tools": [],
        "findings_count": {"blocking": 0, "advisory": 0},
        "coverage": [{"control_id": g1_sbom.CONTROL, "state": "pending", "reason": None}],
    }


class SbomIncludeBoundaryTests(unittest.TestCase):
    def setUp(self):
        isolated_git_environment(self)

    def _run_main(self, repo_dir: pathlib.Path, work_dir: pathlib.Path, policy_root: pathlib.Path, sbom_doc: dict):
        syft = _write_syft_script(work_dir / "syft", sbom_doc)
        json_path = work_dir / "out.json"
        sarif_path = work_dir / "out.sarif"
        gate_path = work_dir / "G1.json"
        gate_path.write_text(json.dumps(_base_gate()), encoding="utf-8")
        env = {"VIBESEC_SYFT": str(syft), "TMPDIR": str(work_dir)}
        with mock.patch.dict(os.environ, env), mock.patch("tempfile.tempdir", str(work_dir)), \
                contextlib.redirect_stdout(io.StringIO()):
            rc = g1_sbom.main(
                [
                    "--target", str(repo_dir),
                    "--sbom", str(work_dir / "s.cdx.json"),
                    "--sarif", str(sarif_path),
                    "--json", str(json_path),
                    "--merge-gate", str(gate_path),
                ],
                policy_root=policy_root,
            )
        summary = json.loads(json_path.read_text(encoding="utf-8"))
        gate = json.loads(gate_path.read_text(encoding="utf-8"))
        return rc, summary, gate, sarif_path

    def test_same_directory_include_passes_when_all_pinned_packages_are_in_sbom(self):
        with TempRepo() as r, tempfile.TemporaryDirectory() as out_dir:
            r.write("requirements/sibling.in", "pytest==8.0.0\n")
            r.write("requirements/dev.txt", "requests==2.31.0\n-r sibling.in\n")
            r.commit()
            sbom = _bom("pkg:pypi/requests@2.31.0", "pkg:pypi/pytest@8.0.0")
            summary = g1_sbom.run(r.dir, "HEAD", pathlib.Path(out_dir, "sbom.cdx.json"), _fake_syft(sbom))
            self.assertEqual(summary["status"], "pass", summary)
            self.assertIsNone(summary["status_reason"])
            self.assertEqual(summary["lockfiles"]["requirements/dev.txt"], {"pinned": 2, "missing": []})

    def test_upward_include_within_project_root_with_complete_sbom(self):
        # #270：邊界改為專案根目錄（匯出的樹）後，子目錄 requirements 往上 -r ../base.in 可解析且齊全 → pass
        with TempRepo() as r, tempfile.TemporaryDirectory() as out_dir:
            r.write("base.in", "pytest==8.0.0\n")
            r.write("requirements/dev.txt", "requests==2.31.0\n-r ../base.in\n")
            r.commit()
            sbom = _bom("pkg:pypi/requests@2.31.0", "pkg:pypi/pytest@8.0.0")
            summary = g1_sbom.run(r.dir, "HEAD", pathlib.Path(out_dir, "sbom.cdx.json"), _fake_syft(sbom))
            self.assertEqual(summary["status"], "pass", summary)
            self.assertIsNone(summary["status_reason"])
            self.assertEqual(summary["lockfiles"]["requirements/dev.txt"], {"pinned": 2, "missing": []})

    def test_upward_include_within_project_root_missing_package_from_main_entrypoint(self):
        # #270：../base.in 納入核對後，其中釘選的 pytest==8.0.0 若不在 SBOM → fail 並發出 sbom-incomplete 發現
        with TempRepo() as r, tempfile.TemporaryDirectory() as d, temp_policy_root() as pr:
            r.write("base.in", "pytest==8.0.0\n")
            r.write("requirements/dev.txt", "requests==2.31.0\n-r ../base.in\n")
            r.commit()
            tier = Policy(pr).tier(g1_sbom.RULE)
            rc, summary, gate, sarif_path = self._run_main(
                r.dir, pathlib.Path(d), pr, _bom("pkg:pypi/requests@2.31.0")
            )
            want_fc = {"blocking": 1, "advisory": 0} if tier == "blocking" else {"blocking": 0, "advisory": 1}
            self.assertEqual(rc, 1 if tier == "blocking" else 0, summary)
            self.assertEqual(summary["status"], "fail", summary)
            self.assertEqual(summary["lockfiles"]["requirements/dev.txt"], {"pinned": 2, "missing": ["pytest@8.0.0"]})
            self.assertTrue(sarif_path.is_file(), "fail 時應寫出 SARIF")
            results = json.loads(sarif_path.read_text(encoding="utf-8"))["runs"][0]["results"]
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["ruleId"], g1_sbom.RULE)
            self.assertEqual(results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "requirements/dev.txt")
            self.assertEqual(gate["findings_count"], want_fc)
            self.assertEqual(gate["coverage"][0]["state"], "fail")

    def test_upward_include_chaining_out_of_project_root_stays_incomplete(self):
        # 往上包含到專案根目錄內的 base.in 後，若 base.in 再往上 -r ../outside.in 超出專案根目錄，仍須回 incomplete
        with tempfile.TemporaryDirectory() as d:
            pathlib.Path(d, "outside.in").write_text("idna==3.10\n", encoding="utf-8")
            tree = pathlib.Path(d, "src")
            (tree / "requirements").mkdir(parents=True)
            (tree / "base.in").write_text("pytest==8.0.0\n-r ../outside.in\n", encoding="utf-8")
            (tree / "requirements/dev.txt").write_text("requests==2.31.0\n-r ../base.in\n", encoding="utf-8")
            sbom = _bom("pkg:pypi/requests@2.31.0", "pkg:pypi/pytest@8.0.0", "pkg:pypi/idna@3.10")
            summary = g1_sbom.check(sbom, tree)
            self.assertEqual(summary["status"], "incomplete", summary)
            self.assertEqual(summary["lockfiles"]["requirements/dev.txt"], {"pinned": 2, "missing": []})
            self.assertIn("requirements/dev.txt：1 筆無法解析或不是 registry 來源", summary["status_reason"] or "")

    def test_include_escaping_project_root_is_incomplete_even_when_outside_file_exists(self):
        # 即使匯出樹父目錄與上層暫存目錄真有同名檔案、且套件已在 SBOM，超出專案根目錄的 -r 仍必須回 incomplete（exit 2）
        with TempRepo() as r, tempfile.TemporaryDirectory() as tmp, temp_policy_root() as pr:
            work_dir = pathlib.Path(tmp)
            (work_dir / "outside.in").write_text("idna==3.10\n", encoding="utf-8")
            r.write("requirements/dev.txt", "requests==2.31.0\n-r ../../../outside.in\n")
            r.commit()
            rc, summary, _gate, _sarif = self._run_main(
                r.dir, work_dir, pr, _bom("pkg:pypi/requests@2.31.0", "pkg:pypi/idna@3.10")
            )
            self.assertEqual(rc, 2)
            self.assertEqual(summary["status"], "incomplete", summary)
            self.assertIn("requirements/dev.txt：1 筆無法解析或不是 registry 來源", summary["status_reason"] or "")

        # 緊鄰匯出樹上一層（../outside.in）真有檔案時，check(sbom, tree) 也一樣擋下（防止 root 誤傳 tree.parent）
        with tempfile.TemporaryDirectory() as d:
            pathlib.Path(d, "outside.in").write_text("idna==3.10\n", encoding="utf-8")
            tree = pathlib.Path(d, "src")
            (tree / "requirements").mkdir(parents=True)
            (tree / "requirements/dev.txt").write_text("requests==2.31.0\n-r ../../outside.in\n", encoding="utf-8")
            summary = g1_sbom.check(_bom("pkg:pypi/requests@2.31.0", "pkg:pypi/idna@3.10"), tree)
            self.assertEqual(summary["status"], "incomplete", summary)
            self.assertIn("requirements/dev.txt：1 筆無法解析或不是 registry 來源", summary["status_reason"] or "")


if __name__ == "__main__":
    unittest.main()
