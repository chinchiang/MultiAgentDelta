"""正式報告的產物、證據完整性及舊格式相容性。"""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import pr_report
from findings_format import finding_items
from gate_result import GateRun
from gate_verdict import REQUIRED_CONTROLS

COMMIT = "a" * 40


class ReportTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.out = Path(temp.name) / "reports"
        self.out.mkdir()
        self.art = Path(temp.name) / "artifacts"
        for gate, sources in pr_report.SOURCES.items():
            run = GateRun(gate, mode="shadow", controls=REQUIRED_CONTROLS.get(gate, ()), scope="diff", commit=COMMIT)
            for control in REQUIRED_CONTROLS.get(gate, ()):
                run.cover(control, "pass")
            self.put(self.out / f"{gate.lower()}-gate.json", run.result())
            for job, tool, name in sources:
                data = {"runs": [{"tool": {"driver": {"name": tool}}, "results": []}]}
                if tool == "envcheck":
                    data = {"env_gitignore_fail": 0, "committed": [], "error": None}
                self.put(self.art / f"vibesec-{job}-reports" / name, data)
        self.review = self.art / "vibesec-g4-reports/g4-review-findings.json"
        self.put(self.review, {"findings": [], "trust_problems": [], "record": None})

    def put(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data))

    def build(self):
        return pr_report.build(self.art, self.out, COMMIT, ROOT / "docs/threat-model.yaml")

    def test_empty_report(self):
        self.assertEqual(self.build(), 0)
        self.assertEqual(json.loads((self.out / "findings.json").read_text())["findings"], [])
        self.assertIn("受驗提交", (self.out / "summary.md").read_text())
        self.assertEqual(json.loads((self.out / "risk_register.json").read_text())["risks"], [])
        self.assertTrue(json.loads((self.out / "vibesec.sarif").read_text())["runs"])

    def test_blocking_and_missing_evidence_on_retry(self):
        path = self.art / "vibesec-g2-reports/gitleaks.sarif"
        self.put(path, {"runs": [{"results": [{"ruleId": "generic-api-key",
                                                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}}}]}]}]})
        gate_path = self.out / "g2-gate.json"
        gate = json.loads(gate_path.read_text())
        gate.update(status="fail", findings_count={"blocking": 1, "advisory": 0})
        self.put(gate_path, gate)
        self.assertEqual(self.build(), 0)
        item, = json.loads((self.out / "findings.json").read_text())["findings"]
        self.assertEqual(item["policy_tier"], "blocking")
        self.assertEqual(item["evidence_refs"][0]["ref"], "vibesec-g2-reports/gitleaks.sarif")
        path.unlink()
        self.assertEqual(self.build(), 2)
        self.assertIn("gitleaks.sarif", (self.out / "summary.md").read_text())
        self.assertFalse(json.loads((self.out / "findings.json").read_text())["findings"])
        runs = json.loads((self.out / "vibesec.sarif").read_text())["runs"]
        gitleaks, = (run for run in runs if run["tool"]["driver"]["name"] == "gitleaks")
        self.assertFalse(gitleaks["invocations"][0]["executionSuccessful"])

    def test_same_location_keeps_both_evidence_references(self):
        path = self.art / "vibesec-g1-reports/g1-slopcheck.sarif"
        results = [{"ruleId": "vibesec.g1.low-download-package", "properties": {
            "package": package, "policy_tier": "advisory"}, "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": "package.json"}}}]} for package in ("a", "b")]
        self.put(path, {"runs": [{"results": results}]})
        gate_path = self.out / "g1-gate.json"
        gate = json.loads(gate_path.read_text())
        gate["findings_count"]["advisory"] = 2
        self.put(gate_path, gate)
        self.assertEqual(self.build(), 0)
        item, = finding_items(json.loads((self.out / "findings.json").read_text()))
        self.assertEqual(len({r["note"] for r in item["evidence_refs"]}), 2)

    def test_corrupt_review(self):
        self.put(self.review, {})
        self.assertEqual(self.build(), 2)

    def test_review_preserves_id(self):
        record = {"id": "VS-20261123-12345678", "rule_id": "vibesec.g4.owner-binding", "title": "測試",
                  "policy_tier": "blocking", "evidence_grade": "E1", "validation_status": "pending",
                  "requires_human": True, "opinions": []}
        self.put(self.review, {"record": "reviews/g4/example.yaml", "trust_problems": [], "findings": [record]})
        path = self.out / "g4-gate.json"
        gate = json.loads(path.read_text())
        gate.update(status="pending", findings_count={"blocking": 1, "advisory": 0})
        self.put(path, gate)
        self.assertEqual(self.build(), 0)
        item, = finding_items(json.loads((self.out / "findings.json").read_text()))
        self.assertEqual(item["id"], record["id"])
        self.assertTrue(item["review"]["requires_human"])

    def test_report_envelopes(self):
        for invalid in ({}, None, {"findings": ""}, {"findings": {}}, {"findings": None}, False):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                finding_items(invalid)
        for valid in ([], {"findings": []}):
            self.assertEqual(finding_items(valid), [])
