"""正式報告的產物、證據完整性及舊格式相容性。"""
import json
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from g4_review import derive_gate
import pr_report
from findings_format import finding_items
from gate_result import GateRun
from gate_verdict import REQUIRED_CONTROLS

COMMIT = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()


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
                data = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": tool}}, "results": []}]}
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
        self.put(path, {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "測試掃描器"}}, "results": [{"ruleId": "generic-api-key",
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
        self.put(path, {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "測試掃描器"}}, "results": results}]})
        gate_path = self.out / "g1-gate.json"
        gate = json.loads(gate_path.read_text())
        gate["findings_count"]["advisory"] = 2
        self.put(gate_path, gate)
        self.assertEqual(self.build(), 0)
        items = finding_items(json.loads((self.out / "findings.json").read_text()))
        self.assertEqual({item["location"]["package"] for item in items}, {"a", "b"})
        self.assertEqual(len({r["note"] for item in items for r in item["evidence_refs"]}), 2)

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

    def test_invalid_results_keep_valid_evidence_and_positions(self):
        path = self.art / "vibesec-g2-reports/gitleaks.sarif"
        gate = self.out / "g2-gate.json"
        for results, good in [([None], 0), ([None, {"ruleId": "generic-api-key"}], 1)]:
            with self.subTest(results=results):
                self.put(path, {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "測試掃描器"}}, "results": results}]})
                result = json.loads(gate.read_text())
                result.update(status="fail" if good else "incomplete", status_reason="測試輸入損壞",
                              findings_count={"blocking": good, "advisory": 0})
                self.put(gate, result)
                self.assertEqual(self.build(), 2)
                report = json.loads((self.out / "findings.json").read_text())
                self.assertIn("runs[0].results[0]", str(report["evidence_gaps"]))
                self.assertEqual(len(report["findings"]), good)
                if good:
                    self.assertIn("runs[0].results[1]", report["findings"][0]["evidence_refs"][0]["note"])

    def test_malformed_exception_keeps_next_native_result(self):
        path = self.art / "vibesec-g4-reports/g4-static.sarif"
        rule = "vibesec.g4.single-middleware-authz"
        self.put(path, {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "測試掃描器"}}, "results": [
            {"ruleId": rule, "properties": {"policy_tier": "advisory", "exception": "格式錯誤"}},
            {"ruleId": rule, "properties": {"policy_tier": "advisory"}},
        ]}]})
        gate_path = self.out / "g4-gate.json"
        gate = json.loads(gate_path.read_text())
        gate["findings_count"]["advisory"] = 1
        self.put(gate_path, gate)
        self.assertEqual(self.build(), 2)
        report = json.loads((self.out / "findings.json").read_text())
        gap, = report["evidence_gaps"]
        for detail in ("g4-static", "vibesec-g4-reports/g4-static.sarif", "runs[0].results[0]"):
            self.assertIn(detail, gap)
        item, = report["findings"]
        self.assertIn("runs[0].results[1]", item["evidence_refs"][0]["note"])

    def test_cross_day_review_merge_and_ruling(self):
        rule = "vibesec.g4.single-middleware-authz"
        self.put(self.art / "vibesec-g4-reports/g4-static.sarif", {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "測試掃描器"}}, "results": [
            {"ruleId": rule, "properties": {"policy_tier": "advisory"}, "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": "app.py"}}}]}]}]})
        gate_path = self.out / "g4-gate.json"
        gate = json.loads(gate_path.read_text())
        gate["findings_count"]["advisory"] = 1
        self.put(gate_path, gate)
        report_path = self.out / "findings.json"
        with patch.object(pr_report, "now", return_value="2026-11-23T23:59:59Z"):
            self.assertEqual(self.build(), 0)
        original, = finding_items(json.loads(report_path.read_text()))
        fid = original["id"]
        # 裁決檔先引用第一天的識別碼，隔天從新的報告入口查詢與套用。
        ruling = self.write_ruling(fid)
        record = {"id": fid, "rule_id": rule, "title": "測試", "policy_tier": "blocking",
                  "evidence_grade": "E2", "opinions": []}
        for status in ("pending", "confirmed", "refuted"):
            with self.subTest(status=status):
                active = status != "refuted"
                ev = {"findings": [dict(record, validation_status=status, requires_human=status == "pending")],
                      "families": 2, "incomplete": []}
                review_ref = "reviews/g4/example.yaml"
                derived, findings = derive_gate(gate, {"providers": [], "coverage": gate["coverage"]},
                                                ev, None, review_ref)
                expected = {"pending": "pending", "confirmed": "fail", "refuted": "pass"}[status]
                self.assertEqual(derived["status"], expected)
                self.assertEqual(derived["findings_count"], {"blocking": int(active), "advisory": 1})
                self.put(gate_path, derived)
                self.put(self.review, {"record": review_ref, "trust_problems": [], "findings": findings})
                with patch.object(pr_report, "now", return_value="2026-11-24T00:00:01Z"):
                    self.assertEqual(self.build(), 0)
                doc = json.loads(report_path.read_text())
                item, = finding_items(doc)
                tier = "blocking" if active else "advisory"
                self.assertEqual((item["id"], item["policy_tier"], item["validation_status"]), (fid, tier, status))
                self.assertNotEqual(item["created_at"], original["created_at"])
                refs = item["evidence_refs"]
                self.assertIn("advisory", refs[0]["note"])
                self.assertIn("blocking", refs[1]["note"])
                summary = (self.out / "summary.md").read_text()
                label = f"`{expected}`" + ("（blocking 1，待裁決）" if status == "pending" else "")
                self.assertIn(f"| G4 | {label} | {int(active)} | 1 |", summary)
                self.assertIn(f"{fid} G4 {rule} {tier}", summary.replace("\\", ""))
                if status == "pending":
                    self.exercise_ruling(doc, fid, ruling)

    def write_ruling(self, fid):
        example = yaml.safe_load((ROOT / "docs/templates/human-ruling.example.yaml").read_text())
        example.update(finding_id=fid, minority_acknowledged=[])
        ruling = self.out / "decision.yaml"
        ruling.write_text(yaml.safe_dump(example))
        return ruling

    def exercise_ruling(self, doc, fid, ruling):
        for envelope in (True, False):
            report = self.out / "old-or-new.json"
            self.put(report, doc if envelope else doc["findings"])
            for cmd, target in (("request", fid), ("check", str(ruling)), ("apply", str(ruling))):
                result = subprocess.run([sys.executable, str(ROOT / "scripts/ruling.py"), cmd, target,
                                         "--findings", str(report)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            updated = json.loads(report.read_text())
            self.assertEqual(isinstance(updated, dict), envelope)
            if envelope:
                self.assertEqual({k: v for k, v in updated.items() if k != "findings"},
                                 {k: v for k, v in doc.items() if k != "findings"})
            item, = finding_items(updated)
            self.assertEqual((item["validation_status"], item["policy_tier"]), ("confirmed", "blocking"))

    def test_ruling_entry_points_preserve_legacy_and_wrapped_reports(self):
        import ruling
        item, decision = ruling._synthetic()
        path = self.out / "existing-ruling.yaml"
        path.write_text(yaml.safe_dump(decision))
        self.exercise_ruling({"findings": [item], "project": {"name": "test"}}, item["id"], path)

    def test_mixed_run_metadata_keeps_good_result(self):
        path = self.art / "vibesec-g2-reports/gitleaks.sarif"
        self.put(path, {"version": "2.1.0", "runs": [
            {"invocations": 1, "results": []},
            {"tool": {"driver": "bad"}, "results": [None, {"ruleId": "generic-api-key"}]}]})
        self.assertEqual(self.build(), 2)
        report = json.loads((self.out / "findings.json").read_text())
        item, = report["findings"]
        self.assertEqual(item["policy_tier"], "blocking")
        self.assertIn("runs[1].results[1]", item["evidence_refs"][0]["note"])
        self.assertIn("runs[0].invocations", str(report["evidence_gaps"]))

    def test_legacy_review_id_and_untrusted_ruling(self):
        from gate_result import _finding_id
        rule = "vibesec.g4.single-middleware-authz"
        legacy_id = _finding_id(rule, "app.py", None, COMMIT, "2020-01-01T00:00:00Z")
        self.put(self.art / "vibesec-g4-reports/g4-static.sarif", {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "測試掃描器"}}, "results": [
            {"ruleId": rule, "properties": {"policy_tier": "advisory"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}}}]}]}]})
        record = {"location": {"kind": "architecture"}, "id": legacy_id, "rule_id": rule, "title": "測試", "policy_tier": "blocking",
                  "evidence_grade": "E3", "validation_status": "confirmed", "requires_human": False,
                  "ruling_ref": "rulings/test.yaml", "opinions": []}
        self.put(self.review, {"findings": [record], "record": "reviews/g4/example.yaml", "trust_problems": ["待核准"]})
        path = self.out / "g4-gate.json"
        gate = json.loads(path.read_text())
        gate.update(status="pending", findings_count={"blocking": 1, "advisory": 1})
        self.put(path, gate)
        self.assertEqual(self.build(), 0)
        item, = finding_items(json.loads((self.out / "findings.json").read_text()))
        self.assertEqual((item["id"], item["evidence_grade"], item["validation_status"]), (legacy_id, "E1", "pending"))
        self.assertIsNone(item["review"]["ruling_ref"])
        runs = json.loads((self.out / "vibesec.sarif").read_text())["runs"]
        run, = (r for r in runs if r["tool"]["driver"]["name"] == "g4-static")
        result, = run["results"]
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "app.py")
        risks = json.loads((self.out / "risk_register.json").read_text())["risks"]
        self.assertEqual([r["id"] for r in risks], [legacy_id])
        self.assertEqual(result["fingerprints"]["vibesec/id"], legacy_id)
        self.assertEqual(result["properties"]["vibesec/policy_tier"], "blocking")

    def test_exception_uses_scan_day(self):
        self.put(self.art / "vibesec-g2-reports/gitleaks.sarif", {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "測試掃描器"}}, "results": [
            {"ruleId": "generic-api-key", "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": "examples/vulnapp/app/main.py"}}}]}]}]})
        self.put(self.art / "vibesec-g2-reports/g2-envcheck.json", {"env_gitignore_fail": 0})
        path = self.out / "g2-gate.json"
        gate = json.loads(path.read_text())
        for day, active in (("2027-03-31", True), ("2027-04-01", False)):
            with self.subTest(day=day):
                gate.update(started_at=day + "T20:00:00Z", finished_at=day + "T20:01:00Z",
                            status="pass" if active else "fail",
                            findings_count={"advisory": int(active), "blocking": int(not active)})
                self.put(path, gate)
                self.assertEqual(self.build(), 0)
                item, = finding_items(json.loads((self.out / "findings.json").read_text()))
                self.assertEqual(item["policy_tier"], "advisory" if active else "blocking")

    def test_refutation_requires_trust_before_releasing_block(self):
        from g4_review import gate_exit_code
        gate_path = self.out / "g4-gate.json"
        static = json.loads(gate_path.read_text())
        row = {"id": "VS-20261124-a1234567", "rule_id": "vibesec.g4.owner-binding", "title": "裁決",
               "policy_tier": "blocking", "evidence_grade": "E3", "opinions": [],
               "ruling_ref": "rulings/example.yaml", "validation_status": "refuted", "requires_human": False}
        ev = {"findings": [row], "families": 2, "incomplete": []}
        for trust, count, status, gate_status in ((["待核准"], 1, "pending", "pending"), ([], 0, "refuted", "pass")):
            with self.subTest(trust=trust):
                gate, details = derive_gate(static, {"providers": [], "coverage": static["coverage"]},
                                            ev, None, "record", trust_problems=trust)
                self.assertEqual((gate["status"], gate["findings_count"]["blocking"]), (gate_status, count))
                self.assertEqual(gate_exit_code(gate, "enforce"), count)
                self.put(gate_path, gate)
                self.put(self.review, {"findings": details, "record": "record", "trust_problems": trust})
                self.assertEqual(self.build(), 0)
                item, = json.loads((self.out / "findings.json").read_text())["findings"]
                self.assertEqual((item["policy_tier"], item["validation_status"]), ("blocking", status))
                self.assertEqual(item["review"]["requires_human"], bool(trust))
                summary = (self.out / "summary.md").read_text()
                label = "`pending`（blocking 1，待裁決）" if trust else "`pass`"
                self.assertIn(f"| G4 | {label} | {count} |", summary)

    def test_empty_scan_requires_version_and_named_driver(self):
        import sarif_gate
        path = self.art / "vibesec-g2-reports/gitleaks.sarif"
        env = path.with_name("g2-envcheck.json")
        policy, _ = pr_report.load_policy(ROOT)
        for version, name, field in ((None, "Gitleaks", "version"), ("2.0.0", "Gitleaks", "version"),
                                     ("2.1.0", None, "runs[0].tool.driver.name"),
                                     ("2.1.0", " ", "runs[0].tool.driver.name"), ("2.1.0", "Gitleaks", None)):
            with self.subTest(version=version, name=name):
                run = {"results": []}
                if name is not None:
                    run["tool"] = {"driver": {"name": name}}
                doc = {"runs": [run]}
                if version is not None:
                    doc["version"] = version
                self.put(path, doc)
                gate = sarif_gate.derive("G2", {"gitleaks": path}, env, sarif_gate.load_context(policy),
                                         policy.for_project(ROOT))
                self.assertEqual(gate["status"], "incomplete" if field else "pass")
                self.put(self.out / "g2-gate.json", gate)
                self.assertEqual(self.build(), 2 if field else 0)
                gaps = json.loads((self.out / "findings.json").read_text())["evidence_gaps"]
                if field:
                    self.assertTrue(any(path.name in gap and field in gap for gap in gaps))
                else:
                    self.assertEqual(gaps, [])

    def test_review_location_reaches_risk_register_and_corruption_is_isolated(self):
        import copy
        import g4_review
        record = g4_review._example()
        arch, = record["findings"]
        arch["location"] = {"kind": "architecture"}
        code = copy.deepcopy(arch)
        code.update(id="VS-20261124-ab000002", location={"kind": "code", "path": "app.py", "start_line": 9})
        record["findings"].append(code)
        ev = g4_review.evaluate(record, g4_review.load_cfg(), g4_review.known_controls())
        self.assertEqual(ev["errors"], [])
        gate_path = self.out / "g4-gate.json"
        gate, details = derive_gate(json.loads(gate_path.read_text()), record, ev, None, "record")
        self.put(gate_path, gate)
        for bad_index in (None, 0, 2):
            with self.subTest(bad_index=bad_index):
                rows = details.copy()
                if bad_index is not None:
                    rows.insert(bad_index, None)
                self.put(self.review, {"record": "record", "trust_problems": [], "findings": rows})
                self.assertEqual(self.build(), 0 if bad_index is None else 2)
                doc = json.loads((self.out / "findings.json").read_text())
                self.assertEqual([f["location"] for f in doc["findings"]], [arch["location"], code["location"]])
                risks = json.loads((self.out / "risk_register.json").read_text())["risks"]
                self.assertEqual([r["id"] for r in risks], [arch["id"]])
                runs = json.loads((self.out / "vibesec.sarif").read_text())["runs"]
                review_run, = (r for r in runs if r["tool"]["driver"]["name"] == "g4-review")
                self.assertEqual(review_run["invocations"][0]["executionSuccessful"], bad_index is None)
                result, = (r for run in runs for r in run["results"])
                self.assertEqual(result["fingerprints"]["vibesec/id"], code["id"])
                self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 9)
                if bad_index is not None:
                    gap, = doc["evidence_gaps"]
                    self.assertIn(f"findings[{bad_index}]", gap)

    def test_static_conflict_keeps_later_blocking_result(self):
        rules = ["vibesec.g4.first", "vibesec.g4.first", "vibesec.g4.last"]
        rows = [{"ruleId": rule, "properties": {"policy_tier": tier}}
                for rule, tier in zip(rules, ("advisory", "blocking", "blocking"))]
        self.put(self.art / "vibesec-g4-reports/g4-static.sarif", {
            "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "g4-static"}}, "results": rows}]})
        gate_path = self.out / "g4-gate.json"
        gate = json.loads(gate_path.read_text())
        gate.update(status="fail", findings_count={"advisory": 1, "blocking": 2})
        self.put(gate_path, gate)
        self.assertEqual(self.build(), 2)
        doc = json.loads((self.out / "findings.json").read_text())
        gap, = doc["evidence_gaps"]
        self.assertIn("runs[0].results[1]", gap)
        self.assertEqual(doc["findings"][-1]["rule_id"], rules[-1])
        self.assertEqual(doc["findings"][-1]["policy_tier"], "blocking")

    def test_grype_damage_preserves_valid_matches(self):
        from datetime import datetime, timezone
        grype, kev = self.out / "grype.json", self.out / "kev.json"
        summary = self.out / "kev-summary.json"
        sarif = self.art / "vibesec-g1-reports/g1-kev.sarif"
        gate_path = self.out / "g1-gate.json"
        base_gate = json.loads(gate_path.read_text())
        self.put(kev, {"dateReleased": datetime.now(timezone.utc).isoformat(),
                       "vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}]})
        good = {"vulnerability": {"id": "CVE-2021-44228"}, "artifact": {"name": "example", "version": "1"}}
        for rows, rc, count in (([], 0, 0), ([good], 1, 1), ([{}], 2, 0), ([None], 2, 0),
                                ([None, good, {}], 2, 1)):
            with self.subTest(rows=rows):
                self.put(gate_path, base_gate)
                self.put(grype, {"matches": rows})
                result = subprocess.run([sys.executable, str(ROOT / "scripts/g1_kev.py"), "--grype", str(grype),
                                         "--kev-feed", str(kev), "--json", str(summary), "--sarif", str(sarif),
                                         "--merge-gate", str(gate_path)],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, rc, result.stderr)
                doc = json.loads(summary.read_text())
                self.assertEqual(len(doc["hits"]), count)
                self.assertEqual(doc["matches_checked"], count)
                self.assertEqual(doc["status"], {0: "pass", 1: "fail", 2: "incomplete"}[rc])
                for index, row in enumerate(rows):
                    if not row:
                        self.assertIn(f"matches[{index}]", doc["status_reason"])
                self.assertEqual(sarif.exists(), rc != 2 or count > 0)
                if rc == 2 and count:
                    run, = json.loads(sarif.read_text())["runs"]
                    self.assertFalse(run["invocations"][0]["executionSuccessful"])
                    self.assertEqual(len(run["results"]), count)
                    self.assertEqual(json.loads(gate_path.read_text())["findings_count"]["blocking"], count)
                    self.assertEqual(self.build(), 2)
                    report = json.loads((self.out / "findings.json").read_text())
                    self.assertEqual(len(report["findings"]), count)
                    self.assertTrue(any("matches[0]" in gap for gap in report["evidence_gaps"]))

    def test_envcheck_gate_and_report_agree(self):
        path = self.art / "vibesec-g2-reports/g2-envcheck.json"
        gate_path = self.out / "g2-gate.json"
        for data, status in (({"env_gitignore_fail": 0}, "pass"), ({}, "incomplete"),
                             ({"env_gitignore_fail": 1}, "pass"), ({"env_gitignore_fail": None}, "incomplete"),
                             ({"env_gitignore_fail": 0, "committed": 7}, "incomplete"),
                             ({"env_gitignore_fail": 0, "committed": [None]}, "incomplete")):
            with self.subTest(data=data):
                self.put(path, data)
                subprocess.run([sys.executable, str(ROOT / "scripts/sarif_gate.py"), "--gate", "G2", "--tool",
                                "gitleaks=" + str(path.with_name("gitleaks.sarif")), "--envcheck", str(path),
                                "--out", str(gate_path)], capture_output=True, text=True, check=True)
                self.assertEqual(json.loads(gate_path.read_text())["status"], status)
                self.assertEqual(self.build(), 2 if status == "incomplete" else 0)

        self.put(path, {"env_gitignore_fail": 0, "committed": [None, ".env"]})
        subprocess.run([sys.executable, str(ROOT / "scripts/sarif_gate.py"), "--gate", "G2", "--tool",
                        "gitleaks=" + str(path.with_name("gitleaks.sarif")), "--envcheck", str(path),
                        "--out", str(gate_path)], capture_output=True, text=True, check=True)
        gate = json.loads(gate_path.read_text())
        self.assertEqual(sum(gate["findings_count"].values()), 1)
        self.assertIn("committed[0]", gate["status_reason"])
        self.assertEqual(self.build(), 2)
        doc = json.loads((self.out / "findings.json").read_text())
        self.assertEqual(doc["findings"][0]["location"]["path"], ".env")
        self.assertIn("committed[0]", str(doc["evidence_gaps"]))

    def test_dependency_identity_and_source_fields(self):
        import g1_kev
        policy, _ = pr_report.load_policy(ROOT)
        first = dict(package="a", version="1", uri="pom.xml", ecosystem="maven", cve="CVE-2021-44228",
                     kev_date="2021-12-10", fixed_versions=[])
        hits = [first, dict(first, package="b"), dict(first, version="2"), dict(first, cve="CVE-2021-44832")]
        gate_path = self.out / "g1-gate.json"
        gate = json.loads(gate_path.read_text())
        gate.update(status="fail", findings_count={"blocking": 4, "advisory": 0})
        self.put(gate_path, gate)
        runs = []
        for source in (hits, hits[::-1]):
            self.put(self.art / "vibesec-g1-reports/g1-kev.sarif", g1_kev.to_sarif(source, [], policy))
            self.assertEqual(self.build(), 0)
            rows = json.loads((self.out / "findings.json").read_text())["findings"]
            ids = {(f["location"]["package"], f["location"]["version"], f["cve"]): f["id"] for f in rows}
            self.assertEqual(set(ids), {(r["package"], r["version"], r["cve"]) for r in hits})
            self.assertEqual(len(set(ids.values())), 4)
            self.assertTrue(all(f["kev"] and f["kev_date"] == "2021-12-10" for f in rows))
            runs.append(ids)
        self.assertEqual(*runs)

    def test_ruling_fields_match_report_and_direct_apply(self):
        import g4_review
        import ruling
        rec = g4_review._example()
        row, = rec["findings"]
        ref = "rulings/" + row["id"] + ".yaml"
        row["ruling_ref"] = ref
        decision = g4_review._example_ruling(row["id"])
        applied = ruling.apply(decision, {**row, "review": {"opinions": row["opinions"]}}, ref)
        ev = g4_review.evaluate(rec, g4_review.load_cfg(), g4_review.known_controls(), ruling_loader=lambda _: decision)
        self.assertEqual(ev["errors"], [])
        path = self.out / "g4-gate.json"
        static = json.loads(path.read_text())
        for trust in ([], ["未核准"]):
            gate, details = derive_gate(static, rec, ev, None, "record", trust_problems=trust)
            self.put(path, gate)
            self.put(self.review, {"record": "record", "trust_problems": trust, "findings": details})
            self.assertEqual(self.build(), 0)
            item, = json.loads((self.out / "findings.json").read_text())["findings"]
            evidence = [e for e in item["evidence_refs"] if e["kind"] != "model_review"]
            if trust:
                self.assertEqual((item["validation_status"], item["evidence_grade"]), ("pending", "E1"))
                self.assertEqual(evidence, [])
                self.assertIsNone(item["review"]["human_decision"])
                self.assertIsNone(item["review"]["ruling_ref"])
            else:
                for key in ("validation_status", "evidence_grade", "review"):
                    self.assertEqual(item[key], applied[key])
                self.assertEqual(evidence, applied["evidence_refs"])
