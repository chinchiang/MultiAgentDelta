"""彙整本次 PR 的 G1–G4 結果；保留證據缺口，報告不重新裁決閘門。"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re

from jsonschema import ValidationError

from findings_format import finding_items
from g0_trifecta import load_threat_model
from gate_result import finding, now, _finding_validator
from gate_verdict import _cell, _load_gates, _read_settings, enforce
from sarif_gate import env_findings, load_context, read_sarif, to_findings
from vibesec_policy import load_policy

ROOT = Path(__file__).resolve().parents[1]
# 只讀參與閘門計數的證據。Grype 掃描結果經 G1 KEV 分類；Trivy 檔案系統掃描另上傳 Code Scanning。
SOURCES = {
    "G1": [("g1", "g1-slopcheck", "g1-slopcheck.sarif"), ("g1", "g1-sbom", "g1-sbom.sarif"),
           ("g1", "g1-kev", "g1-kev.sarif")],
    "G2": [("g2", "gitleaks", "gitleaks.sarif"), ("g2", "envcheck", "g2-envcheck.json")],
    "G3": [("g3-semgrep", "semgrep", "semgrep.sarif"), ("g3-iac", "checkov", "results_sarif.sarif"),
           ("g3-iac", "trivy", "trivy-config.sarif")],
    "G4": [("g4", "g4-static", "g4-static.sarif")],
}


def read_source(path, tool, context, project):
    if tool == "envcheck":
        data = json.loads(path.read_text())
        if data.get("env_gitignore_fail") not in (0, 1) or not isinstance(data.get("committed"), list):
            raise ValueError("缺少 .gitignore 檢查狀態")
        return env_findings(data, context), data.get("error")
    results, problem = read_sarif(path)
    rows = []
    for index, result in enumerate(results or []):
        if not result.get("ruleId"):
            raise ValueError("缺少 SARIF 規則識別碼")
        for row in to_findings(tool, [result], context, project):
            props = result.get("properties") or {}
            if tool.startswith(("g1-", "g4-")):
                row["rule_id"] = result["ruleId"]
                row["policy_tier"] = props["policy_tier"]
                if props.get("exception"):
                    row["exception"] = props["exception"]
            locations = result.get("locations") or [{}]
            region = locations[0].get("physicalLocation", {}).get("region", {})
            row["line"] = region.get("startLine")
            row["result_index"] = index
            rows.append(row)
    return rows, problem


def build(artifacts, out, commit, threat_model):
    if not re.fullmatch("[0-9a-f]{40}", commit):
        raise ValueError("需要完整的受驗提交識別碼")
    policy, problem = load_policy(ROOT)
    if problem:
        raise ValueError(problem)
    context = load_context(policy)
    project = policy.for_project(ROOT)
    gates = _load_gates([f"{g}={out}/{g.lower()}-gate.json" for g in SOURCES], ROOT)
    mode, incomplete, config, errors, notes = _read_settings(ROOT, None)
    verdict = enforce(gates, mode=mode, incomplete_blocking_gates=incomplete, errors=errors, notes=notes)
    stamp = now()
    findings, gaps = {}, []
    runs = defaultdict(list)
    failed_tools = set()
    validator = _finding_validator()
    for gate, sources in SOURCES.items():
        counts = Counter()
        for job, tool, filename in sources:
            ref = f"vibesec-{job}-reports/{filename}"
            path = artifacts / ref
            try:
                rows, issue = read_source(path, tool, context, project)
                runs.setdefault(tool, [])
                if issue:
                    failed_tools.add(tool)
                    gaps.append(f"{gate} {ref}：{issue}")
                if not rows:
                    continue
                digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
                for row in rows:
                    rule = row["rule_id"]
                    loc = {"kind": "dependency" if gate == "G1" else "code",
                           "path": row["location"], "start_line": row.get("line"), "commit": commit}
                    evidence = {"kind": "tool_output", "ref": ref, "digest": digest}
                    if "result_index" in row:
                        evidence["note"] = f"SARIF 結果序號（跨 run，自零起算）：{row['result_index']}"
                    item = finding(gate=gate, rule_id=rule, title=rule, policy_tier=row["policy_tier"],
                                   evidence_grade="E1", sources={"tool": tool, "tool_version": None},
                                   location=loc, commit=commit, created_at=stamp, evidence_refs=[evidence],
                                   exception=row.get("exception"))
                    validator.validate(item)
                    counts[item["policy_tier"]] += 1
                    previous = findings.setdefault(item["id"], item)
                    if previous is not item:
                        if previous["policy_tier"] != item["policy_tier"] or previous["gate"] != gate:
                            raise ValueError("相同發現識別碼有相衝突的判定")
                        if evidence not in previous["evidence_refs"]:
                            previous["evidence_refs"].append(evidence)
                    physical = {"artifactLocation": {"uri": loc["path"]}}
                    if loc["start_line"]:
                        physical["region"] = {"startLine": loc["start_line"]}
                    runs[tool].append({"ruleId": rule, "message": {"text": rule},
                                       "fingerprints": {"vibesec/id": item["id"]},
                                       "locations": [{"physicalLocation": physical}]})
            except (OSError, ValueError, AttributeError, KeyError, TypeError, ValidationError, IndexError) as exc:
                failed_tools.add(tool)
                runs.setdefault(tool, [])
                gaps.append(f"{gate} {ref}：證據無法驗收（{type(exc).__name__}）")
        if gate == "G4":
            ref = "vibesec-g4-reports/g4-review-findings.json"
            try:
                review = json.loads((artifacts / ref).read_text())
                for f in finding_items(review):
                    item = finding(gate=gate, rule_id=f["rule_id"], title=f["title"],
                                   evidence_grade=f["evidence_grade"], policy_tier=f["policy_tier"],
                                   sources={"tool": "g4-review", "tool_version": None}, created_at=stamp,
                                   validation_status="pending" if review["trust_problems"] else f["validation_status"],
                                   review={"opinions": f["opinions"], "ruling_ref": f.get("ruling_ref"),
                                           "requires_human": bool(review["trust_problems"] or f["requires_human"])},
                                   evidence_refs=[{"kind": "model_review", "ref": ref, "note": review["record"]}])
                    item["id"] = f["id"]
                    validator.validate(item)
                    prior = findings.get(item["id"])
                    if prior is None:
                        findings[item["id"]] = item
                    else:
                        if prior["gate"] != gate or prior["rule_id"] != item["rule_id"]:
                            raise ValueError("審查識別碼與其他發現衝突")
                        # 同一筆發現可同時有靜態證據與人工審查，保留兩種來源。
                        prior["evidence_refs"].extend(item["evidence_refs"])
                        prior.update({k: item[k] for k in ("review", "validation_status", "evidence_grade")})

                    if f["validation_status"] != "refuted":
                        counts[f["policy_tier"]] += 1
            except (OSError, ValueError, KeyError, TypeError, ValidationError) as exc:
                gaps.append(f"G4 {ref}：審查明細無法驗收（{type(exc).__name__}）")
        result = gates[gate]
        if not isinstance(result, dict):
            gaps.append(f"{gate} 閘門結果缺少或格式無效")
        elif result.get("commit") and not commit.startswith(result["commit"]):
            gaps.append(f"{gate} 閘門結果的提交與受驗版本不符")
        elif counts != Counter(result["findings_count"]):
            gaps.append(f"{gate} 發現明細與閘門計數不一致")
    items = list(findings.values())
    model, problem = load_threat_model(threat_model)
    if problem:
        gaps.append(f"威脅模型：{problem}")
    open_threats = [t for t in (model or {}).get("threats", []) if t.get("status") == "open"]
    metadata = {"commit": commit, "generated_at": stamp, "gates": list(SOURCES), "evidence_gaps": gaps}
    def write(name, obj):
        (out / name).write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")
    write("findings.json", {**metadata, "findings": items})
    write("risk_register.json", {**metadata, "project": config["project"]["name"], "mode": mode,
                                 "risk_tier": policy.risk_tier, "threat_model_open_threats": open_threats, "risks": [
                                     f for f in items if (f["location"] or {}).get("kind") in ("architecture", "prompt")]})
    write("vibesec.sarif", {"version": "2.1.0", "runs": [
        {"tool": {"driver": {"name": t}}, "results": r,
         "invocations": [{"executionSuccessful": t not in failed_tools}]} for t, r in sorted(runs.items())]})
    coverage = [f"{g} {c['control_id']}：{c['state']}" for g, data in gates.items()
                if isinstance(data, dict) for c in data["coverage"]]
    pending = [r["gate"] for r in verdict["rows"] if r["status"] == "pending"]
    pending.extend(f["id"] for f in items if (f.get("review") or {}).get("requires_human"))
    unfinished = [f"{r['gate']}：{r['reason']}" for r in verdict["rows"] if r["status"] == "incomplete"]
    parts = [verdict["markdown"], f"受驗提交：{commit}"]
    for title, lines in [("未完成與證據缺口", gaps + unfinished), ("致命三要素", ["G0 屬設計審查，本次範圍為 G1–G4。"]),
                         ("發現", [f"{f['id']} {f['gate']} {f['rule_id']} {f['policy_tier']}" for f in items]),
                         ("控制覆蓋情形", coverage), ("待人工裁決", pending),
                         ("退出碼", [f"閘門政策 {verdict['code']}；報告驗收 {2 if gaps else 0}"])]:
        parts.extend([f"## {title}", "\n".join("- " + _cell(line) for line in lines) or "無"])
    (out / "summary.md").write_text("\n\n".join(parts) + "\n")
    return 2 if gaps else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--threat-model", required=True, type=Path)
    args = parser.parse_args()
    raise SystemExit(build(args.artifacts, args.out, args.commit, args.threat_model))
