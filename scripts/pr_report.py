"""彙整本次 PR 的 G1–G4 結果；保留證據缺口，報告不重新裁決閘門。"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

from jsonschema import ValidationError

from findings_format import finding_items
from g0_trifecta import load_threat_model
from g4_review import effective_review_finding
from gate_result import finding, now, _finding_id, _finding_validator, known_cves
from gate_verdict import _cell, _load_gates, _read_settings, enforce
from sarif_gate import env_findings, load_context, read_envcheck, read_sarif, to_findings
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


def dependency_fields(props, catalog):
    """保留來源的套件識別；正式 CVE 欄位只採用目錄可核對的識別碼。"""
    package = props.get("package")
    if package is None:
        return {}, {}
    version, ecosystem = props.get("version"), props.get("ecosystem")
    vuln_id = props.get("vuln_id") or props.get("cve")
    if not isinstance(package, str) or not package.strip() or any(
            v is not None and not isinstance(v, str) for v in (version, ecosystem, vuln_id)):
        raise ValueError("套件名稱、版本、生態系或弱點識別碼格式錯誤")
    cves = props.get("cves", [])
    if not isinstance(cves, list) or not all(isinstance(v, str) for v in cves):
        raise ValueError("cves 格式錯誤")
    if props.get("cve") is not None and not isinstance(props["cve"], str):
        raise ValueError("cve 格式錯誤")
    ids = [props["cve"]] if props.get("cve") else cves
    fields = {"dependency_key": [ecosystem, package, version, vuln_id],
              "cve": next((c for c in ids if c in catalog), None),
              "kev": props.get("kev"), "kev_date": props.get("kev_date")}
    unknown = [c for c in ids if c not in catalog]
    if unknown:
        fields["notes"] = "來源列出但目錄未收錄的 CVE：" + "、".join(unknown)
    severity = props.get("grype_severity")
    if isinstance(severity, str) and severity.lower() in ("critical", "high", "medium", "low", "info"):
        fields["severity"] = severity.lower()
    score = props.get("cvss")
    if isinstance(score, dict) and score.get("version") in ("3.1", "4.0"):
        fields.update(cvss_version=score["version"], cvss_vector=score.get("vector"), cvss_score=score.get("base_score"))
    return {"package": package, "version": version}, fields


def read_source(path, tool, context, project, catalog):
    if tool == "envcheck":
        try:
            data = read_envcheck(path)
        except ValueError as exc:
            return [], str(exc)
        return env_findings(data, context), data.get("error")
    results, problem = read_sarif(path)
    problems = [problem] if problem else []
    rows = []
    for result in results or []:
        if not result.get("ruleId"):
            raise ValueError("缺少 SARIF 規則識別碼")
        for row in to_findings(tool, [result], context, project):
            props = result.get("properties") or {}
            if tool.startswith(("g1-", "g4-")):
                row["rule_id"] = result["ruleId"]
                if props.get("policy_tier") not in ("blocking", "advisory"):
                    problems.append(f"{result['_vibesec_position']}.properties.policy_tier 格式錯誤")
                    continue
                row["policy_tier"] = props["policy_tier"]
                if props.get("exception") is not None:
                    row["exception"] = props["exception"]
            if tool.startswith("g1-"):
                try:
                    row["dependency"], row["fields"] = dependency_fields(props, catalog)
                except ValueError as exc:
                    problems.append(f"{result['_vibesec_position']}.properties：{exc}")
                    continue
                if row["dependency"]:
                    message = result.get("message")
                    if isinstance(message, dict) and isinstance(message.get("text"), str):
                        row["fields"]["description"] = message["text"]
            locations = result.get("locations") or [{}]
            region = locations[0].get("physicalLocation", {}).get("region", {})
            row["line"] = region.get("startLine")
            row["source_position"] = result["_vibesec_position"]
            rows.append(row)
    return rows, "；".join(problems) or None


def sarif_result(item):
    loc = item["location"]
    physical = {"artifactLocation": {"uri": loc["path"]}}
    if loc.get("start_line"):
        physical["region"] = {"startLine": loc["start_line"]}
    return {"ruleId": item["rule_id"], "message": {"text": item.get("description") or item["title"]},
            "fingerprints": {"vibesec/id": item["id"]}, "locations": [{"physicalLocation": physical}]}


def build(artifacts, out, commit, threat_model, *, commit_date=None):
    if not re.fullmatch("[0-9a-f]{40}", commit):
        raise ValueError("需要完整的受驗提交識別碼")
    if commit_date is None:
        commit_date = subprocess.check_output(
            ["git", "show", "-s", "--format=%cI", commit], text=True
        ).strip()
    policy, problem = load_policy(ROOT)
    if problem:
        raise ValueError(problem)
    context = load_context(policy)
    gates = _load_gates([f"{g}={out}/{g.lower()}-gate.json" for g in SOURCES], ROOT)
    mode, incomplete, config, errors, notes = _read_settings(ROOT, None)
    verdict = enforce(gates, mode=mode, incomplete_blocking_gates=incomplete, errors=errors, notes=notes)
    stamp = now()
    findings, gaps = {}, []
    runs = defaultdict(list)
    reviewed_ids = {}
    failed_tools = set()
    validator = _finding_validator()
    catalog = known_cves()
    for gate, sources in SOURCES.items():
        counts = Counter()
        gate_result = gates[gate]
        scan_day = None
        if isinstance(gate_result, dict):
            try:
                started = datetime.fromisoformat(gate_result["started_at"])
                if started.tzinfo is None:
                    raise ValueError("缺少時區")
                scan_day = started.astimezone(timezone.utc).date()
            except (TypeError, ValueError):
                gaps.append(f"{gate} 無法從開始時間確認政策例外適用日期")
        project = policy.for_project(ROOT, today=scan_day)
        for job, tool, filename in sources:
            ref = f"vibesec-{job}-reports/{filename}"
            path = artifacts / ref
            try:
                rows, issue = read_source(path, tool, context, project, catalog)
                runs.setdefault(tool, [])
                if issue:
                    failed_tools.add(tool)
                    gaps.append(f"{gate} {tool} {ref}：{issue}")
                if not rows:
                    continue
                digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
                for row in rows:
                    rule = row["rule_id"]
                    loc = {"kind": "dependency" if gate == "G1" else "code",
                           "path": row["location"], "start_line": row.get("line"), "commit": commit, **row.get("dependency", {})}
                    evidence = {"kind": "tool_output", "ref": ref, "digest": digest}
                    evidence["note"] = f"來源政策等級：{row['policy_tier']}"
                    if "source_position" in row:
                        evidence["note"] += f"，位置：{row['source_position']}"
                    item = finding(gate=gate, rule_id=rule, title=rule, policy_tier=row["policy_tier"],
                                   evidence_grade="E1", sources={"tool": tool, "tool_version": None},
                                   location=loc, commit=commit, created_at=stamp, id_date=commit_date, evidence_refs=[evidence],
                                   exception=row.get("exception"), **row.get("fields", {}))
                    try:
                        validator.validate(item)
                    except ValidationError as exc:
                        failed_tools.add(tool)
                        position = row.get("source_position", "")
                        gaps.append(f"{gate} {tool} {ref} {position}：發現欄位格式錯誤（{exc.json_path}）")
                        continue
                    counts[item["policy_tier"]] += 1
                    previous = findings.setdefault(item["id"], item)
                    if previous is not item:
                        if previous["policy_tier"] != item["policy_tier"] or previous["gate"] != gate:
                            failed_tools.add(tool)
                            position = row.get("source_position", "")
                            gaps.append(f"{gate} {tool} {ref} {position}：相同發現識別碼有相衝突的判定")
                            continue
                        if evidence not in previous["evidence_refs"]:
                            previous["evidence_refs"].append(evidence)
                    runs[tool].append(sarif_result(item))
            except (OSError, ValueError, AttributeError, KeyError, TypeError, ValidationError, IndexError) as exc:
                failed_tools.add(tool)
                runs.setdefault(tool, [])
                gaps.append(f"{gate} {ref}：證據無法驗收（{type(exc).__name__}）")
        if gate == "G4":
            static_by_rule = defaultdict(list)
            for candidate in findings.values():
                if candidate["gate"] == gate:
                    static_by_rule[candidate["rule_id"]].append((candidate["location"], candidate["id"]))
            ref = "vibesec-g4-reports/g4-review-findings.json"
            try:
                review = json.loads((artifacts / ref).read_text())
                rows = finding_items(review)
                trust = review["trust_problems"]
                if not isinstance(trust, list) or "record" not in review:
                    raise ValueError("審查明細缺少紀錄或信任資訊")
            except (OSError, ValueError, KeyError, TypeError) as exc:
                gaps.append(f"G4 {ref}：審查明細無法驗收（{type(exc).__name__}）")
                rows = []
            for index, raw in enumerate(rows):
                try:
                    f = effective_review_finding(raw, trust)
                    item = finding(gate=gate, rule_id=f["rule_id"], title=f["title"],
                                   evidence_grade=f["evidence_grade"], policy_tier=f["policy_tier"],
                                   sources={"tool": "g4-review", "tool_version": None}, created_at=stamp, location=f.get("location"),
                                   validation_status=f["validation_status"],
                                   review={"opinions": f["opinions"], "ruling_ref": f.get("ruling_ref"),
                                           "requires_human": f["requires_human"], "human_decision": f.get("human_decision")},
                                   evidence_refs=[{"kind": "model_review", "ref": ref, "note": review["record"]}])
                    item["evidence_refs"][0]["note"] = f"{review['record']}；來源政策等級：{f['policy_tier']}"
                    item["evidence_refs"].extend(f.get("evidence_refs", []))
                    item["id"] = f["id"]
                    validator.validate(item)
                    # 舊報告以觀測日產生 ID。以相同規則、位置與提交重算，
                    # 確認對應後保留已被人工裁決引用的識別碼。
                    prior_id = item["id"]
                    if prior_id not in findings:
                        day = item["id"].split("-")[1]
                        legacy_day = f"{day[:4]}-{day[4:6]}-{day[6:]}T00:00:00Z"
                        matches = []
                        for loc, static_id in static_by_rule.get(f["rule_id"], []):
                            if _finding_id(f["rule_id"], loc["path"], loc["start_line"], commit, legacy_day) == prior_id:
                                matches.append(reviewed_ids.get(static_id, static_id))
                        if len(matches) > 1:
                            raise ValueError("舊審查識別碼對應多筆靜態發現")
                        if matches:
                            prior_id, = matches
                    prior = findings.get(prior_id)
                    if prior is None:
                        findings[item["id"]] = item
                        loc = item.get("location") or {}
                        if loc.get("kind") == "code" and loc.get("path"):
                            runs["g4-review"].append(sarif_result(item))
                    else:
                        if prior["gate"] != gate or prior["rule_id"] != item["rule_id"]:
                            raise ValueError("審查識別碼與其他發現衝突")
                        # 同一筆發現可同時有靜態證據與人工審查，保留兩種來源。
                        if prior.get("review"):
                            raise ValueError("同一筆靜態發現有多筆審查紀錄")
                        if prior_id != item["id"]:
                            del findings[prior_id]
                            reviewed_ids[prior_id] = item["id"]
                            prior["id"] = item["id"]
                            findings[item["id"]] = prior
                        prior["evidence_refs"].extend(item["evidence_refs"])
                        if (item.get("location") or {}).get("kind") in ("architecture", "prompt"):
                            prior["location"] = item["location"]
                        if item["policy_tier"] == "blocking" and f["validation_status"] != "refuted":
                            prior["policy_tier"] = "blocking"
                        prior.update({k: item[k] for k in ("review", "validation_status", "evidence_grade")})

                    if f["validation_status"] != "refuted":
                        counts[f["policy_tier"]] += 1
                except (ValueError, KeyError, TypeError, AttributeError, ValidationError) as exc:
                    failed_tools.add("g4-review")
                    gaps.append(f"G4 {ref} findings[{index}]：審查明細無法驗收（{type(exc).__name__}）")
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
    for results in runs.values():
        for result in results:
            fid = result["fingerprints"]["vibesec/id"]
            result["fingerprints"]["vibesec/id"] = reviewed_ids.get(fid, fid)
            merged = findings[reviewed_ids.get(fid, fid)]
            result["properties"] = {"vibesec/policy_tier": merged["policy_tier"],
                                    "vibesec/validation_status": merged["validation_status"]}
            if merged["gate"] == "G1" and merged["location"].get("package"):
                result["properties"].update({"vibesec/" + k: merged[k] for k in
                                            ("cve", "kev", "kev_date", "cvss_version", "cvss_vector", "cvss_score")
                                            if merged[k] is not None})
                result["properties"]["vibesec/package"] = merged["location"]["package"]
                result["properties"]["vibesec/version"] = merged["location"]["version"]
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
    parser.add_argument("--commit-date", help="離線彙整時提供受驗 Git 提交的 ISO 8601 時間（含時區）")
    args = parser.parse_args()
    raise SystemExit(build(args.artifacts, args.out, args.commit, args.threat_model, commit_date=args.commit_date))
