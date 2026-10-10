#!/usr/bin/env python3
"""G0 威脅建模（本機／harness 版）— 威脅模型的確定性檢查；可用 --target 檢查其他專案的模型。

docs/01「自動化作法」的確定性部分（G0 本身是人工活動；簽核與遺漏威脅的判斷仍屬人工／LLM 審查）：
  1. 威脅模型存在、通過 schemas/threat-model.schema.json，且不是範本（docs/templates/、system.name: example-project）
  2. 致命三要素：scripts/g0_trifecta.py（mitigation 須有可驗證證據；證據檔在被檢查專案內核對，tier 取自本 repo 政策）
  3. risk_tier：宣告值不得低於 docs/01 §4 決策樹的推導值；目標是本 repo 時另須與 vibesec.yaml 的 risk_tier 一致
閘門狀態（docs/01「阻擋政策」）：模型缺失／不符 schema／是範本 → incomplete；三要素未切斷、risk_tier 不一致或低於推導值
→ fail；否則 pass。

--target <dir>：被檢查的 git repo 根目錄（預設本 repo）。威脅模型依序取：--threat-model 指定的檔案（操作者提供，
  可放在目標之外）→ 目標 vibesec.yaml 的 project.threat_model → 目標的 docs/threat-model.yaml。
  模型與證據檔一律從目標「追蹤中檔案」的暫存副本讀（不跟隨 symlink）：否則目標可把證據檔 symlink 到操作者本機的
  Claude Code 設定，讓 mitigation 看似已落實。外部專案沒有可對照的 vibesec.yaml，只檢查「不低於推導值」；
  G1–G4 仍以本 repo vibesec.yaml 的 risk_tier 計算 tier（tier_overrides 只升不降，結果偏嚴），差異寫進 status_reason。

用法：python3 scripts/g0_threat_model.py [--target <dir>] [--threat-model <file>] [--out-dir reports/raw/G0]
                                         [--gate reports/gates/G0.json]
      python3 scripts/g0_threat_model.py selftest
退出碼：0 pass；1 fail（有 blocking 發現或 risk_tier 不符）；2 incomplete。
"""
from __future__ import annotations
import argparse, datetime, json, pathlib, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import sarif_gate  # noqa: E402  缺 PyYAML 時以 exit 2 結束（無法判定，不視為通過）
from g0_trifecta import trifecta_findings  # noqa: E402
from g3_sast import copy_tracked, _git  # noqa: E402  同一份「追蹤中檔案、不跟隨 symlink」的副本

ORDER = {"L1": 1, "L2": 2, "L3": 3}
DEFAULT_MODEL = "docs/threat-model.yaml"


def derive_tier(tm: dict, contains_llm: bool) -> tuple[str, str]:
    """docs/01 §4 風險分級決策樹 → (推導值, 推導路徑)。"""
    sysm = tm.get("system") or {}
    exp, ds = sysm.get("exposure"), sysm.get("data_sensitivity")
    agents = tm.get("agents") or []
    if exp == "internal" and ds in ("none", "business") and not agents and not contains_llm:
        return "L1", f"exposure internal、data_sensitivity {ds}、無 agent、不含 LLM"
    if ds in ("pii", "sensitive_pii_or_secrets"):
        risky = [a.get("id") for a in agents if a.get("can_communicate_externally") is True and a.get("high_impact_tools")]
        if exp in ("partner", "public") and risky:
            return "L3", f"exposure {exp}、data_sensitivity {ds}、agent {'、'.join(map(str, risky))} 可對外通訊且有高影響工具"
        return "L2", f"data_sensitivity {ds}，但未同時具備對外暴露與可對外通訊、有高影響工具的 agent"
    return "L2", f"exposure {exp}、data_sensitivity {ds}（對外或處理業務資料的一般應用）"


def _model_contains_llm(tm: dict) -> bool:
    """外部專案沒有本 repo 的 project.contains_llm：模型有 agent 或 llm／agent 元件即視為含 LLM（從嚴）。"""
    return bool(tm.get("agents")) or any((c or {}).get("kind") in ("llm", "agent") for c in tm.get("components") or [])


def _safe_rel(rel: str) -> pathlib.PurePosixPath | None:
    p = pathlib.PurePosixPath(str(rel or ""))
    return None if not str(p) or p.is_absolute() or ".." in p.parts else p


def locate_model(copy: pathlib.Path, explicit: pathlib.Path | None, external: bool) -> tuple[pathlib.Path | None, str, str | None]:
    """回傳 (模型檔, 顯示用路徑, 找不到時的理由)。"""
    if explicit is not None:
        return (explicit, str(explicit), None) if explicit.is_file() else (None, str(explicit), f"--threat-model {explicit} 不存在")
    tried = []
    vb = copy / "vibesec.yaml"
    if vb.is_file():
        try:
            rel = ((sarif_gate._yaml(vb).get("project") or {}).get("threat_model") or "").strip()
        except Exception:
            rel = ""
        if rel:
            safe = _safe_rel(rel)
            if safe is None:
                return None, rel, f"vibesec.yaml 的 project.threat_model 路徑不安全（{rel}）"
            tried.append(str(safe))
            if (copy / safe).is_file():
                return copy / safe, str(safe), None
    if external and DEFAULT_MODEL not in tried:
        tried.append(DEFAULT_MODEL)
        if (copy / DEFAULT_MODEL).is_file():
            return copy / DEFAULT_MODEL, DEFAULT_MODEL, None
    return None, "", "threat model missing（找過：" + ("、".join(tried) or "vibesec.yaml project.threat_model 未設定") + "）"


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def check(target: pathlib.Path, out_dir: pathlib.Path, threat_model: pathlib.Path | None = None,
          vibesec: dict | None = None) -> dict:
    """檢查目標專案的威脅模型並回傳 G0 gate JSON（schemas/gate-result.schema.json）。vibesec：測試用的 vibesec.yaml 內容。"""
    started = _now()
    target, out_dir = target.resolve(), out_dir.resolve()
    explicit = threat_model.resolve() if threat_model else None
    external = target != ROOT.resolve()
    vb = vibesec if vibesec is not None else sarif_gate._yaml(ROOT / "vibesec.yaml")
    mode, policy_tier = vb.get("mode", "shadow"), vb.get("risk_tier", "L2")
    out_dir.mkdir(parents=True, exist_ok=True)
    findings_ref = out_dir / "g0-findings.json"
    findings_ref.unlink(missing_ok=True)       # 不讓上一次的輸出被當成這次的結果
    gate = {"gate": "G0", "status": "incomplete", "status_reason": None, "mode": mode, "risk_tier": policy_tier,
            "scope": "full", "diff_base": None, "commit": None, "started_at": started, "finished_at": None,
            "tools": [{"name": "vibesec-g0", "version": None, "state": "ran", "exit_code": None,
                       "output_ref": str(findings_ref), "duration_seconds": None}],
            "findings_count": {"blocking": 0, "advisory": 0},
            "coverage": [{"control_id": "VS-G0-LETHAL-TRIFECTA", "state": "untested", "reason": None},
                         {"control_id": "VS-G0-RISK-TIER", "state": "untested", "reason": None}]}
    cov = {c["control_id"]: c for c in gate["coverage"]}
    reasons: list[str] = []

    def done(status: str) -> dict:
        for c in gate["coverage"]:
            if c["state"] == "untested" and not c["reason"]:
                c["reason"] = reasons[0] if reasons else None
        gate.update(status=status, status_reason="；".join(reasons) or None, finished_at=_now())
        return gate

    top = _git(target, "rev-parse", "--show-toplevel")
    if top is None or pathlib.Path(top).resolve() != target:
        gate["tools"][0]["state"] = "error"
        reasons.append(f"目標不是 git repo（{target}）" if top is None else f"--target 必須是 git repo 根目錄（{top}）")
        return done("incomplete")
    gate["commit"] = _git(target, "rev-parse", "HEAD")
    with tempfile.TemporaryDirectory(prefix="vibesec-g0-") as tmp:
        copy = pathlib.Path(tmp) / "vibesec-target"
        copy.mkdir()
        copy_tracked(target, copy)
        path, shown, missing = locate_model(copy, explicit, external)
        if path is None:
            reasons.append(missing)
            return done("incomplete")
        try:
            tm = sarif_gate._yaml(path)
        except Exception as e:
            reasons.append(f"{shown} 無法解析（{type(e).__name__}）")
            return done("incomplete")
        try:
            from jsonschema import Draft202012Validator
        except ImportError:   # 工具缺席 → incomplete（不讓 ImportError 以 exit 1 被當成 fail）
            gate["tools"][0]["state"] = "missing"
            reasons.append("工具缺席：jsonschema，無法驗證威脅模型是否符合 schema（incomplete ≠ pass）")
            return done("incomplete")
        schema = json.loads((ROOT / "schemas/threat-model.schema.json").read_text(encoding="utf-8"))
        errs = sorted(Draft202012Validator(schema).iter_errors(tm), key=str)
        if errs:
            reasons.append(f"{shown} 不符 threat-model schema：{errs[0].message} @ {'/'.join(map(str, errs[0].path)) or '(root)'}"
                           + (f"（共 {len(errs)} 處）" if len(errs) > 1 else ""))
            return done("incomplete")
        if "docs/templates/" in shown or (tm.get("system") or {}).get("name") == "example-project":
            reasons.append(f"{shown} 仍是範本（docs/templates/ 或 system.name: example-project）：G0 需要描述被檢查系統的模型")
            return done("incomplete")
        # 三要素：證據檔在被檢查專案（副本）內核對；--threat-model 指向目標之外時，證據仍以目標為準
        findings = trifecta_findings(tm, copy)
    blocking = [f for f in findings if f["policy_tier"] == "blocking"]
    gate["findings_count"] = {"blocking": len(blocking), "advisory": len(findings) - len(blocking)}
    cov["VS-G0-LETHAL-TRIFECTA"]["state"] = "fail" if blocking else "pass"
    if blocking:
        reasons.append("致命三要素未切斷：" + "、".join(str(f["agent"]) for f in blocking))

    declared = tm["risk_tier"]
    contains_llm = bool((vb.get("project") or {}).get("contains_llm")) if not external else _model_contains_llm(tm)
    derived, why = derive_tier(tm, contains_llm)
    tier_fail = []
    if ORDER[declared] < ORDER[derived]:
        tier_fail.append(f"宣告 {declared} 低於決策樹推導值 {derived}（{why}）")
    if not external and declared != policy_tier:
        tier_fail.append(f"威脅模型 {declared} 與 vibesec.yaml {policy_tier} 不一致")
    cov["VS-G0-RISK-TIER"].update(state="fail" if tier_fail else "pass", reason="；".join(tier_fail) or None)
    reasons += [f"risk_tier：{x}" for x in tier_fail]
    if external and declared != policy_tier:
        reasons.append(f"目標模型宣告 risk_tier {declared}；G1–G4 以本 repo vibesec.yaml 的 {policy_tier} 計算 tier"
                       "（tier_overrides 只升不降，結果偏嚴）")
    findings_ref.write_text(json.dumps({"gate": "G0", "threat_model": shown, "risk_tier": {
        "declared": declared, "derived": derived, "derivation": why, "policy": policy_tier}, "findings": findings},
        ensure_ascii=False, indent=2), encoding="utf-8")
    return done("fail" if blocking or tier_fail else "pass")


# ------------------------------------------------------------------ selftest
def selftest() -> list[str]:
    import yaml, subprocess
    from jsonschema import Draft202012Validator
    fails: list[str] = []
    schema = Draft202012Validator(json.loads((ROOT / "schemas/gate-result.schema.json").read_text(encoding="utf-8")))
    template = sarif_gate._yaml(ROOT / "docs/templates/threat-model.yaml")

    # 決策樹（docs/01 §4）
    tm = lambda exp, ds, agents=(), comps=(): {"system": {"exposure": exp, "data_sensitivity": ds},
                                               "agents": list(agents), "components": list(comps)}
    risky = {"id": "a", "can_communicate_externally": True, "high_impact_tools": ["merge"]}
    for case, llm, want in [(tm("internal", "business"), False, "L1"), (tm("internal", "business"), True, "L2"),
                            (tm("internal", "none", [{"id": "a"}]), False, "L2"), (tm("public", "business"), False, "L2"),
                            (tm("public", "pii"), True, "L2"), (tm("public", "pii", [risky]), True, "L3"),
                            (tm("internal", "sensitive_pii_or_secrets", [risky]), True, "L2"),
                            (tm("partner", "sensitive_pii_or_secrets", [risky]), True, "L3")]:
        if derive_tier(case, llm)[0] != want:
            fails.append(f"決策樹 {case['system']}、agents={len(case['agents'])}、llm={llm} 應推導為 {want}")

    git = lambda d, *a: subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *a], cwd=d,
                                       capture_output=True, check=True, text=True)

    def run(target, out, **kw):
        g = check(target, out, **kw)
        errs = list(schema.iter_errors(g))
        if errs:
            fails.append(f"gate JSON 不符 schema：{errs[0].message}")
        return g

    with tempfile.TemporaryDirectory() as d:
        D = pathlib.Path(d)
        repo, out, outside = D / "proj", D / "out", D / "outside"
        repo.mkdir(); outside.mkdir()
        (repo / "README.md").write_text("x\n")
        git(repo, "init", "-q"); git(repo, "add", "-A"); git(repo, "commit", "-qm", "c0")

        def commit_model(model, path=DEFAULT_MODEL):
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            (repo / path).write_text(yaml.safe_dump(model, allow_unicode=True), encoding="utf-8")
            git(repo, "add", "-A"); git(repo, "commit", "-qm", "model")

        g = run(repo, out)
        if g["status"] != "incomplete" or "threat model missing" not in (g["status_reason"] or ""):
            fails.append(f"外部專案沒有威脅模型 → incomplete、threat model missing（得到 {g['status']}：{g['status_reason']}）")
        commit_model(template)
        g = run(repo, out)
        if g["status"] != "incomplete" or "範本" not in (g["status_reason"] or ""):
            fails.append("模型仍是範本 → incomplete")
        good = dict(template, system=dict(template["system"], name="proj"))
        (repo / ".claude").mkdir()                # 範本的 egress_allowlist 證據（docs/01 §5：切腳也要可驗證）
        (repo / ".claude/settings.json").write_text(json.dumps({"permissions": {"deny": ["WebFetch"]}}))
        commit_model(good)
        g = run(repo, out)
        head = git(repo, "rev-parse", "HEAD").stdout.strip()
        if g["status"] != "pass" or g["commit"] != head:
            fails.append(f"合規的模型（已切腳、L2 = 推導值）→ pass，commit 取目標 HEAD（得到 {g['status']}：{g['status_reason']}）")
        if "G1–G4 以本 repo" not in (g["status_reason"] or ""):
            fails.append("外部模型的 risk_tier 與本 repo 不同 → status_reason 註明 G1–G4 的 tier 來源")
        commit_model(dict(good, risk_tier="L1"))
        g = run(repo, out)
        rt = next(c for c in g["coverage"] if c["control_id"] == "VS-G0-RISK-TIER")
        if g["status"] != "fail" or rt["state"] != "fail" or "推導值 L2" not in (g["status_reason"] or ""):
            fails.append("宣告 L1 但決策樹推導 L2 → fail（附推導路徑）")
        saved = sys.modules.get("jsonschema")
        sys.modules["jsonschema"] = None          # 模擬 jsonschema 未安裝（import 會拋 ImportError）
        try:
            g = check(repo, out)
        except Exception as e:
            g = {"status": f"例外 {type(e).__name__}", "tools": [{}], "status_reason": None}
        finally:
            sys.modules["jsonschema"] = saved
        if g["status"] != "incomplete" or g["tools"][0].get("state") != "missing" or "jsonschema" not in (g["status_reason"] or ""):
            fails.append(f"缺 jsonschema → incomplete（tools state missing），不是例外或 fail（得到 {g['status']}）")
        commit_model({"system": {"name": "proj"}})
        g = run(repo, out)
        if g["status"] != "incomplete" or "schema" not in (g["status_reason"] or ""):
            fails.append("不符 schema → incomplete")
        # 三要素未切斷：證據檔是指向目標之外的 symlink（例如操作者本機的 Claude Code 設定）→ 不採信；目標的政策檔不得降級
        (outside / "settings.json").write_text(json.dumps({"permissions": {"ask": ["mcp__x__merge"]}}))
        (repo / ".claude/settings.json").unlink()
        (repo / ".claude/settings.json").symlink_to(outside / "settings.json")
        (repo / "config/policy").mkdir(parents=True)
        (repo / "config/policy/blocking-policy.yaml").write_text(
            "version: 1\ndefault_tier: advisory\nblocking: []\nadvisory: [{rule_id: vibesec.g0.lethal-trifecta-open}]\n")
        agent = dict(good["agents"][0], trifecta_leg_cut=None, mitigations=["tool_allowlist"],
                     mitigation_evidence={"tool_allowlist": [{"kind": "claude_permission", "ref": ".claude/settings.json",
                                                               "rules": ["mcp__x__merge"]}]})
        commit_model(dict(good, agents=[agent]))
        g = run(repo, out)
        if g["status"] != "fail" or g["findings_count"]["blocking"] != 1:
            fails.append(f"證據檔 symlink 到目標之外不採信；tier 取本 repo 政策 → blocking、fail（得到 {g['status']}，{g['findings_count']}）")
        # 證據是目標內真正追蹤的檔案 → mitigation 成立
        (repo / ".claude/settings.json").unlink()
        (repo / ".claude/settings.json").write_text(json.dumps({"permissions": {"ask": ["mcp__x__merge"]}}))
        git(repo, "add", "-A"); git(repo, "commit", "-qm", "real evidence")
        g = run(repo, out)
        if g["status"] != "pass":
            fails.append(f"證據檔是目標追蹤中的檔案 → mitigation 成立、pass（得到 {g['status']}：{g['status_reason']}）")
        # --threat-model 指向目標之外的檔案；目標 vibesec.yaml 的路徑不得跳出目標
        ext = D / "beta-threat-model.yaml"
        ext.write_text(yaml.safe_dump(dict(good, risk_tier="L1"), allow_unicode=True), encoding="utf-8")
        g = run(repo, out, threat_model=ext)
        if g["status"] != "fail" or str(ext) not in json.loads((out / "g0-findings.json").read_text())["threat_model"]:
            fails.append("--threat-model 指定的檔案優先（可放在目標之外）")
        (repo / "vibesec.yaml").write_text("project:\n  threat_model: ../outside/settings.json\n")
        git(repo, "add", "-A"); git(repo, "commit", "-qm", "escape")
        g = run(repo, out)
        if g["status"] != "incomplete" or "不安全" not in (g["status_reason"] or ""):
            fails.append("目標 vibesec.yaml 的 project.threat_model 跳出目標 → incomplete")
        g = run(repo / ".claude", out)
        if g["status"] != "incomplete" or "根目錄" not in (g["status_reason"] or ""):
            fails.append("--target 不是 repo 根目錄 → incomplete")
        if git(repo, "status", "--porcelain").stdout.strip():
            fails.append("檢查不得改動被測專案的工作目錄")
    with tempfile.TemporaryDirectory() as d:
        g = run(ROOT, pathlib.Path(d))
        if g["status"] != "pass":
            fails.append(f"本 repo 的威脅模型 → pass（得到 {g['status']}：{g['status_reason']}）")
        vb = dict(sarif_gate._yaml(ROOT / "vibesec.yaml"), risk_tier="L2")
        g = run(ROOT, pathlib.Path(d), vibesec=vb)
        if g["status"] != "fail" or "不一致" not in (g["status_reason"] or ""):
            fails.append("本 repo：威脅模型與 vibesec.yaml 的 risk_tier 不一致 → fail")
    return fails


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["selftest"]:
        fails = selftest()
        for f in fails:
            print(f"FAIL {f}")
        print("selftest " + ("通過" if not fails else f"失敗 {len(fails)} 項"))
        return 1 if fails else 0
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--target", default=str(ROOT), help="被檢查的 git repo 根目錄（預設本 repo）")
    ap.add_argument("--threat-model", help="威脅模型檔（優先於目標的 vibesec.yaml 與 docs/threat-model.yaml）")
    ap.add_argument("--out-dir", default="reports/raw/G0", help="g0-findings.json 的輸出目錄")
    ap.add_argument("--gate", default="reports/gates/G0.json", help="G0 gate JSON 輸出路徑")
    a = ap.parse_args(argv)
    target = pathlib.Path(a.target).expanduser()
    g = check(target, pathlib.Path(a.out_dir), pathlib.Path(a.threat_model).expanduser() if a.threat_model else None)
    pathlib.Path(a.gate).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(a.gate).write_text(json.dumps(g, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"G0 {g['status']}（{target.resolve()}）：blocking={g['findings_count']['blocking']}"
          + (f"；{g['status_reason']}" if g["status_reason"] else ""))
    return {"pass": 0, "fail": 1}.get(g["status"], 2)


if __name__ == "__main__":
    sys.exit(main())
