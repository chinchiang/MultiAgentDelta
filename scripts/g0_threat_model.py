#!/usr/bin/env python3
"""G0 威脅建模（本機／harness 版）— 威脅模型的確定性檢查；可用 --target 檢查其他專案的模型。

docs/01「自動化作法」的確定性部分（G0 本身是人工活動；簽核與遺漏威脅的判斷仍屬人工／LLM 審查）：
  1. 威脅模型存在、通過 schemas/threat-model.schema.json，且不是範本（docs/templates/、system.name: example-project）
  2. 致命三要素：scripts/g0_trifecta.py（mitigation 須有可驗證證據；證據檔在被檢查專案內核對，tier 取自本 repo 政策）
  3. risk_tier：宣告值不得低於 docs/01 §4 決策樹的推導值；目標是本 repo 時另須與 vibesec.yaml 的 risk_tier 一致
  4. 覆蓋對照（coverage_findings）：threats[].gate 指向的閘門須在 vibesec.yaml enabled: true（vibesec.g0.threat-gate-disabled）；
     含 LLM 但模型的 system.methodologies（目標是本 repo 時另看 vibesec.yaml gates.g0_threat_model.methodologies）
     沒有 MAESTRO（vibesec.g0.maestro-missing）；exposure public 但 threats[] 為空（vibesec.g0.threats-empty-public）。
     tier 一律由本 repo 的 blocking-policy 決定（政策未列的 vibesec.* 規則 → advisory，scripts/vibesec_policy.py）。
閘門狀態（docs/01「阻擋政策」）：模型缺失／不符 schema／是範本 → incomplete；三要素未切斷、risk_tier 不一致或低於推導值、
其他 blocking 發現 → fail；否則 pass（advisory 發現只計數、寫進 g0-findings.json，不擋）。

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
import argparse, json, pathlib, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import sarif_gate  # noqa: E402  缺 PyYAML 時以 exit 2 結束（無法判定，不視為通過）
from g0_trifecta import policy_notes, trifecta_findings  # noqa: E402
from vibesec_policy import load_policy  # noqa: E402  tier 的唯一來源
from g3_sast import copy_tracked, _git  # noqa: E402  同一份「追蹤中檔案、不跟隨 symlink」的副本
from gate_result import GateRun  # noqa: E402  閘門結果的外層欄位、tool 列與時間戳（#181）

CONTROLS = ["VS-G0-LETHAL-TRIFECTA", "VS-G0-RISK-TIER"]

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


COVERAGE_RULES = ("vibesec.g0.threat-gate-disabled", "vibesec.g0.maestro-missing", "vibesec.g0.threats-empty-public")


def coverage_findings(tm: dict, vb: dict, contains_llm: bool, external: bool = False, *, policy: "Policy") -> list[dict]:
    """docs/01「自動化作法」第 4 項與「阻擋政策」的覆蓋對照 → 發現（格式同 trifecta_findings）。
    vb：本 repo 的 vibesec.yaml（G1–G6 以它執行，外部專案也以它判斷閘門是否啟用）；external 時不看它的 methodologies
    （外部專案沒有可對照的 vibesec.yaml）。policy：本 repo 的 Policy（tier 只取本 repo 的政策，不讀被檢查專案的政策檔）。"""
    out, gates = [], (vb.get("gates") or {})
    mk = lambda rule, reason, **kw: {"rule_id": rule, "control_id": "ASVS5-V15.1", "policy_tier": policy.tier(rule), **kw, "reason": reason}
    for t in tm.get("threats") or []:
        g = (t or {}).get("gate")
        if not g:
            continue        # gate: null = 不由執行閘門驗證（接受／轉移的風險），非本檢查範圍
        key = next((k for k in gates if k.split("_")[0] == str(g).lower()), None)
        if key is None or (gates.get(key) or {}).get("enabled") is not True:
            out.append(mk(COVERAGE_RULES[0], f"threat {t.get('id')!r} 由 {g} 驗證，但 vibesec.yaml 的 "
                          + (f"gates.{key}.enabled 不是 true" if key else f"gates 沒有 {g}") + "：這條威脅實際上沒有閘門把關",
                          threat=t.get("id")))
    if contains_llm:
        lacking = [] if "MAESTRO" in ((tm.get("system") or {}).get("methodologies") or []) else ["威脅模型 system.methodologies"]
        if not external and "MAESTRO" not in ((gates.get("g0_threat_model") or {}).get("methodologies") or []):
            lacking.append("vibesec.yaml gates.g0_threat_model.methodologies")
        if lacking:
            out.append(mk(COVERAGE_RULES[1], "系統含 LLM，但" + "、".join(lacking) + " 沒有 MAESTRO：Agent／模型層的威脅（MAESTRO-L1–L7）未被系統性列舉"))
    if (tm.get("system") or {}).get("exposure") == "public" and not tm.get("threats"):
        out.append(mk(COVERAGE_RULES[2], "system.exposure 為 public，但 threats[] 為空：至少列 STRIDE 六類各一"))
    return out


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


def check(target: pathlib.Path, out_dir: pathlib.Path, threat_model: pathlib.Path | None = None,
          vibesec: dict | None = None, policy_root: pathlib.Path = ROOT, project_root=None) -> dict:
    """檢查目標專案的威脅模型並回傳 G0 gate JSON（schemas/gate-result.schema.json）。vibesec：測試用的 vibesec.yaml 內容。
    policy_root、project_root：測試用，交給 Policy（政策取自 policy_root；預設本 repo，且不讀 VIBESEC_PROJECT_ROOT）。"""
    target, out_dir = target.resolve(), out_dir.resolve()
    explicit = threat_model.resolve() if threat_model else None
    # G0 只認 ROOT 是本 repo（不讀 VIBESEC_PROJECT_ROOT）：G0 不在 CI 執行，判定程式與受驗樹不會分開。
    # G0 進 CI、判定程式與受驗樹分開時，改認 VIBESEC_PROJECT_ROOT，並重新判斷 external 的其他用途（docs/adr/0001）
    external = target != ROOT.resolve()
    vb = vibesec if vibesec is not None else sarif_gate._yaml(ROOT / "vibesec.yaml")
    mode, policy_tier = vb.get("mode", "shadow"), vb.get("risk_tier", "L2")
    out_dir.mkdir(parents=True, exist_ok=True)
    findings_ref = out_dir / "g0-findings.json"
    findings_ref.unlink(missing_ok=True)       # 不讓上一次的輸出被當成這次的結果
    # 閘門結果由 GateRun 產出（#181）：外層欄位、tool 列、時間戳只有 gate_result 一份寫法；狀態仍由 gate_verdict 判定
    run = GateRun("G0", controls=CONTROLS, mode=mode, scope="full", risk_tier=policy_tier)
    cov = {c: {"state": "untested", "reason": None} for c in CONTROLS}
    st8 = {"tool": "ran", "blocking": 0, "advisory": 0}
    reasons: list[str] = []

    def done(status: str, tier_fail: bool = False) -> dict:
        """status 只區分兩種收尾：incomplete（提早結束，reasons 是未完成原因）與完成（reasons 是附註）；
        實際狀態由 gate_verdict.verdict 判定（GateRun.result）。tier_fail（risk_tier 宣告低於推導值或與 vibesec.yaml
        不一致）不是發現、卻要讓 G0 fail：維持既有行為，以 GateRun.fail_condition 交給 verdict（findings_count 不計入；
        改成正式規則須另開政策 PR，CLAUDE.md 規則 1）。"""
        run.tool("vibesec-g0", st8["tool"], output_ref=str(findings_ref))
        for cid, c in cov.items():
            run.cover(cid, c["state"], c["reason"] if c["state"] != "untested" or c["reason"] else (reasons[0] if reasons else None))
        run.count(blocking=st8["blocking"], advisory=st8["advisory"])
        if tier_fail:
            run.fail_condition()
        for x in reasons:
            (run.problem if status == "incomplete" else run.note)(x)
        return run.result()

    policy, problem = load_policy(policy_root, project_root=project_root)   # 只建立一次；讀不到 → incomplete，不判定任何發現
    if problem:   # 控制全部 untested（原因＝problem）、tool 列只有 vibesec-g0 一列 error
        return run.unreadable(problem, tool_name="vibesec-g0")
    top = _git(target, "rev-parse", "--show-toplevel")
    if top is None or pathlib.Path(top).resolve() != target:
        st8["tool"] = "error"
        reasons.append(f"目標不是 git repo（{target}）" if top is None else f"--target 必須是 git repo 根目錄（{top}）")
        return done("incomplete")
    run.commit = _git(target, "rev-parse", "HEAD")
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
            st8["tool"] = "missing"
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
        # blocking-policy 例外只核准給本 repo：外部專案不套用
        try:
            tm_rel = None if external else path.resolve().relative_to(copy.resolve()).as_posix()
        except ValueError:
            tm_rel = None
        # 政策例外綁定受驗樹本身（target），不綁暫存副本 copy：副本一定是外部專案，本 repo 的例外會全部失效
        project = policy.for_project(target)
        findings = trifecta_findings(tm, copy, tm_rel, project=project)
    open_agents = [f for f in findings if f["policy_tier"] == "blocking"]
    for f in findings:
        if f.get("exception"):   # 已接受風險：照實寫進 status_reason，不讓它看起來像「已切斷」
            reasons.append(f"致命三要素未切斷：{f['agent']}（依 blocking-policy 例外降為 advisory，核准 {f['exception']['approved_by']}、"
                           f"到期 {f['exception']['expires']}）")
    reasons += policy_notes(findings, tm_rel, project)   # 命中筆數、忽略與缺 agent_id 的例外（各閘門相同的文字；外部專案 → 無）
    cov["VS-G0-LETHAL-TRIFECTA"]["state"] = "fail" if open_agents else "pass"
    if open_agents:
        reasons.append("致命三要素未切斷：" + "、".join(str(f["agent"]) for f in open_agents))
    contains_llm = bool((vb.get("project") or {}).get("contains_llm")) if not external else _model_contains_llm(tm)
    extra = coverage_findings(tm, vb, contains_llm, external, policy=policy)
    findings += extra
    reasons += [f"{f['rule_id']}（blocking）：{f['reason']}" for f in extra if f["policy_tier"] == "blocking"]
    blocking = [f for f in findings if f["policy_tier"] == "blocking"]
    st8.update(blocking=len(blocking), advisory=len(findings) - len(blocking))

    declared = tm["risk_tier"]
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
    return done("complete", tier_fail=bool(tier_fail))


# ------------------------------------------------------------------ selftest
def selftest() -> list[str]:
    from vibesec_policy import Policy
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

    # 覆蓋對照（docs/01 自動化作法第 4 項、阻擋政策 advisory 兩列）；舊版不產生這些發現
    vb0 = sarif_gate._yaml(ROOT / "vibesec.yaml")
    gset = lambda key, **kw: dict(vb0, gates=dict(vb0["gates"], **{key: dict(vb0["gates"][key], **kw)}))
    off, nomaestro = gset("g6_ai_red_team", enabled=False), gset("g0_threat_model", methodologies=["STRIDE"])
    th = lambda g: {"id": "t1", "gate": g}
    base = {"system": {"exposure": "public", "methodologies": ["STRIDE", "MAESTRO"]}, "threats": [th("G6")]}
    sysm = lambda **kw: dict(base, system=dict(base["system"], **kw))
    for label, model, vbx, llm, ext, want in [
            ("覆蓋完整", base, vb0, True, False, set()),
            ("threat 指向停用的 G6", base, off, True, False, {"vibesec.g0.threat-gate-disabled"}),
            ("外部專案也以本 repo 的閘門設定判斷", base, off, True, True, {"vibesec.g0.threat-gate-disabled"}),
            ("gate: null 不檢查", dict(base, threats=[th(None)]), off, True, False, set()),
            ("含 LLM、模型無 MAESTRO", sysm(methodologies=["STRIDE"]), vb0, True, False, {"vibesec.g0.maestro-missing"}),
            ("含 LLM、模型未填 methodologies", dict(base, system={"exposure": "public"}), vb0, True, False, {"vibesec.g0.maestro-missing"}),
            ("含 LLM、vibesec.yaml methodologies 無 MAESTRO", base, nomaestro, True, False, {"vibesec.g0.maestro-missing"}),
            ("外部專案不看本 repo 的 methodologies", base, nomaestro, True, True, set()),
            ("不含 LLM 不要求 MAESTRO", sysm(methodologies=["STRIDE"]), nomaestro, False, False, set()),
            ("public 但 threats 為空", dict(base, threats=[]), vb0, True, False, {"vibesec.g0.threats-empty-public"}),
            ("internal 且 threats 為空", dict(base, threats=[], system=dict(base["system"], exposure="internal")), vb0, True, False, set())]:
        got = coverage_findings(model, vbx, llm, ext, policy=Policy(ROOT))
        if {f["rule_id"] for f in got} != want or any(f["policy_tier"] != "advisory" for f in got):
            fails.append(f"覆蓋對照「{label}」應得 {sorted(want) or '無發現'}（advisory），得到 {[(f['rule_id'], f['policy_tier']) for f in got]}")

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
        got = json.loads((out / "g0-findings.json").read_text())["findings"]
        if g["findings_count"] != {"blocking": 0, "advisory": 1} or [f["rule_id"] for f in got] != ["vibesec.g0.threats-empty-public"]:
            fails.append(f"範本衍生模型 exposure public、threats 為空 → advisory 一筆，仍 pass（得到 {g['findings_count']}）")
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
        (outside / "settings.json").write_text(json.dumps({"permissions": {"deny": ["mcp__x__merge"]}}))
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
        # 證據是目標內真正追蹤的檔案 → mitigation 成立（切腳的 tool_allowlist 只採信 deny；ask 是 human_in_the_loop）
        (repo / ".claude/settings.json").unlink()
        (repo / ".claude/settings.json").write_text(json.dumps({"permissions": {"deny": ["mcp__x__merge"]}}))
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
        # 本 repo：不得有 blocking；advisory 只能是 blocking-policy 核准、未過期的已接受風險（c-claude，例外到期即恢復 blocking）
        unexcepted = [f for f in json.loads((pathlib.Path(d) / "g0-findings.json").read_text())["findings"] if not f.get("exception")]
        if g["status"] != "pass" or g["findings_count"]["blocking"] or unexcepted:
            fails.append(f"本 repo 的威脅模型 → pass、除已核准例外外無發現（得到 {g['status']}，{g['findings_count']}：{g['status_reason']}）")
        g = run(ROOT, pathlib.Path(d), vibesec=gset("g4_access_control_review", enabled=False))
        if g["status"] != "pass" or g["findings_count"]["advisory"] < 1:
            fails.append(f"本 repo：G4 停用但 threats 指向 G4 → advisory（不擋），得到 {g['status']}，{g['findings_count']}")
        vb = dict(sarif_gate._yaml(ROOT / "vibesec.yaml"), risk_tier="L2")
        g = run(ROOT, pathlib.Path(d), vibesec=vb)
        if g["status"] != "fail" or "不一致" not in (g["status_reason"] or ""):
            fails.append("本 repo：威脅模型與 vibesec.yaml 的 risk_tier 不一致 → fail")
    # 例外的回報（#158）：命中 → finding.exception 固定 5 欄、status_reason 註明筆數；忽略與缺 agent_id 的例外
    # 寫進 status_reason（只列 G0 的規則），不再附加在 finding.reason。政策指向暫存檔，不依賴本 repo 現有例外的到期日
    import g0_trifecta
    from vibesec_policy import temp_policy_root
    rule = g0_trifecta.RULE
    base = {"rule_id": rule, "path_glob": "docs/threat-model.yaml", "reason": "selftest", "approved_by": "o"}
    with temp_policy_root([dict(base, agent_id="c-claude", expires="2099-01-01"),
                           dict(base, agent_id="other", expires="2020-01-01"),
                           dict(base, expires="2099-01-01"),
                           {"rule_id": "vibesec.g1.cooldown-violation", "path_glob": "x/**", "reason": "r", "approved_by": "o",
                            "expires": "2020-01-01"}]) as PR, tempfile.TemporaryDirectory() as d:
        # 暫存政策檔與受驗樹（本 repo）分開：以 project_root 指出受驗樹，與 CI 的 _trusted/ 加 workspace 同一種情況
        g = run(ROOT, pathlib.Path(d), policy_root=PR, project_root=ROOT)
        why = g["status_reason"] or ""
        fs = [f for f in json.loads((pathlib.Path(d) / "g0-findings.json").read_text())["findings"] if f["rule_id"] == rule]
        want = {"path_glob": "docs/threat-model.yaml", "reason": "selftest", "approved_by": "o", "expires": "2099-01-01", "agent_id": "c-claude"}
        if [f.get("exception") for f in fs] != [want]:
            fails.append(f"G0 命中例外 → finding.exception 固定 5 欄（含 reason）：{[f.get('exception') for f in fs]}")
        if "1 筆命中 blocking-policy 例外（blocking 降為 advisory，發現保留）" not in why:
            fails.append(f"G0 status_reason 註明命中筆數：{why}")
        if (f"忽略的例外：{rule} @ docs/threat-model.yaml：已於 2020-01-01 過期；"
                f"{rule} @ docs/threat-model.yaml：G0 例外缺 agent_id，未套用") not in why or "cooldown" in why:
            fails.append(f"G0 status_reason 列出本閘門忽略與缺 agent_id 的例外、不列其他閘門的：{why}")
        if any("過期" in f["reason"] or "缺 agent_id" in f["reason"] for f in fs):
            fails.append(f"忽略的例外不再附加在 finding.reason：{[f['reason'] for f in fs]}")
    # 政策檔讀不到 → 進入點就停：G0 incomplete 並寫明未完成原因、沒有任何發現、控制 untested。
    # 以前 tier 退回 blocking 照樣判定，而且沒有發現時根本不讀政策，G0 報 pass（fail-open）
    from vibesec_policy import POLICY_UNREADABLE, broken_policy_root
    with broken_policy_root() as pr, tempfile.TemporaryDirectory() as d:
        g = run(ROOT, pathlib.Path(d), policy_root=pr)
        if g["status"] != "incomplete" or not (g["status_reason"] or "").startswith(POLICY_UNREADABLE + "（") \
                or g["findings_count"] != {"blocking": 0, "advisory": 0} or {c["state"] for c in g["coverage"]} != {"untested"} \
                or (pathlib.Path(d) / "g0-findings.json").exists():
            fails.append(f"政策檔讀不到 → G0 incomplete、寫明原因、沒有發現、控制 untested（得到 {g['status']}：{g['status_reason']}）")
        # 接線（#181）：閘門結果由 GateRun.unreadable 產出 → 自己的 tool 列 error（output_ref null）、宣告的控制依序 untested 並寫明原因
        import gate_result
        if g["tools"] != [gate_result.tool("vibesec-g0", "error")] \
                or [(c["control_id"], c["state"], (c["reason"] or "").startswith(POLICY_UNREADABLE)) for c in g["coverage"]] \
                != [("VS-G0-LETHAL-TRIFECTA", "untested", True), ("VS-G0-RISK-TIER", "untested", True)]:
            fails.append(f"政策檔讀不到 → tool 列只有 vibesec-g0 一列 error、控制依序 untested 並寫明原因（得到 {g['tools']}、{g['coverage']}）")
    # risk_tier 打錯 → load_policy 回報政策讀不到 → 照樣寫出 incomplete 閘門結果、省略 risk_tier 欄位，不拋例外（#181 決定）
    from vibesec_policy import temp_policy_root
    with temp_policy_root() as pr, tempfile.TemporaryDirectory() as d:
        vb = dict(sarif_gate._yaml(pr / "vibesec.yaml"), risk_tier="l3")
        (pr / "vibesec.yaml").write_text(yaml.safe_dump(vb, allow_unicode=True), encoding="utf-8")
        try:
            g = run(ROOT, pathlib.Path(d), policy_root=pr, vibesec=vb)
            if g["status"] != "incomplete" or "risk_tier" in g:
                fails.append(f"risk_tier 打錯 → incomplete、沒有 risk_tier 欄位（得到 {g['status']}、{g.get('risk_tier')!r}）")
        except Exception as e:
            fails.append(f"risk_tier 打錯 → 不得拋例外（得到 {type(e).__name__}：{e}）")
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
