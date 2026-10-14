#!/usr/bin/env python3
"""VibeSec：從工具 SARIF 推導閘門結果（gate JSON，schemas/gate-result.schema.json）。用於 G2、G3。

用法：
  python3 scripts/sarif_gate.py --gate G3 \
      --tool semgrep=_artifacts/x/semgrep.sarif --tool checkov=_artifacts/y/results_sarif.sarif \
      [--envcheck reports/g2-envcheck.json] --out reports/g3-gate.json
  python3 scripts/sarif_gate.py selftest

規則對應：
  - SARIF rule／result properties 帶 vibesec_rule_id（或 properties.metadata.vibesec_rule_id）且在 cwe-map → 該規則
  - SARIF ruleId 結尾是 vibesec.gN.x（semgrep 自訂規則）→ 規則檔 metadata.vibesec_rule_id（semgrep SARIF 不帶 metadata，
    由本 repo 規則檔反查）；否則該規則（-js / -supabase-js 變體歸回本名）
  - 否則以 config/catalogs/cwe-map.yaml 的 implemented_by（<tool>:<id>）對回 vibesec 規則
  - 都對不到 → 保留外部 ID（<tool>:<ruleId>），tier 取 blocking-policy 的 default_tier
tier：blocking-policy.yaml 的 blocking 清單 + tier_overrides[risk_tier]；exceptions（未過期）把 blocking 降為 advisory，發現保留。
狀態（incomplete ≠ pass，CLAUDE.md #2）：
  有 blocking → fail；否則任一工具輸出缺席、無法解析或自報執行失敗（invocations executionSuccessful=false、
  toolExecutionNotifications 有 level error）→ incomplete；否則 → pass。
退出碼：0（寫出 gate JSON；狀態由 summary 依 mode 決定是否阻擋）；2 = 缺 PyYAML（無法判定）。
"""
from __future__ import annotations
import argparse, collections, datetime, fnmatch, json, pathlib, re, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
VARIANT = re.compile(r"-(supabase-)?js$")
VIBESEC_ID = re.compile(r"(vibesec\.g[0-6]\.[a-z0-9-]+)$")
# 每個閘門的控制與負責工具：控制的 state 由該工具是否跑完、是否有相關 blocking 發現決定
GATE_CONTROLS = {
    "G2": {"ASVS5-V13.3": ["gitleaks", "envcheck"]},
    "G3": {"ASVS5-V1.2": ["semgrep"], "ASVS5-V1.1": ["semgrep"], "ASVS5-V13.2": ["checkov", "trivy"],
           "ASVS5-V15.1": ["semgrep"]},
}

try:
    import yaml
except ImportError:
    print("工具缺席：PyYAML；無法判定閘門狀態（不視為通過）", file=sys.stderr)
    sys.exit(2)

sys.path.insert(0, str(ROOT / "scripts"))
from vibesec_policy import Policy, ProjectPolicy, load_policy  # noqa: E402  tier 的唯一來源


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def _yaml(p: pathlib.Path) -> dict:
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


def load_context(policy: Policy) -> dict:
    """推導 gate JSON 用的資料：mode、tier、規則對應（cwe-map implemented_by）、控制。policy 由進入點建立一次傳入
    （vibesec_policy.load_policy；讀不到 → 呼叫端改用 unreadable_gate，不推導）。"""
    vb = _yaml(ROOT / "vibesec.yaml")
    tier = policy.risk_tier
    blocking = policy.effective_blocking()
    rules = (_yaml(ROOT / "config/catalogs/cwe-map.yaml").get("rules") or {})
    impl: dict[str, set[str]] = collections.defaultdict(set)
    controls: dict[str, list[str]] = {}
    for rid, meta in rules.items():
        controls[rid] = list((meta or {}).get("control_ids") or [])
        for ref in (meta or {}).get("implemented_by") or []:
            t, _, ext = str(ref).partition(":")
            impl[f"{t}:{ext}"].add(rid)
    return {"mode": vb.get("mode", "shadow"), "risk_tier": tier, "blocking": blocking, "policy": policy,
            "default_tier": policy.default_tier, "impl": impl, "controls": controls,
            "semgrep_aliases": load_semgrep_aliases()}   # 政策例外不在這裡：呼叫端以 Policy.for_project(受驗樹) 傳入


_TIMEOUT_RE = re.compile(r"\btime(?:d)?\s?out\b", re.I)


def _note_text(n: dict) -> str:
    m = n.get("message")
    return (m.get("text") or "") if isinstance(m, dict) else ""


def read_sarif(path: pathlib.Path) -> tuple[list[dict] | None, str | None]:
    """回傳 (results, 錯誤)。檔案缺席或無法解析 → (None, 原因)。
    工具自報執行失敗（invocations[].executionSuccessful == false 或 toolExecutionNotifications 有 level error）
    → (results, 原因)：結果可能不完整，發現照算，但該工具不算跑完（incomplete ≠ pass）。
    每筆 result 附 `_vibesec_rule_id`：取自 SARIF rule／result 的 properties.vibesec_rule_id（或 properties.metadata.vibesec_rule_id）。"""
    if not path.is_file():
        return None, f"{path.name} 不存在（工具未執行、失敗或 artifact 缺席）"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return None, f"{path.name} 無法解析（{type(e).__name__}）"
    runs = data.get("runs") if isinstance(data, dict) else None
    if not isinstance(runs, list) or not all(isinstance(run, dict) for run in runs):
        return None, f"{path.name} 沒有 runs 或 runs 內容不是物件（不是有效的 SARIF）"
    if not runs:
        # 空的 runs 代表工具沒有產出任何分析（與「有跑、沒發現」不同）；不能當成 pass（incomplete ≠ pass）
        return None, f"{path.name} 的 runs 為空（工具沒有產出分析結果）"
    out, failed = [], []
    for run in runs:
        for inv in run.get("invocations") or []:
            if not isinstance(inv, dict):
                continue
            if inv.get("executionSuccessful") is False:
                failed.append("executionSuccessful=false")
            # error 等級一律算未完成；semgrep 1.179 的規則逾時只發 warning（實測 "Timeout when running <rule> on <file>"），
            # 該檔該規則沒有被分析，同樣不能當成 pass
            errs = [n for n in inv.get("toolExecutionNotifications") or [] if isinstance(n, dict)
                    and (n.get("level") == "error" or _TIMEOUT_RE.search(_note_text(n)))]
            if errs:
                msg = ((errs[0].get("message") or {}).get("text") or "") if isinstance(errs[0].get("message"), dict) else ""
                failed.append(f"{len(errs)} 個 error 等級或逾時的 toolExecutionNotifications" + (f"（{msg[:120]}）" if msg else ""))
        rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") if isinstance(run.get("tool"), dict) else None
        rules = [x for x in rules or [] if isinstance(x, dict)] if isinstance(rules, list) else []
        by_id = {x.get("id"): x for x in rules if x.get("id")}
        # SARIF 2.1.0 §3.14.23：results 缺席或為 null 代表分析沒有完成；空陣列才代表「沒有發現」。
        # 實測 semgrep／checkov／gitleaks／trivy 乾淨掃描都輸出 "results": []。
        if run.get("results") is None:
            failed.append("run 缺 results（分析未完成）")
            continue
        results = run["results"]
        if not isinstance(results, list):
            return None, f"{path.name} 的 results 不是陣列（不是有效的 SARIF）"
        for r in results:
            if not isinstance(r, dict):
                continue
            idx = r.get("ruleIndex")
            rule = by_id.get(r.get("ruleId")) or (rules[idx] if isinstance(idx, int) and 0 <= idx < len(rules) else {})
            vid = None
            for props in (r.get("properties"), rule.get("properties")):
                if isinstance(props, dict):
                    md = props.get("metadata") if isinstance(props.get("metadata"), dict) else {}
                    vid = vid or props.get("vibesec_rule_id") or md.get("vibesec_rule_id")
            out.append(dict(r, _vibesec_rule_id=vid if isinstance(vid, str) else None))
    if failed:
        return out, f"{path.name} 回報工具執行未成功：" + "；".join(dict.fromkeys(failed))
    return out, None


def _location(r: dict) -> str:
    for loc in r.get("locations") or []:
        uri = ((loc.get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri")
        if uri:
            return re.sub(r"^(file://)?(/github/workspace/|\./)", "", uri)
    return ""


def load_semgrep_aliases() -> dict[str, str]:
    """本 repo semgrep 規則檔（vibesec.yaml g3_sast_iac.semgrep_rules 中的本地路徑）的 id → metadata.vibesec_rule_id。
    semgrep 的 SARIF 不帶自訂 metadata（rules[].properties 只有 precision、tags），只能從規則檔反查。"""
    out: dict[str, str] = {}
    cfg = ((_yaml(ROOT / "vibesec.yaml").get("gates") or {}).get("g3_sast_iac") or {})
    for ref in cfg.get("semgrep_rules") or ["config/semgrep/vibesec-rules.yaml"]:
        p = ROOT / str(ref)
        if str(ref).startswith(("p/", "r/")) or not p.is_file():
            continue
        for r in _yaml(p).get("rules") or []:
            vid = ((r or {}).get("metadata") or {}).get("vibesec_rule_id")
            if isinstance(r, dict) and r.get("id") and isinstance(vid, str):
                out[str(r["id"])] = vid
    return out


def map_rule(tool: str, rule_id: str, pol: dict, declared: str | None = None) -> list[str]:
    # 1) SARIF 自帶 vibesec_rule_id；2) 本 repo 規則檔的 metadata.vibesec_rule_id（semgrep）；
    # 只採用 cwe-map 有登錄的 ID（CLAUDE.md #3），否則回到原本的對應邏輯
    known = pol.get("controls") or {}
    if declared and declared in known:
        return [declared]
    m = VIBESEC_ID.search(rule_id or "")
    if m:
        alias = (pol.get("semgrep_aliases") or {}).get(m.group(1))
        if alias and alias in known:
            return [alias]
        return [VARIANT.sub("", m.group(1))]
    key = f"{tool}:{rule_id}"
    mapped = set(pol["impl"].get(key, set()))
    if not mapped:   # 萬用字元（例如 gitleaks:*：useDefault 載入的內建規則）；精確對應優先
        for pat, rids in pol["impl"].items():
            if "*" in pat and fnmatch.fnmatchcase(key, pat):
                mapped |= rids
    return sorted(mapped) or [key]


def to_findings(tool: str, results: list[dict], pol: dict, project: ProjectPolicy) -> list[dict]:
    out = []
    for r in results:
        loc = _location(r)
        for rid in map_rule(tool, r.get("ruleId") or "", pol, r.get("_vibesec_rule_id")):
            c = project.classify(rid, loc)   # tier 唯一來源；命中例外 → advisory、發現保留
            f = {"rule_id": rid, "tool": tool, "location": loc, "policy_tier": c["policy_tier"]}
            if c["exception"]:
                f["exception"] = c["exception"]   # 各閘門相同的固定形狀
            out.append(f)
    return out


def env_findings(d: dict, pol: dict) -> list[dict]:
    """g2-envcheck.json（scripts/env_guard.py record()）→ 發現。.gitignore 少規則記一筆 env-not-ignored；
    已提交的機密檔每個檔一筆 env-committed（以前併進 env-not-ignored，位置也只寫 .gitignore）。
    舊格式沒有 committed 欄位時照舊只看 env_gitignore_fail。"""
    out = []
    if d.get("env_gitignore_fail"):
        rid = d.get("rule_id") or "vibesec.g2.env-not-ignored"
        out.append({"rule_id": rid, "tool": "envcheck", "location": ".gitignore", "policy_tier": pol["policy"].tier(rid)})
    for path in d.get("committed") or []:
        rid = d.get("committed_rule_id") or "vibesec.g2.env-committed"
        out.append({"rule_id": rid, "tool": "envcheck", "location": str(path), "policy_tier": pol["policy"].tier(rid)})
    return out


def unreadable_gate(gate: str, problem: str, *, scope: str, started: str | None = None) -> dict:
    """政策檔讀不到：不讀工具結果、不分類任何發現；閘門的每個控制 untested 並寫明未完成原因（incomplete ≠ pass）。
    mode 讀不到 → 視同 enforce（與 gate_verdict 相同；阻擋判定另讀受信任樹的 mode）。"""
    try:
        mode = _yaml(ROOT / "vibesec.yaml").get("mode")
    except Exception:
        mode = None
    coverage = [{"control_id": ctl, "state": "untested", "reason": problem} for ctl in GATE_CONTROLS[gate]]
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    from gate_verdict import verdict
    status, status_reason = verdict(blocking=0, coverage=coverage, problems=[problem])
    return {"gate": gate, "status": status, "status_reason": status_reason,
            "mode": mode if mode in ("shadow", "enforce") else "enforce", "scope": scope, "diff_base": None,
            "commit": None, "started_at": started or _now(), "finished_at": _now(), "tools": [],
            "findings_count": {"blocking": 0, "advisory": 0}, "coverage": coverage}


def context_or_unreadable(gate: str, policy_root: pathlib.Path, started: str, **gate_fields) -> tuple[dict | None, dict | None]:
    """掃描入口（g2_secrets、g3_sast）：以 policy_root 的政策建立一次推導資料 → (load_context 的結果, None)；
    政策讀不到 → (None, unreadable_gate 加上 gate_fields)，呼叫端直接回傳它、不跑工具。"""
    policy, problem = load_policy(policy_root)
    if problem:
        return None, dict(unreadable_gate(gate, problem, scope="full", started=started), **gate_fields)
    return load_context(policy), None


def derive(gate: str, tools: dict[str, pathlib.Path], envcheck: pathlib.Path | None, pol: dict,
           project: ProjectPolicy, started: str | None = None) -> dict:
    """project：受驗樹的政策例外（Policy.for_project），必填；外部專案的 project 沒有任何例外。"""
    started = started or _now()
    tool_rows, findings, problems = [], [], []
    ran: set[str] = set()
    # 閘門的每個負責工具都必須提供結果：沒列在 --tool 的工具以前被當成「不需要」而 pass（第四次審視 S-3）
    required = {o for owners in GATE_CONTROLS.get(gate, {}).values() for o in owners}
    for name in sorted(required - set(tools) - {"envcheck"}):
        tool_rows.append({"name": name, "version": None, "state": "missing", "exit_code": None, "output_ref": None, "duration_seconds": None})
        problems.append(f"{name}：未提供結果檔（--tool {name}=… 缺席）")
    if "envcheck" in required and envcheck is None:
        problems.append("envcheck：未提供 g2-envcheck.json")
    for name, path in tools.items():
        results, err = read_sarif(path)
        state = "ran" if err is None else ("missing" if results is None and "不存在" in err else "error")
        tool_rows.append({"name": name, "version": None, "state": state, "exit_code": None,
                          "output_ref": str(path), "duration_seconds": None})
        if err:
            problems.append(f"{name}：{err}")
        if results is None:
            continue
        if err is None:   # 工具自報失敗：發現照算，但不算跑完（負責的控制記 untested）
            ran.add(name)
        findings += to_findings(name, results, pol, project)
    if envcheck is not None:
        try:
            d = json.loads(envcheck.read_text(encoding="utf-8"))
            if not isinstance(d, dict) or "env_gitignore_fail" not in d:
                raise json.JSONDecodeError("缺 env_gitignore_fail 欄位", "", 0)   # 空物件不是「檢查通過」
            # error：git 無法列出追蹤檔，不知道有沒有提交 .env → 工具未完成（incomplete），不是「沒有已提交的檔」
            if d.get("error"):
                problems.append(f"envcheck：{d['error']}")
            else:
                ran.add("envcheck")
            tool_rows.append({"name": "envcheck", "version": None, "state": "error" if d.get("error") else "ran",
                              "exit_code": None, "output_ref": str(envcheck), "duration_seconds": None})
            findings += env_findings(d, pol)
        except (OSError, json.JSONDecodeError) as e:
            tool_rows.append({"name": "envcheck", "version": None, "state": "missing" if isinstance(e, OSError) else "error",
                              "exit_code": None, "output_ref": str(envcheck), "duration_seconds": None})
            problems.append(f"envcheck：{envcheck.name} 缺席或無法解析")
    blocking = [f for f in findings if f["policy_tier"] == "blocking"]
    advisory = len(findings) - len(blocking)
    coverage = []
    for ctl, owners in GATE_CONTROLS.get(gate, {}).items():
        if not all(o in ran for o in owners):
            state, why = "untested", "負責工具未完成：" + "、".join(o for o in owners if o not in ran)
        elif any(ctl in pol["controls"].get(f["rule_id"], []) for f in blocking):
            state, why = "fail", None
        else:
            state, why = "pass", None
        coverage.append({"control_id": ctl, "state": state, "reason": why})
    # 狀態由 gate_verdict.verdict 判定（blocking 優先 fail、工具未完成或控制未實測 → incomplete）；
    # blocking 摘要與例外說明只是附註，不影響狀態
    notes = []
    if blocking:
        top = collections.Counter(f["rule_id"] for f in blocking).most_common(5)
        notes.append("blocking：" + "、".join(f"{r}×{n}" for r, n in top))
    notes += project.report(findings, gate)   # 命中筆數與本閘門忽略的例外（各閘門相同的文字）
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    from gate_verdict import verdict
    status, status_reason = verdict(blocking=len(blocking), coverage=coverage,
                                    problems=list(dict.fromkeys(problems)), notes=notes)
    return {"gate": gate, "status": status, "status_reason": status_reason,
            "mode": pol["mode"], "risk_tier": pol["risk_tier"], "scope": "diff", "diff_base": None, "commit": None,
            "started_at": started, "finished_at": _now(), "tools": tool_rows,
            "findings_count": {"blocking": len(blocking), "advisory": advisory}, "coverage": coverage}


# ------------------------------------------------------------------ selftest
def selftest() -> list[str]:
    from jsonschema import Draft202012Validator
    fails: list[str] = []
    schema = Draft202012Validator(json.loads((ROOT / "schemas/gate-result.schema.json").read_text(encoding="utf-8")),
                                  format_checker=Draft202012Validator.FORMAT_CHECKER)
    pol = load_context(Policy(ROOT))
    sarif = lambda *res: {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t"}}, "results": list(res)}]}
    res = lambda rid, uri="app/x.py": {"ruleId": rid, "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]}
    with tempfile.TemporaryDirectory() as d:
        D = pathlib.Path(d)
        def run(gate, files: dict, env=None):
            tools = {}
            for name, content in files.items():
                p = D / f"{gate}-{name}.sarif"
                if content is None:
                    p.unlink(missing_ok=True)
                else:
                    p.write_text(json.dumps(content) if isinstance(content, dict) else content, encoding="utf-8")
                tools[name] = p
            e = None
            if env is not None:
                e = D / "env.json"; e.write_text(json.dumps(env), encoding="utf-8")
            g = derive(gate, tools, e, pol, pol["policy"].for_project(ROOT))
            errs = sorted(schema.iter_errors(g), key=str)
            if errs:
                fails.append(f"{gate} gate JSON 不符 schema：{errs[0].message}")
            return g
        g = run("G3", {"semgrep": sarif(), "checkov": sarif(), "trivy": sarif()})
        if g["status"] != "pass":
            fails.append(f"三個工具都跑完且無發現 → pass（得到 {g['status']}）")
        g = run("G3", {"semgrep": sarif(res("config.semgrep.vibesec.g3.sql-string-concat")), "checkov": sarif(), "trivy": sarif()})
        if g["status"] != "fail" or g["findings_count"]["blocking"] != 1:
            fails.append("semgrep 命中 blocking 規則 → fail")
        if next(c for c in g["coverage"] if c["control_id"] == "ASVS5-V1.2")["state"] != "fail":
            fails.append("blocking 發現對應的控制 → coverage fail")
        g = run("G3", {"semgrep": sarif(res("vibesec.g3.xss-innerhtml-js")), "checkov": sarif(), "trivy": sarif()})
        if g["status"] != "pass" or g["findings_count"]["advisory"] != 1:
            fails.append("advisory 規則（含 -js 變體）→ pass 且記 advisory")
        g = run("G3", {"semgrep": sarif(), "checkov": sarif(res("CKV2_VIBESEC_1", "infra/main.tf")), "trivy": sarif()})
        if g["status"] != "fail":
            fails.append("checkov 經 implemented_by 對到 blocking 規則（imdsv1）→ fail")
        g = run("G3", {"semgrep": sarif(res("python.lang.security.audit.foo")), "checkov": sarif(), "trivy": sarif()})
        if g["status"] != "pass" or g["findings_count"]["advisory"] != 1:
            fails.append("對不到目錄的外部規則 → default_tier advisory")
        g = run("G3", {"semgrep": sarif(), "checkov": None, "trivy": sarif()})
        if g["status"] != "incomplete" or "checkov" not in (g["status_reason"] or ""):
            fails.append("工具輸出缺席 → incomplete（不是 pass）")
        if next(c for c in g["coverage"] if c["control_id"] == "ASVS5-V13.2")["state"] != "untested":
            fails.append("負責工具缺席的控制 → coverage untested")
        g = run("G3", {"semgrep": "{not json", "checkov": sarif(), "trivy": sarif()})
        if g["status"] != "incomplete":
            fails.append("SARIF 無法解析 → incomplete")
        g = run("G3", {"semgrep": sarif(res("vibesec.g3.command-injection")), "checkov": None, "trivy": sarif()})
        if g["status"] != "fail" or "另有未完成項目" not in (g["status_reason"] or "") or "checkov" not in (g["status_reason"] or ""):
            fails.append("有 blocking 又有工具缺席 → fail，且理由寫出缺席工具")
        bad_run = lambda inv: {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "semgrep"}}, "results": [],
                                                             "invocations": [inv]}]}
        g = run("G3", {"semgrep": bad_run({"executionSuccessful": False}), "checkov": sarif(), "trivy": sarif()})
        if g["status"] != "incomplete" or "executionSuccessful" not in (g["status_reason"] or ""):
            fails.append(f"invocations executionSuccessful=false → incomplete（得到 {g['status']}）")
        if next(c for c in g["coverage"] if c["control_id"] == "ASVS5-V1.2")["state"] != "untested":
            fails.append("工具自報失敗 → 負責的控制 untested")
        g = run("G3", {"semgrep": bad_run({"executionSuccessful": True, "toolExecutionNotifications": [
            {"level": "error", "message": {"text": "Timeout when running rule"}}]}), "checkov": sarif(), "trivy": sarif()})
        if g["status"] != "incomplete":
            fails.append(f"toolExecutionNotifications level error → incomplete（得到 {g['status']}）")
        g = run("G3", {"semgrep": bad_run({"executionSuccessful": True, "toolExecutionNotifications": [
            {"level": "warning", "message": {"text": "x"}}]}), "checkov": sarif(), "trivy": sarif()})
        if g["status"] != "pass":
            fails.append(f"只有 warning 等級的通知 → 仍可 pass（得到 {g['status']}）")
        g = run("G3", {"semgrep": bad_run({"executionSuccessful": True, "toolExecutionNotifications": [
            {"level": "warning", "message": {"text": "Timeout when running vibesec.g3.command-injection on big.py"}}]}),
            "checkov": sarif(), "trivy": sarif()})
        if g["status"] != "incomplete" or "Timeout" not in (g["status_reason"] or ""):
            fails.append(f"semgrep 規則逾時（warning 等級）→ 該檔未分析 → incomplete（得到 {g['status']}）")
        # 空 runs、run 缺 results、results 為 null：SARIF 規範上代表分析未完成，不是「沒有發現」（以前三者都判 pass）
        for why, doc in (("runs 為空", {"version": "2.1.0", "runs": []}),
                         ("run 缺 results", {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t"}}}]}),
                         ("results 為 null", {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t"}}, "results": None}]})):
            g = run("G3", {"semgrep": doc, "checkov": sarif(), "trivy": sarif()})
            if g["status"] != "incomplete" or next(c for c in g["coverage"] if c["control_id"] == "ASVS5-V1.2")["state"] != "untested":
                fails.append(f"{why} → incomplete、負責控制 untested（得到 {g['status']}）")
        g = run("G2", {"gitleaks": {"version": "2.1.0", "runs": []}}, env={"env_gitignore_fail": 0})
        if g["status"] != "incomplete":
            fails.append(f"G2 gitleaks runs 為空 → incomplete（得到 {g['status']}）")
        g = run("G3", {"semgrep": {"version": "2.1.0", "runs": ["oops"]}, "checkov": sarif(), "trivy": sarif()})
        if g["status"] != "incomplete":
            fails.append("runs 內含非物件 → 無效 SARIF → incomplete（不得丟出例外）")
        if map_rule("semgrep", "config.semgrep.vibesec.g4.supabase-table-without-rls", pol) != ["vibesec.g4.supabase-rls-disabled"]:
            fails.append("supabase-table-without-rls 應依規則檔 metadata.vibesec_rule_id 歸到 vibesec.g4.supabase-rls-disabled")
        if map_rule("semgrep", "config.semgrep.vibesec.g3.xss-unescaped-render-py", pol) != ["vibesec.g3.xss-innerhtml"]:
            fails.append("xss-unescaped-render-py 應歸到 vibesec.g3.xss-innerhtml")
        if map_rule("semgrep", "x.vibesec.g3.sql-string-concat-js", pol) != ["vibesec.g3.sql-string-concat"]:
            fails.append("-js 變體仍歸回本名")
        tagged = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t", "rules": [
            {"id": "custom-1", "properties": {"metadata": {"vibesec_rule_id": "vibesec.g3.command-injection"}}}]}},
            "results": [res("custom-1")]}]}
        g = run("G3", {"semgrep": tagged, "checkov": sarif(), "trivy": sarif()})
        if g["status"] != "fail":
            fails.append(f"SARIF rule properties.metadata.vibesec_rule_id 應被採用（command-injection blocking → fail；得到 {g['status']}）")
        # L3：tier_overrides 把 vibesec.g4.supabase-rls-disabled 升為 blocking；建表未啟用 RLS 的 semgrep 規則要吃到這個升級
        run("G3", {"semgrep": sarif(res("config.semgrep.vibesec.g4.supabase-table-without-rls", "supabase/migrations/1.sql")),
                "checkov": sarif(), "trivy": sarif()})
        l3 = Policy(ROOT, risk_tier="L3")
        g = derive("G3", {k: D / f"G3-{k}.sarif" for k in ("semgrep", "checkov", "trivy")}, None,
                   dict(pol, policy=l3), l3.for_project(ROOT))
        if g["status"] != "fail" or g["findings_count"]["blocking"] != 1:
            fails.append(f"L3 下 supabase-table-without-rls → supabase-rls-disabled blocking → fail（得到 {g['status']}）")
        g = run("G2", {"gitleaks": sarif()}, env={"rule_id": "vibesec.g2.env-not-ignored", "env_gitignore_fail": 0})
        if g["status"] != "pass":
            fails.append("G2 無發現 → pass")
        g = run("G2", {"gitleaks": sarif(res("vibesec-openai-api-key", "app/llm.py"))}, env={"env_gitignore_fail": 0})
        if g["status"] != "fail":
            fails.append("gitleaks 經 implemented_by 對到 hardcoded-secret（blocking）→ fail")
        g = run("G2", {"gitleaks": sarif(res("aws-access-token", "app/cfg.py"), res("private-key", "deploy/id_rsa"))}, env={"env_gitignore_fail": 0})
        if g["status"] != "fail" or g["findings_count"]["blocking"] != 2:
            fails.append("gitleaks 內建規則（aws-access-token、private-key）經 gitleaks:* 對到 hardcoded-secret → blocking fail")
        g = run("G2", {"gitleaks": sarif(res("vibesec-openai-api-key", "examples/vulnapp/app/main.py"))}, env={"env_gitignore_fail": 0})
        if g["status"] != "pass" or g["findings_count"]["advisory"] < 1 or "例外" not in (g["status_reason"] or ""):
            fails.append("blocking-policy 例外 → 降為 advisory、發現保留、理由註明")
        hits = to_findings("gitleaks", [res("vibesec-openai-api-key", "examples/vulnapp/app/main.py")], pol, pol["policy"].for_project(ROOT))
        if not hits or any(f["policy_tier"] != "advisory" or sorted(f.get("exception") or {}) !=
                           ["agent_id", "approved_by", "expires", "path_glob", "reason"] for f in hits):
            fails.append(f"命中例外的發現帶 exception 紀錄（固定 5 欄，finding.schema.json）：{hits}")
        # 接線：derive 把閘門 ID 傳給 report → 只列本閘門忽略的例外（G1 的過期例外不出現在 G2）
        e = D / "env.json"; e.write_text(json.dumps({"env_gitignore_fail": 0}), encoding="utf-8")
        (D / "G2-gitleaks.sarif").write_text(json.dumps(sarif()), encoding="utf-8")
        ignored = ProjectPolicy(pol["policy"], [], [("vibesec.g1.cooldown-violation", "G1 的過期例外"),
                                                    ("vibesec.g2.hardcoded-secret", "G2 的過期例外")])
        why = derive("G2", {"gitleaks": D / "G2-gitleaks.sarif"}, e, pol, ignored)["status_reason"] or ""
        if "忽略的例外：G2 的過期例外" not in why or "G1 的過期例外" in why:
            fails.append(f"G2 只列本閘門忽略的例外（不列 G1 的）：{why}")
        g = run("G2", {"gitleaks": None}, env={"env_gitignore_fail": 1})
        if g["status"] != "incomplete" or g["findings_count"]["advisory"] != 1:
            fails.append("gitleaks 缺席 → incomplete；envcheck 失敗 → advisory 發現")
        # 已提交的 .env：以前與「.gitignore 少規則」壓成同一個 env_gitignore_fail，只記一筆 env-not-ignored、位置寫 .gitignore
        envd = {"env_gitignore_fail": 0, "committed": ["config/.env", ".env.production"], "error": None}
        g2 = run("G2", {"gitleaks": sarif()}, env=envd)
        got = sorted((f["rule_id"], f["location"]) for f in env_findings(envd, pol))
        if got != [("vibesec.g2.env-committed", ".env.production"), ("vibesec.g2.env-committed", "config/.env")] \
                or g2["findings_count"]["blocking"] + g2["findings_count"]["advisory"] != 2:
            fails.append(f"已提交的 .env 應以 vibesec.g2.env-committed 逐檔記錄（得到 {got}）")
        # git 無法列出追蹤檔：不知道有沒有提交 .env → incomplete，不是 pass
        g = run("G2", {"gitleaks": sarif()}, env={"env_gitignore_fail": 0, "committed": [], "error": "git ls-files 失敗"})
        if g["status"] != "incomplete" or "git ls-files 失敗" not in (g["status_reason"] or "") \
                or next(c for c in g["coverage"] if c["control_id"] == "ASVS5-V13.3")["state"] != "untested":
            fails.append(f"envcheck 記 error（git 失敗）→ incomplete、ASVS5-V13.3 untested（得到 {g['status']}）")
        g = run("G3", {"semgrep": sarif()})
        if g["status"] != "incomplete" or "checkov" not in (g["status_reason"] or "") or "trivy" not in (g["status_reason"] or ""):
            fails.append("只提供 semgrep → 其他負責工具缺席 → incomplete（不是 pass）")
        if next(c for c in g["coverage"] if c["control_id"] == "ASVS5-V13.2")["state"] != "untested":
            fails.append("未提供結果檔的工具負責的控制 → untested")
        g = run("G3", {})
        if g["status"] != "incomplete":
            fails.append("沒有任何 --tool → incomplete")
        g = run("G2", {"gitleaks": sarif()}, env={})
        if g["status"] != "incomplete":
            fails.append("envcheck 結果缺 env_gitignore_fail → incomplete")
        g = run("G2", {"gitleaks": sarif()})
        if g["status"] != "incomplete":
            fails.append("G2 未提供 envcheck → incomplete")
    # 政策檔讀不到 → 命令列不推導：G2／G3 incomplete、控制 untested 並寫明未完成原因、沒有任何發現
    import contextlib, io
    from vibesec_policy import POLICY_UNREADABLE, broken_policy_root
    with broken_policy_root() as pr, tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
        for gate in ("G2", "G3"):
            o = pathlib.Path(d, f"{gate}.json")
            rc = main(["--gate", gate, "--out", str(o)], policy_root=pr)
            g = json.loads(o.read_text(encoding="utf-8"))
            if rc != 0 or g["status"] != "incomplete" or POLICY_UNREADABLE + "（" not in (g["status_reason"] or "") \
                    or {c["state"] for c in g["coverage"]} != {"untested"} or g["findings_count"] != {"blocking": 0, "advisory": 0} \
                    or list(schema.iter_errors(g)):
                fails.append(f"政策檔讀不到 → {gate} incomplete、控制 untested、寫明原因、沒有發現（得到 {rc}、{g}）")
    return fails


def main(argv=None, policy_root: pathlib.Path = ROOT) -> int:
    """policy_root：阻擋政策所在的 repo（selftest 指向壞政策檔）。"""
    if argv is None:
        argv = sys.argv[1:]
    if argv[:1] == ["selftest"]:
        fails = selftest()
        for f in fails: print(f"FAIL {f}")
        print("selftest " + ("通過" if not fails else f"失敗 {len(fails)} 項"))
        return 1 if fails else 0
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--gate", required=True, choices=sorted(GATE_CONTROLS))
    ap.add_argument("--tool", action="append", default=[], help="<name>=<sarif path>")
    ap.add_argument("--envcheck")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    tools = {}
    for spec in a.tool:
        name, _, path = spec.partition("=")
        tools[name] = pathlib.Path(path)
    policy, problem = load_policy(policy_root)   # 只建立一次；讀不到 → 不推導，閘門 incomplete
    if problem:
        g = unreadable_gate(a.gate, problem, scope="diff")   # 與 derive 相同：命令列推導的是 PR 的變更
    else:
        # 命令列只用於本 repo 的 CI：SARIF 來自本 repo 的受驗樹 → 綁定政策所在的 repo（G2／G3 掃其他專案走 g2_secrets／g3_sast）
        g = derive(a.gate, tools, pathlib.Path(a.envcheck) if a.envcheck else None, load_context(policy),
                   policy.for_project(policy.root))
    pathlib.Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(a.out).write_text(json.dumps(g, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"{a.gate} {g['status']}：blocking={g['findings_count']['blocking']} advisory={g['findings_count']['advisory']}"
          + (f"；{g['status_reason']}" if g["status_reason"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
