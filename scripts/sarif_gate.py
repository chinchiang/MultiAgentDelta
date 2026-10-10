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
from g1_slopcheck import load_exceptions  # noqa: E402  同一份例外規則（欄位完整且未過期，fail closed）
from vibesec_policy import Policy  # noqa: E402  tier 的唯一來源


def _yaml(p: pathlib.Path) -> dict:
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


def load_policy() -> dict:
    vb = _yaml(ROOT / "vibesec.yaml")
    pol = _yaml(ROOT / "config/policy/blocking-policy.yaml")
    policy = Policy(ROOT)
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
    exceptions, ignored = load_exceptions()
    return {"mode": vb.get("mode", "shadow"), "risk_tier": tier, "blocking": blocking, "policy": policy,
            "default_tier": policy.default_tier, "impl": impl, "controls": controls,
            "exceptions": exceptions, "ignored_exceptions": ignored, "semgrep_aliases": load_semgrep_aliases()}


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
    out, failed = [], []
    for run in runs:
        for inv in run.get("invocations") or []:
            if not isinstance(inv, dict):
                continue
            if inv.get("executionSuccessful") is False:
                failed.append("executionSuccessful=false")
            errs = [n for n in inv.get("toolExecutionNotifications") or [] if isinstance(n, dict) and n.get("level") == "error"]
            if errs:
                msg = ((errs[0].get("message") or {}).get("text") or "") if isinstance(errs[0].get("message"), dict) else ""
                failed.append(f"{len(errs)} 個 error 等級的 toolExecutionNotifications" + (f"（{msg[:120]}）" if msg else ""))
        rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") if isinstance(run.get("tool"), dict) else None
        rules = [x for x in rules or [] if isinstance(x, dict)] if isinstance(rules, list) else []
        by_id = {x.get("id"): x for x in rules if x.get("id")}
        results = run.get("results") or []
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


def to_findings(tool: str, results: list[dict], pol: dict) -> list[dict]:
    out = []
    for r in results:
        loc = _location(r)
        for rid in map_rule(tool, r.get("ruleId") or "", pol, r.get("_vibesec_rule_id")):
            f = {"rule_id": rid, "tool": tool, "location": loc, "policy_tier": pol["policy"].tier(rid)}   # tier 唯一來源
            for ex in pol["exceptions"]:
                if ex["rule_id"] == rid and fnmatch.fnmatchcase(loc, ex["path_glob"]):
                    if f["policy_tier"] == "blocking":
                        f["policy_tier"] = "advisory"
                    f["exception"] = ex["path_glob"]
                    break
            out.append(f)
    return out


def derive(gate: str, tools: dict[str, pathlib.Path], envcheck: pathlib.Path | None, pol: dict,
           started: str | None = None) -> dict:
    now = lambda: datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    started = started or now()
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
        findings += to_findings(name, results, pol)
    if envcheck is not None:
        try:
            d = json.loads(envcheck.read_text(encoding="utf-8"))
            if not isinstance(d, dict) or "env_gitignore_fail" not in d:
                raise json.JSONDecodeError("缺 env_gitignore_fail 欄位", "", 0)   # 空物件不是「檢查通過」
            ran.add("envcheck")
            tool_rows.append({"name": "envcheck", "version": None, "state": "ran", "exit_code": None,
                              "output_ref": str(envcheck), "duration_seconds": None})
            if d.get("env_gitignore_fail"):
                rid = d.get("rule_id") or "vibesec.g2.env-not-ignored"
                findings.append({"rule_id": rid, "tool": "envcheck", "location": ".gitignore",
                                 "policy_tier": pol["policy"].tier(rid)})
        except (OSError, json.JSONDecodeError) as e:
            tool_rows.append({"name": "envcheck", "version": None, "state": "missing" if isinstance(e, OSError) else "error",
                              "exit_code": None, "output_ref": str(envcheck), "duration_seconds": None})
            problems.append(f"envcheck：{envcheck.name} 缺席或無法解析")
    blocking = [f for f in findings if f["policy_tier"] == "blocking"]
    advisory = len(findings) - len(blocking)
    reasons = []
    if blocking:
        status = "fail"
        top = collections.Counter(f["rule_id"] for f in blocking).most_common(5)
        reasons.append("blocking：" + "、".join(f"{r}×{n}" for r, n in top))
        if problems:
            reasons.append("另有工具未完成：" + "；".join(problems))
    elif problems:
        status = "incomplete"
        reasons.append("工具未完成：" + "；".join(problems))
    else:
        status = "pass"
    excepted = [f for f in findings if f.get("exception")]
    if excepted:
        reasons.append(f"{len(excepted)} 筆命中 blocking-policy 例外（blocking 降為 advisory，發現保留）")
    if pol["ignored_exceptions"]:
        reasons.append("忽略的例外：" + "；".join(pol["ignored_exceptions"]))
    coverage = []
    for ctl, owners in GATE_CONTROLS.get(gate, {}).items():
        if not all(o in ran for o in owners):
            state, why = "untested", "負責工具未完成：" + "、".join(o for o in owners if o not in ran)
        elif any(ctl in pol["controls"].get(f["rule_id"], []) for f in blocking):
            state, why = "fail", None
        else:
            state, why = "pass", None
        coverage.append({"control_id": ctl, "state": state, "reason": why})
    return {"gate": gate, "status": status, "status_reason": "；".join(reasons) or None,
            "mode": pol["mode"], "risk_tier": pol["risk_tier"], "scope": "diff", "diff_base": None, "commit": None,
            "started_at": started, "finished_at": now(), "tools": tool_rows,
            "findings_count": {"blocking": len(blocking), "advisory": advisory}, "coverage": coverage}


# ------------------------------------------------------------------ selftest
def selftest() -> list[str]:
    from jsonschema import Draft202012Validator
    fails: list[str] = []
    schema = Draft202012Validator(json.loads((ROOT / "schemas/gate-result.schema.json").read_text(encoding="utf-8")),
                                  format_checker=Draft202012Validator.FORMAT_CHECKER)
    pol = load_policy()
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
            g = derive(gate, tools, e, pol)
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
        if g["status"] != "fail" or "另有工具未完成" not in (g["status_reason"] or ""):
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
        g = derive("G3", {k: D / f"G3-{k}.sarif" for k in ("semgrep", "checkov", "trivy")}, None,
                   dict(pol, policy=Policy(ROOT, risk_tier="L3")))
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
        g = run("G2", {"gitleaks": None}, env={"env_gitignore_fail": 1})
        if g["status"] != "incomplete" or g["findings_count"]["advisory"] != 1:
            fails.append("gitleaks 缺席 → incomplete；envcheck 失敗 → advisory 發現")
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
    return fails


def main(argv=None) -> int:
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
    g = derive(a.gate, tools, pathlib.Path(a.envcheck) if a.envcheck else None, load_policy())
    pathlib.Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(a.out).write_text(json.dumps(g, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"{a.gate} {g['status']}：blocking={g['findings_count']['blocking']} advisory={g['findings_count']['advisory']}"
          + (f"；{g['status_reason']}" if g["status_reason"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
