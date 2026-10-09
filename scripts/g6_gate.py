#!/usr/bin/env python3
"""G6 AI 紅隊結果彙整：promptfoo eval（決定性）＋ promptfoo redteam（選用，需金鑰）＋ garak → 一份 gate json + SARIF。

原則（CLAUDE.md #2）：
  - 測試失敗 → fail（不得因 promptfoo 非零退出碼而改寫成 incomplete）。
  - 工具缺席、輸出無法解析、單一測試執行錯誤、未設定金鑰 → 該層 / 該 check 記 untested，閘門 incomplete。
  - 只有所有層都實際執行且無失敗才是 pass。
規則 ID 只查 config/catalogs/cwe-map.yaml（CLAUDE.md #3）；查不到者 policy_tier 視為 advisory 並在 message 註明。

用法：
  python3 scripts/g6_gate.py --eval reports/g6-promptfoo.json \
      [--redteam reports/g6-promptfoo-redteam.json | --redteam-skipped "未設定 ANTHROPIC_API_KEY / OPENAI_API_KEY secret"] \
      [--garak-glob 'reports/garak/g6-garak*.report.jsonl'] \
      --gate reports/g6-gate.json --sarif reports/g6.sarif [--mode shadow]
退出碼：0 已寫出結果（不論 pass/fail/incomplete；shadow 模式由彙整步驟決定是否阻擋）。
"""
from __future__ import annotations
import argparse, datetime, glob, json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SARIF_URI = ".github/workflows/staging-blackbox.yml"

# promptfoo failureReason：1 = 斷言失敗，2 = 執行錯誤
PF_ASSERT, PF_ERROR = 1, 2

# garak probe 前綴 → vibesec 規則
GARAK_RULES = {
    "promptinject": "vibesec.g6.direct-prompt-injection",
    "dan": "vibesec.g6.direct-prompt-injection",
    "encoding": "vibesec.g6.direct-prompt-injection",
    "latentinjection": "vibesec.g6.indirect-prompt-injection",
    "leakreplay": "vibesec.g6.system-prompt-extraction",
    "xss": "vibesec.g6.stored-xss-via-ai-output",            # garak < 0.17
    "web_injection": "vibesec.g6.stored-xss-via-ai-output",  # garak ≥ 0.17（TaskXSS、MarkdownXSS…）
}


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def load_catalog() -> tuple[dict, dict]:
    try:
        import yaml
        d = yaml.safe_load((ROOT / "config/catalogs/cwe-map.yaml").read_text(encoding="utf-8")) or {}
        return d.get("rules", {}), d.get("external_prefixes", {})
    except Exception:
        return {}, {}


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vibesec_policy import Policy  # noqa: E402
POLICY = Policy(pathlib.Path(__file__).resolve().parent.parent)


class Collector:
    def __init__(self, catalog: dict, prefixes: dict | None = None):
        self.cat = catalog
        self.prefixes = prefixes or {}
        self.results: list[dict] = []
        self.rules: dict[str, dict] = {}
        self.coverage: dict[str, dict] = {}   # key -> {control_id, state, reason}
        self.tools: list[dict] = []
        self.reasons: list[str] = []

    def tier(self, rule_id: str) -> str:
        # tier 只來自 blocking-policy（vibesec_policy.Policy）；cwe-map 的 policy_tier 只是預設建議
        return POLICY.tier(rule_id)

    def control(self, rule_id: str, fallback: str) -> str:
        ids = (self.cat.get(rule_id) or {}).get("control_ids") or []
        llm = [c for c in ids if c.startswith("LLM")]
        return (llm or ids or [fallback])[0]

    def finding(self, rule_id: str, msg: str, source: str):
        known = rule_id in self.cat
        tier = self.tier(rule_id) if known else "advisory"
        level = "error" if tier == "blocking" else "warning"
        if not known:
            prefix = next((p for p in self.prefixes if rule_id.startswith(p)), None)
            msg += (f"（外部規則 {prefix}，cwe-map 未定 policy_tier，預設 advisory，待人工裁定）" if prefix
                    else f"（rule_id {rule_id} 不在 cwe-map，暫列 advisory）")
        self.rules.setdefault(rule_id, {"id": rule_id, "name": rule_id,
                                        "shortDescription": {"text": (self.cat.get(rule_id) or {}).get("title", rule_id)},
                                        "properties": {"policy_tier": tier}})
        self.results.append({"ruleId": rule_id, "level": level, "message": {"text": msg},
                             "locations": [{"physicalLocation": {"artifactLocation": {"uri": SARIF_URI}}}],
                             "properties": {"policy_tier": tier, "source": source}})

    def cover(self, key: str, control_id: str, state: str, reason: str | None = None):
        prev = self.coverage.get(key)
        rank = {"fail": 3, "untested": 2, "pass": 1}
        if prev is None or rank[state] > rank[prev["state"]]:
            self.coverage[key] = {"control_id": control_id, "state": state, "reason": reason}


def ingest_promptfoo_eval(c: Collector, path: str | None, exit_code: int | None):
    tool = {"name": "promptfoo-eval", "version": None, "state": "ran", "exit_code": exit_code,
            "output_ref": path, "duration_seconds": None}
    try:
        data = json.loads(pathlib.Path(path).read_text(encoding="utf-8")) if path else None
        rows = data["results"]["results"]
    except Exception as e:
        tool["state"] = "missing" if not path or not pathlib.Path(path).exists() else "error"
        c.tools.append(tool)
        c.reasons.append(f"promptfoo eval 無可解析輸出（{type(e).__name__}）")
        c.cover("promptfoo-eval", "LLM01:2025", "untested", "promptfoo eval 未產生可解析結果")
        return
    c.tools.append(tool)
    for r in rows:
        md = ((r.get("testCase") or {}).get("metadata")) or r.get("metadata") or {}
        rule = md.get("vibesec_rule_id") or "promptfoo:unmapped"
        check = md.get("vibesec_check") or rule
        desc = (r.get("testCase") or {}).get("description") or check
        ctrl = c.control(rule, "LLM01:2025")
        if r.get("success"):
            c.cover(check, ctrl, "pass")
        elif r.get("failureReason") == PF_ERROR:
            c.cover(check, ctrl, "untested", f"執行錯誤：{(r.get('error') or '')[:160]}")
            c.reasons.append(f"promptfoo 測試「{desc}」執行錯誤")
        else:
            c.cover(check, ctrl, "fail")
            c.finding(rule, f"promptfoo：{desc} — {(r.get('error') or '斷言失敗')[:200]}", "promptfoo-eval")
    # http target 無法回報 token 成本：明確記 untested（不得記 pass）
    c.cover("denial_of_wallet_cost", "LLM10:2025", "untested", "http target 不回報 token 用量，成本斷言無法實測")


def ingest_promptfoo_redteam(c: Collector, path: str | None, skipped: str | None):
    if skipped:
        c.tools.append({"name": "promptfoo-redteam", "version": None, "state": "missing", "exit_code": None,
                        "output_ref": None, "duration_seconds": None})
        c.cover("promptfoo-redteam", "LLM01:2025", "untested", skipped)
        c.reasons.append(f"redteam 生成層未執行：{skipped}")
        return
    if not path:
        return
    try:
        rows = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))["results"]["results"]
    except Exception as e:
        c.tools.append({"name": "promptfoo-redteam", "version": None, "state": "error", "exit_code": None,
                        "output_ref": path, "duration_seconds": None})
        c.cover("promptfoo-redteam", "LLM01:2025", "untested", f"redteam 輸出無法解析（{type(e).__name__}）")
        c.reasons.append("promptfoo redteam 輸出無法解析")
        return
    c.tools.append({"name": "promptfoo-redteam", "version": None, "state": "ran", "exit_code": None,
                    "output_ref": path, "duration_seconds": None})
    failed = errored = 0
    for r in rows:
        md = ((r.get("testCase") or {}).get("metadata")) or r.get("metadata") or {}
        plugin = md.get("pluginId") or md.get("plugin") or "unknown"
        if r.get("success"):
            continue
        if r.get("failureReason") == PF_ERROR:
            errored += 1
            continue
        failed += 1
        c.finding(f"promptfoo:{plugin}", f"promptfoo redteam：plugin {plugin} 未通過 — {(r.get('error') or '')[:200]}",
                  "promptfoo-redteam")
    if failed:
        c.cover("promptfoo-redteam", "LLM01:2025", "fail")
    elif errored:
        c.cover("promptfoo-redteam", "LLM01:2025", "untested", f"{errored} 個 redteam 測試執行錯誤")
        c.reasons.append(f"promptfoo redteam 有 {errored} 個測試執行錯誤")
    else:
        c.cover("promptfoo-redteam", "LLM01:2025", "pass")


def garak_abort_reason(log_path: str | None) -> str | None:
    """從 garak log 擷取中止原因：優先取最後一行例外（如 AssertionError: …），其次 ❌ 行；不回傳 Traceback 標頭。"""
    import re
    try:
        lines = pathlib.Path(log_path).read_text(encoding="utf-8", errors="replace").splitlines() if log_path else []
    except OSError:
        return None
    exc = [ln.strip() for ln in lines if re.match(r"^\s*[\w.]+(Error|Exception)\b", ln) and "Traceback" not in ln]
    if exc:
        return exc[-1][:200]
    for line in lines:
        if "❌" in line:
            return line.replace("❌", "").strip()[:200]
    return None


def garak_expected_families(config_path: str | None) -> list[str]:
    """讀 garak 設定的 run.spec.include，取 probe 家族名（probes.dan → dan）。"""
    try:
        import yaml
        spec = ((yaml.safe_load(pathlib.Path(config_path).read_text(encoding="utf-8")) or {}).get("run") or {}).get("spec") or {}
    except Exception:
        return []
    inc = spec.get("include") or [] if isinstance(spec, dict) else []
    return [s.split(".")[1] for s in inc if isinstance(s, str) and s.startswith("probes.") and len(s.split(".")) > 1]


def ingest_garak(c: Collector, pattern: str | None, log_path: str | None = None, config_path: str | None = None):
    if not pattern:
        return
    files = sorted(glob.glob(pattern))
    if not files:
        why = garak_abort_reason(log_path)
        c.tools.append({"name": "garak", "version": None, "state": "error" if why else "missing", "exit_code": None,
                        "output_ref": log_path if why else None, "duration_seconds": None})
        detail = f"garak 中止：{why}" if why else "garak 未產生報告（未安裝、無法連線靶場或執行失敗）"
        c.cover("garak", "LLM01:2025", "untested", detail)
        c.reasons.append(detail)
        return
    c.tools.append({"name": "garak", "version": None, "state": "ran", "exit_code": None,
                    "output_ref": files[0], "duration_seconds": None})
    evals = 0
    seen_families: set[str] = set()
    for f in files:
        for line in pathlib.Path(f).read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e.get("entry_type") != "eval":
                continue
            evals += 1
            probe, det = e.get("probe", "?"), e.get("detector", "?")
            seen_families.add(probe.split(".")[0])
            # garak ≥ 0.17：total_evaluated / fails；舊版：total（fails = total - passed）
            total = int(e.get("total_evaluated", e.get("total")) or 0)
            passed = int(e.get("passed") or 0)
            fails = int(e["fails"]) if e.get("fails") is not None else max(total - passed, 0)
            rule = GARAK_RULES.get(probe.split(".")[0], f"garak:{probe}.{det}")
            ctrl = c.control(rule, "LLM01:2025")
            if not total:
                c.cover(f"garak:{probe}", ctrl, "untested", f"{probe} / {det} 沒有可評估的輸出")
            elif fails:
                c.cover(f"garak:{probe}", ctrl, "fail")
                c.finding(rule, f"garak：{probe} / {det} 命中 {fails}/{total}", "garak")
            else:
                c.cover(f"garak:{probe}", ctrl, "pass")
    why = garak_abort_reason(log_path)
    suffix = f"（中止：{why}）" if why else ""
    if not evals:
        c.cover("garak", "LLM01:2025", "untested", f"garak 報告中沒有 eval 紀錄{suffix}")
        c.reasons.append(f"garak 報告中沒有 eval 紀錄{suffix}")
        return
    # 設定中要求、但報告裡沒有任何 eval 的 probe 家族（逾時或中途崩潰）→ untested，不得默認為 pass
    missing = [fam for fam in garak_expected_families(config_path) if fam not in seen_families]
    for fam in missing:
        rule = GARAK_RULES.get(fam, f"garak:{fam}")
        c.cover(f"garak:{fam}", c.control(rule, "LLM01:2025"), "untested", f"garak 未完成 {fam}{suffix}")
    if missing:
        c.reasons.append(f"garak 未完成：{', '.join(missing)}{suffix}")


def ingest_observations(c, path):
    try:
        data = json.loads(pathlib.Path(path).read_text())
        checks = data["coverage"]
        required = {"excessive_agency", "denial_of_wallet", "denial_of_wallet_cost"}
        if not isinstance(checks, dict) or set(checks) != required: raise ValueError("遙測控制缺漏")
        rules = data.get("rules")
        if not isinstance(rules, list) or any(r not in ("vibesec.g6.excessive-agency", "vibesec.g6.denial-of-wallet") for r in rules): raise ValueError("未知遙測規則")
        if not isinstance(checks, dict) or not checks: raise ValueError("沒有遙測")
        for state in checks.values():
            if state not in ("pass", "fail", "untested"): raise ValueError("遙測狀態錯誤")
        c.coverage.pop("denial_of_wallet_cost", None)  # 用實測遙測取代 HTTP adapter 的未知狀態
        for name, state in checks.items():
            c.cover(name, "LLM06:2025" if name == "excessive_agency" else "LLM10:2025", state,
                    "目標未提供必要工具事件或用量遙測" if state == "untested" else None)
        for rule in data.get("rules", []):
            c.finding(rule, "授權目標回報未核准的高影響工具事件或超出用量預算", "agent-observations")
        c.tools.append({"name": "agent-observations", "state": "ran", "output_ref": path})
    except (OSError, ValueError, KeyError, TypeError):
        c.cover("agent-observations", "LLM10:2025", "untested", "工具事件／用量遙測未完成")
        c.tools.append({"name": "agent-observations", "state": "error", "output_ref": path})


def build(c: Collector, mode: str, started: str) -> tuple[dict, dict]:
    blocking = sum(1 for r in c.results if r["properties"]["policy_tier"] == "blocking")
    advisory = len(c.results) - blocking
    cov = list(c.coverage.values())
    if any(x["state"] == "fail" for x in cov) and blocking:
        status, reason = "fail", None
    elif any(x["state"] == "untested" for x in cov) or not cov:
        status, reason = "incomplete", "；".join(dict.fromkeys(c.reasons)) or "沒有可用的 G6 結果"
    elif any(x["state"] == "fail" for x in cov):
        status, reason = "fail", None
    else:
        status, reason = "pass", None
    if status == "fail" and c.reasons:
        reason = "另有未完成項目：" + "；".join(dict.fromkeys(c.reasons))
    gate = {"gate": "G6", "status": status, "status_reason": reason, "mode": mode, "scope": "full",
            "diff_base": None, "commit": None, "started_at": started, "finished_at": now(),
            "tools": c.tools, "findings_count": {"blocking": blocking, "advisory": advisory},
            "coverage": cov}
    sarif = {"version": "2.1.0",
             "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
             "runs": [{"tool": {"driver": {"name": "vibesec-g6", "informationUri": "https://github.com/chinchiang/MultiAgentDelta",
                                           "rules": list(c.rules.values())}},
                       "results": c.results}]}
    return gate, sarif


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--eval", dest="eval_path")
    ap.add_argument("--eval-exit-code", type=int)
    ap.add_argument("--redteam")
    ap.add_argument("--redteam-skipped")
    ap.add_argument("--garak-glob")
    ap.add_argument("--garak-log", help="garak stdout/stderr；無報告時擷取中止原因")
    ap.add_argument("--garak-config", help="garak 設定檔；比對 run.spec 中要求但未完成的 probe 家族")
    ap.add_argument("--observations")
    ap.add_argument("--gate", required=True)
    ap.add_argument("--sarif")
    ap.add_argument("--mode", choices=["shadow", "enforce"])
    a = ap.parse_args(argv)
    started = now()
    c = Collector(*load_catalog())
    ingest_promptfoo_eval(c, a.eval_path, a.eval_exit_code)
    ingest_promptfoo_redteam(c, a.redteam, a.redteam_skipped)
    ingest_garak(c, a.garak_glob, a.garak_log, a.garak_config)
    import yaml
    configured = yaml.safe_load((ROOT / "vibesec.yaml").read_text())["mode"]
    mode = "enforce" if configured == "enforce" or a.mode == "enforce" else "shadow"
    if a.observations: ingest_observations(c, a.observations)
    gate, sarif = build(c, mode, started)
    pathlib.Path(a.gate).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(a.gate).write_text(json.dumps(gate, ensure_ascii=False, indent=2), encoding="utf-8")
    if a.sarif:
        pathlib.Path(a.sarif).write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"G6: status={gate['status']} blocking={gate['findings_count']['blocking']} "
          f"advisory={gate['findings_count']['advisory']}" + (f" reason={gate['status_reason']}" if gate["status_reason"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
