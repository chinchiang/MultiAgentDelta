#!/usr/bin/env python3
"""VibeSec G5：把 OWASP ZAP（api-scan／baseline）的 JSON 報告轉成 G5 的覆蓋與 SARIF 結果，給 staging 的 G5 api-probes 合併。

  python3 scripts/g5_zap.py --report api=reports/zap-api.json --report baseline=reports/zap-baseline.json \\
      --conf config/zap/api-scan.conf --out reports/g5-zap.json
  python3 scripts/g5_zap.py selftest

判定：
  - 報告缺席或無法解析 → 該掃描 untested（incomplete ≠ pass；vibesec.yaml g5 tools 含 zap-baseline、zap-api-scan）。
  - 規則在 conf 為 IGNORE／OUTOFSCOPE → 略過；conf 沒列且 riskcode 0（Informational）→ 略過；其餘列為發現。
  - 規則 ID：以 config/catalogs/cwe-map.yaml 的 implemented_by（zap:<id>）反查 vibesec 規則；查不到 → zap:<pluginid>
    （CLAUDE.md 規則 3：不自行對應）。tier 一律由 scripts/vibesec_policy.py 決定（外部規則預設 advisory）。
  - 同一 pluginid 在兩個掃描都出現只記一次（來源合併）。
退出碼：0 已寫出結果；2 參數或寫檔錯誤。
"""
from __future__ import annotations
import argparse, json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
SARIF_URI = ".github/workflows/staging-blackbox.yml"
SCANS = {"api": ("zap_api_scan", "zap-api-scan"), "baseline": ("zap_baseline", "zap-baseline")}
SKIP_ACTIONS = {"IGNORE", "OUTOFSCOPE"}


def load_conf(path: pathlib.Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for ln in path.read_text(encoding="utf-8").splitlines():
        parts = ln.split("\t")
        if len(parts) >= 2 and parts[0].strip().isdigit():
            out[parts[0].strip()] = parts[1].strip().upper()
    return out


def load_impl(root: pathlib.Path) -> dict[str, str]:
    import yaml
    d = yaml.safe_load((root / "config/catalogs/cwe-map.yaml").read_text(encoding="utf-8")) or {}
    impl: dict[str, str] = {}
    for rid, meta in (d.get("rules") or {}).items():
        for ref in (meta or {}).get("implemented_by") or []:
            if str(ref).startswith("zap:"):
                impl.setdefault(str(ref), rid)
    return impl


def convert(reports: dict[str, pathlib.Path | None], conf: dict[str, str], impl: dict[str, str], policy) -> dict:
    coverage: dict[str, dict] = {}
    tools: list[dict] = []
    rules: dict[str, dict] = {}
    by_plugin: dict[str, dict] = {}
    for scan, (cov_key, tool_name) in SCANS.items():
        path = reports.get(scan)
        tool = {"name": tool_name, "version": None, "state": "ran", "exit_code": None,
                "output_ref": str(path) if path else None, "duration_seconds": None}
        try:
            data = json.loads(path.read_text(encoding="utf-8")) if path else None
            sites = data["site"]
            if isinstance(sites, dict):
                sites = [sites]
            if not isinstance(sites, list):
                raise ValueError("site")
            version = data.get("@version")
        except Exception as e:
            tool["state"] = "missing" if not path or not path.exists() else "error"
            tools.append(tool)
            coverage[cov_key] = {"state": "untested",
                                 "reason": f"ZAP {tool_name} 沒有可解析的報告（{type(e).__name__}）"}
            continue
        tool["version"] = version
        tools.append(tool)
        hits = 0
        for site in sites:
            for a in (site or {}).get("alerts") or []:
                pid = str(a.get("pluginid") or "").strip()
                if not pid:
                    continue
                action = conf.get(pid)
                if action in SKIP_ACTIONS:
                    continue
                try:
                    risk = int(a.get("riskcode") or 0)
                except ValueError:
                    risk = 0
                if action is None and risk == 0:
                    continue
                hits += 1
                inst = a.get("instances") or []
                uris = [i.get("uri") for i in inst if isinstance(i, dict) and i.get("uri")]
                cur = by_plugin.setdefault(pid, {"alert": a.get("alert") or a.get("name") or pid,
                                                 "cweid": a.get("cweid"), "risk": risk, "count": 0,
                                                 "uris": [], "sources": [], "action": action or "WARN"})
                cur["count"] += int(a.get("count") or len(inst) or 1)
                cur["uris"] += [u for u in uris if u not in cur["uris"]][:3]
                if tool_name not in cur["sources"]:
                    cur["sources"].append(tool_name)
        coverage[cov_key] = {"state": "fail" if hits else "pass", "reason": None}
    results: list[dict] = []
    for pid, f in sorted(by_plugin.items()):
        rule_id = impl.get(f"zap:{pid}", f"zap:{pid}")
        tier = policy.tier(rule_id)
        rules.setdefault(rule_id, {"id": rule_id, "name": rule_id, "shortDescription": {"text": f["alert"]},
                                   "defaultConfiguration": {"level": "error" if tier == "blocking" else "warning"},
                                   "properties": {"policy_tier": tier}})
        where = f"，例：{f['uris'][0]}" if f["uris"] else ""
        results.append({"ruleId": rule_id, "level": "error" if tier == "blocking" else "warning",
                        "message": {"text": f"ZAP {pid} {f['alert']}（{f['count']} 處{where}；conf {f['action']}）"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": SARIF_URI}}}],
                        "properties": {"policy_tier": tier, "source": "+".join(f["sources"]), "zap_pluginid": pid,
                                       "cweid": f["cweid"], "zap_riskcode": f["risk"]}})
    return {"coverage": coverage, "tools": tools, "rules": rules, "results": results}


def selftest() -> list[str]:
    import tempfile
    from vibesec_policy import Policy
    fails: list[str] = []
    conf = {"10038": "WARN", "40018": "FAIL", "10096": "IGNORE", "40040": "FAIL"}
    impl = {"zap:10038": "vibesec.g3.missing-csp", "zap:40040": "vibesec.g5.cors-reflect-origin"}
    pol = Policy(ROOT)
    rep_api = {"@version": "2.16.1", "site": [{"@name": "http://127.0.0.1:8000", "alerts": [
        {"pluginid": "40018", "alert": "SQL Injection", "riskcode": "3", "cweid": "89", "count": "1",
         "instances": [{"uri": "http://127.0.0.1:8000/users?id=1"}]},
        {"pluginid": "10096", "alert": "Timestamp Disclosure", "riskcode": "1"},
        {"pluginid": "10027", "alert": "Suspicious Comments", "riskcode": "0"},
        {"pluginid": "40040", "alert": "CORS Header", "riskcode": "2", "instances": [{"uri": "http://127.0.0.1:8000/"}]}]}]}
    rep_base = {"@version": "2.16.1", "site": {"@name": "http://127.0.0.1:8000", "alerts": [
        {"pluginid": "10038", "alert": "CSP Header Not Set", "riskcode": "2", "count": "4"},
        {"pluginid": "40040", "alert": "CORS Header", "riskcode": "2"}]}}
    with tempfile.TemporaryDirectory() as d:
        dp = pathlib.Path(d)
        (dp / "api.json").write_text(json.dumps(rep_api), encoding="utf-8")
        (dp / "base.json").write_text(json.dumps(rep_base), encoding="utf-8")
        (dp / "bad.json").write_text("{not json", encoding="utf-8")
        r = convert({"api": dp / "api.json", "baseline": dp / "base.json"}, conf, impl, pol)
        ids = sorted(x["ruleId"] for x in r["results"])
        if ids != ["vibesec.g3.missing-csp", "vibesec.g5.cors-reflect-origin", "zap:40018"]:
            fails.append(f"規則對應／過濾錯誤：{ids}")
        cors = [x for x in r["results"] if x["ruleId"] == "vibesec.g5.cors-reflect-origin"]
        if len(cors) != 1 or cors[0]["properties"]["source"] != "zap-api-scan+zap-baseline":
            fails.append(f"同一 pluginid 應合併來源：{cors}")
        for x in r["results"]:
            if x["properties"]["policy_tier"] != pol.tier(x["ruleId"]):
                fails.append(f"tier 必須來自政策：{x['ruleId']}")
        if r["coverage"]["zap_api_scan"]["state"] != "fail" or r["coverage"]["zap_baseline"]["state"] != "fail":
            fails.append(f"有發現的掃描應記 fail：{r['coverage']}")
        r = convert({"api": dp / "missing.json", "baseline": dp / "bad.json"}, conf, impl, pol)
        if [r["coverage"][k]["state"] for k in ("zap_api_scan", "zap_baseline")] != ["untested", "untested"]:
            fails.append(f"缺席／壞掉的報告應 untested：{r['coverage']}")
        if [t["state"] for t in r["tools"]] != ["missing", "error"]:
            fails.append(f"工具狀態應為 missing／error：{r['tools']}")
        r = convert({"api": None, "baseline": None}, conf, impl, pol)
        if any(v["state"] != "untested" for v in r["coverage"].values()):
            fails.append("未提供報告應 untested")
        (dp / "clean.json").write_text(json.dumps({"site": [{"alerts": [
            {"pluginid": "10096", "riskcode": "1"}, {"pluginid": "10027", "riskcode": "0"}]}]}), encoding="utf-8")
        r = convert({"api": dp / "clean.json", "baseline": dp / "clean.json"}, conf, impl, pol)
        if any(v["state"] != "pass" for v in r["coverage"].values()) or r["results"]:
            fails.append(f"只有略過的警示 → pass 且無發現：{r['coverage']} {r['results']}")
    try:
        real = load_impl(ROOT)
        if real.get("zap:10038") != "vibesec.g3.missing-csp":
            fails.append(f"cwe-map 反查 zap:10038 應為 vibesec.g3.missing-csp，實際 {real.get('zap:10038')}")
        rc = load_conf(ROOT / "config/zap/api-scan.conf")
        if rc.get("10038") != "WARN" or rc.get("10096") != "IGNORE":
            fails.append("config/zap/api-scan.conf 解析結果不符預期")
    except Exception as e:
        fails.append(f"讀取 repo 設定失敗：{type(e).__name__}: {e}")
    return fails


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["selftest"]:
        fails = selftest()
        for f in fails: print(f"FAIL {f}")
        print("selftest " + ("通過" if not fails else f"失敗 {len(fails)} 項"))
        return 1 if fails else 0
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--report", action="append", default=[], help="api=<path> 或 baseline=<path>")
    ap.add_argument("--conf", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    reports: dict[str, pathlib.Path | None] = {k: None for k in SCANS}
    for spec in a.report:
        k, _, v = spec.partition("=")
        if k not in SCANS or not v:
            print(f"--report 格式錯誤：{spec!r}（應為 api=<path> 或 baseline=<path>）", file=sys.stderr)
            return 2
        reports[k] = pathlib.Path(v)
    from vibesec_policy import Policy
    try:
        conf = load_conf(pathlib.Path(a.conf))
    except OSError as e:
        print(f"無法讀取 {a.conf}：{e}（ZAP 掃描記 untested）", file=sys.stderr)
        conf = None
    if conf is None:
        r = convert({k: None for k in SCANS}, {}, {}, Policy(ROOT))
    else:
        r = convert(reports, conf, load_impl(ROOT), Policy(ROOT))
    try:
        out = pathlib.Path(a.out); out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(r, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError as e:
        print(f"無法寫出 {a.out}：{e}", file=sys.stderr)
        return 2
    print("G5 ZAP：" + "、".join(f"{k}={v['state']}" for k, v in r["coverage"].items())
          + f"；發現 {len(r['results'])} 項")
    return 0


if __name__ == "__main__":
    sys.exit(main())
