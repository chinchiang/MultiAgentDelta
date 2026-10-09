#!/usr/bin/env python3
"""VibeSec G1：相依套件的 CVE 若收錄於 CISA KEV → 發出 vibesec.g1.kev-hit（blocking，見 config/policy/blocking-policy.yaml）。
其餘 grype 命中的已知漏洞 → vibesec.g1.vulnerable-dependency（advisory）；同一漏洞只歸一條規則（KEV 優先）。

輸入：grype JSON（`grype ... -o json`）與 CISA KEV feed（known_exploited_vulnerabilities.json）。
輸出：SARIF（上傳 Code Scanning）與 JSON 摘要。

不可違反：
  - incomplete ≠ pass（CLAUDE.md #2）：缺 grype 結果或 KEV feed 無法解析 → 退出碼 2、JSON status=incomplete，絕不輸出「沒有命中」。
  - 評分不混算（CLAUDE.md #4）：CVSS、EPSS、KEV 分欄記錄；這裡只記 KEV 是否收錄與收錄日期，不改嚴重度、不相乘。

用法：
  python3 scripts/g1_kev.py --grype reports/grype-full.json --kev-feed .cache/kev.json \\
                            --sarif reports/g1-kev.sarif --json reports/g1-kev.json
  # PR 階段：把結果併入 g1_slopcheck.py 產生的 G1 gate-result（summary 依此彙整）
  python3 scripts/g1_kev.py ... --merge-gate reports/g1-gate.json
  python3 scripts/g1_kev.py selftest
退出碼：0 已完成且無命中；1 有 KEV 命中（blocking：讓 nightly 轉紅、notify 開 issue；SARIF 照常寫出）；
        2 incomplete（輸入缺漏或無法解析）。
"""
from __future__ import annotations
import argparse, datetime, json, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULE = "vibesec.g1.kev-hit"
VULN_RULE = "vibesec.g1.vulnerable-dependency"
CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
# Code Scanning 只收 repo 內檔案：套件位置取不到時，指向產生此結果的 workflow（與 G5 探針一致）
FALLBACK_URI = ".github/workflows/nightly-full.yml"


def load_kev(path: pathlib.Path) -> tuple[dict[str, str | None], str | None]:
    """回傳 ({CVE: dateAdded}, feed 發布時間)。發布時間寫進摘要，讓「下載失敗、改用舊快取」看得出來。"""
    data = json.loads(path.read_text(encoding="utf-8"))
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list) or not vulns:
        raise ValueError("KEV feed 沒有 vulnerabilities 清單")
    return ({v["cveID"]: v.get("dateAdded") for v in vulns if isinstance(v, dict) and v.get("cveID")},
            data.get("dateReleased"))


def match_cves(m: dict) -> list[str]:
    ids = [(m.get("vulnerability") or {}).get("id")]
    ids += [r.get("id") for r in m.get("relatedVulnerabilities") or []]
    return sorted({i for i in ids if i and CVE.match(i)})


def repo_uri(artifact: dict) -> str:
    for loc in artifact.get("locations") or []:
        p = str(loc.get("path") or "").lstrip("/")
        if p and ".." not in pathlib.PurePosixPath(p).parts:
            return p
    return FALLBACK_URI


def find_hits(grype: dict, kev: dict[str, str | None]) -> list[dict]:
    hits, seen = [], set()
    for m in grype.get("matches") or []:
        art = m.get("artifact") or {}
        for cve in match_cves(m):
            if cve not in kev:
                continue
            key = (cve, art.get("name"), art.get("version"))
            if key in seen:
                continue
            seen.add(key)
            fix = (m.get("vulnerability") or {}).get("fix") or {}
            hits.append({"cve": cve, "kev": True, "kev_date": kev[cve], "package": art.get("name"),
                         "version": art.get("version"), "ecosystem": art.get("type"),
                         "fixed_versions": fix.get("versions") or [], "uri": repo_uri(art)})
    return sorted(hits, key=lambda h: (h["cve"], h["package"] or "", h["version"] or ""))


def best_cvss(v: dict) -> dict | None:
    """取 grype 提供的 CVSS：v4.0 優先，其次 v3.x。只照抄向量與分數，不換算、不與 EPSS／KEV 相乘（CLAUDE.md #4）。"""
    entries = [c for c in v.get("cvss") or [] if isinstance(c, dict) and c.get("vector")]
    def rank(c):
        ver = str(c.get("version") or "")
        return (ver.startswith("4"), ver)
    if not entries:
        return None
    c = max(entries, key=rank)
    return {"version": c.get("version"), "vector": c.get("vector"),
            "base_score": (c.get("metrics") or {}).get("baseScore")}


def find_vulns(grype: dict, kev: dict[str, str | None]) -> list[dict]:
    """KEV 以外的已知漏洞。任一關聯 CVE 在 KEV 中 → 交給 kev-hit，不重複列為 advisory。"""
    out, seen = [], set()
    for m in grype.get("matches") or []:
        art, v = m.get("artifact") or {}, m.get("vulnerability") or {}
        vid, cves = v.get("id"), match_cves(m)
        if not vid or any(c in kev for c in cves):
            continue
        key = (vid, art.get("name"), art.get("version"))
        if key in seen:
            continue
        seen.add(key)
        fix = v.get("fix") or {}
        out.append({"id": vid, "cves": cves, "severity": v.get("severity"), "cvss": best_cvss(v),
                    "package": art.get("name"), "version": art.get("version"), "ecosystem": art.get("type"),
                    "fixed_versions": fix.get("versions") or [], "uri": repo_uri(art)})
    return sorted(out, key=lambda h: (h["id"], h["package"] or "", h["version"] or ""))


def _tier(rule: str) -> str:
    """tier 唯一來源是 blocking-policy（第四次審視 S-11）；政策檔讀不到時退回規則預設（只影響標籤）。"""
    try:
        sys.path.insert(0, str(ROOT / "scripts"))
        from vibesec_policy import Policy
        return Policy(ROOT).tier(rule)
    except Exception:
        return "blocking" if rule == RULE else "advisory"


def to_sarif(hits: list[dict], vulns: list[dict] | None = None) -> dict:
    kev_tier, vuln_tier = _tier(RULE), _tier(VULN_RULE)
    lvl = lambda t: "error" if t == "blocking" else "warning"
    rule = {"id": RULE, "name": RULE, "shortDescription": {"text": "相依套件 CVE 收錄於 CISA KEV（已遭實際利用）"},
            "defaultConfiguration": {"level": lvl(kev_tier)}, "properties": {"policy_tier": kev_tier}}
    results = [{
        "ruleId": RULE, "level": lvl(kev_tier),
        "message": {"text": f"{h['package']}@{h['version']} 含 {h['cve']}，已收錄於 CISA KEV（{h['kev_date']}）"
                            + (f"；可升級至 {', '.join(h['fixed_versions'])}" if h["fixed_versions"] else "；尚無修正版")},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": h["uri"]}}}],
        # 分欄記錄（CLAUDE.md #4）：KEV 與日期各自一欄，不與 CVSS／EPSS 混算
        "properties": {"policy_tier": kev_tier, "cve": h["cve"], "kev": True, "kev_date": h["kev_date"],
                       "package": h["package"], "version": h["version"], "ecosystem": h["ecosystem"]},
    } for h in hits]
    vrule = {"id": VULN_RULE, "name": VULN_RULE, "shortDescription": {"text": "相依套件含已知漏洞（未收錄於 KEV）"},
             "defaultConfiguration": {"level": lvl(vuln_tier)}, "properties": {"policy_tier": vuln_tier}}
    results += [{
        "ruleId": VULN_RULE, "level": lvl(vuln_tier),
        "message": {"text": f"{h['package']}@{h['version']} 含 {h['id']}（{h['severity'] or '嚴重度未知'}）"
                            + (f"；可升級至 {', '.join(h['fixed_versions'])}" if h["fixed_versions"] else "；尚無修正版")},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": h["uri"]}}}],
        # CVSS 原樣分欄；EPSS 由 nightly 富化另記（enrichment.json），這裡不混算
        "properties": {"policy_tier": vuln_tier, "vuln_id": h["id"], "cves": h["cves"], "kev": False,
                       "grype_severity": h["severity"], "cvss": h["cvss"],
                       "package": h["package"], "version": h["version"], "ecosystem": h["ecosystem"]},
    } for h in (vulns or [])]
    return {"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "vibesec-g1-kev", "version": "1.0.0",
                                          "informationUri": "https://github.com/chinchiang/MultiAgentDelta",
                                          "rules": [rule, vrule]}}, "results": results}]}


def run(grype_path: pathlib.Path, kev_path: pathlib.Path) -> tuple[dict, list[dict]]:
    """回傳 (摘要, 命中)。輸入有問題時摘要 status=incomplete、命中為空——呼叫端不得把它當成「沒有命中」。"""
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    base = {"rule_id": RULE, "checked_at": now}
    if not grype_path.is_file():
        return {**base, "status": "incomplete", "status_reason": f"缺 grype 結果：{grype_path}"}, []
    if not kev_path.is_file():
        return {**base, "status": "incomplete", "status_reason": f"缺 KEV feed：{kev_path}（下載失敗或快取不存在）"}, []
    try:
        kev, released = load_kev(kev_path)
        grype = json.loads(grype_path.read_text(encoding="utf-8"))
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as e:
        return {**base, "status": "incomplete", "status_reason": f"輸入無法解析：{type(e).__name__}: {e}"}, []
    if not isinstance(grype, dict) or not isinstance(grype.get("matches"), list):
        # {} 或 [] 不是「沒有命中」：grype 沒掃完或輸出格式不符（第四次審視 S-9）
        return {**base, "status": "incomplete", "status_reason": "grype 輸出沒有 matches 陣列（掃描未完成或格式不符）"}, []
    hits, vulns = find_hits(grype, kev), find_vulns(grype, kev)
    return {**base, "status": "fail" if hits else "pass", "status_reason": None, "kev_catalog_size": len(kev),
            "kev_catalog_released": released,
            "matches_checked": len(grype.get("matches") or []), "hits": hits, "vulnerable": vulns}, hits


KEV_CONTROL = "ASVS5-V15.2"   # cwe-map.yaml vibesec.g1.kev-hit 的 control_ids 之一
_RANK = {"pass": 0, "incomplete": 1, "fail": 2}


def merge_gate(gate: dict, summary: dict, hits: list[dict], sarif_ref: str | None) -> dict:
    """把 KEV 結果併入既有 G1 gate-result。嚴重度 fail > incomplete > pass，只升不降；
    KEV incomplete 會讓原本 pass 的 G1 變 incomplete（incomplete ≠ pass），原因附在 status_reason。"""
    g = json.loads(json.dumps(gate))
    kev_status = summary["status"]
    reasons = [r for r in [g.get("status_reason")] if r]
    if kev_status == "incomplete":
        reasons.append(f"KEV：{summary['status_reason']}")
    elif hits:
        reasons.append(f"KEV 命中 {len(hits)} 筆（{', '.join(sorted({h['cve'] for h in hits}))}）")
    cur = g.get("status", "pass")
    if cur in _RANK and _RANK[kev_status] > _RANK[cur]:
        g["status"] = kev_status
    g["status_reason"] = "；".join(reasons) or None
    fc = g.setdefault("findings_count", {"blocking": 0, "advisory": 0})
    fc[_tier(RULE)] = int(fc.get(_tier(RULE)) or 0) + len(hits)
    fc[_tier(VULN_RULE)] = int(fc.get(_tier(VULN_RULE)) or 0) + len(summary.get("vulnerable") or [])
    g.setdefault("tools", []).append({"name": "vibesec-g1-kev", "version": "1.0.0", "state": "ran",
                                      "exit_code": {"pass": 0, "fail": 1, "incomplete": 2}[kev_status],
                                      "output_ref": sarif_ref, "duration_seconds": None})
    state = {"pass": "pass", "fail": "fail", "incomplete": "untested"}[kev_status]
    g.setdefault("coverage", []).append({"control_id": KEV_CONTROL, "state": state,
                                         "reason": summary.get("status_reason") if kev_status == "incomplete" else None})
    return g


def selftest() -> list[str]:
    import tempfile
    fails: list[str] = []
    kev_feed = {"vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}]}
    grype = {"matches": [
        {"vulnerability": {"id": "CVE-2021-44228", "fix": {"versions": ["2.15.0"]}},
         "artifact": {"name": "log4j-core", "version": "2.14.1", "type": "java-archive", "locations": [{"path": "/pom.xml"}]}},
        # 同一 CVE 重複出現 → 只算一次
        {"vulnerability": {"id": "CVE-2021-44228"}, "artifact": {"name": "log4j-core", "version": "2.14.1"}},
        # GHSA 主 ID、CVE 在 relatedVulnerabilities
        {"vulnerability": {"id": "GHSA-jfh8-c2jp-5v3q"}, "relatedVulnerabilities": [{"id": "CVE-2021-44228"}],
         "artifact": {"name": "log4j-api", "version": "2.14.1", "locations": [{"path": "/../../etc/passwd"}]}},
        {"vulnerability": {"id": "CVE-2099-0001", "severity": "High",
                           "cvss": [{"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "metrics": {"baseScore": 9.8}},
                                    {"version": "4.0", "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "metrics": {"baseScore": 9.3}}]},
         "artifact": {"name": "safe", "version": "1.0"}},
    ]}
    with tempfile.TemporaryDirectory() as d:
        g, k = pathlib.Path(d, "g.json"), pathlib.Path(d, "k.json")
        g.write_text(json.dumps(grype)); k.write_text(json.dumps(kev_feed))
        s, hits = run(g, k)
        if s["status"] != "fail" or [(h["cve"], h["package"]) for h in hits] != [("CVE-2021-44228", "log4j-api"), ("CVE-2021-44228", "log4j-core")]:
            fails.append(f"應命中 log4j-core 與 log4j-api 各一次：{s['status']} {hits}")
        if hits and hits[1]["uri"] != "pom.xml":
            fails.append(f"套件位置應為 repo 相對路徑 pom.xml：{hits[1]['uri']}")
        if hits and hits[0]["uri"] != FALLBACK_URI:
            fails.append("含 .. 的位置不得使用，應退回 workflow 路徑")
        sarif = to_sarif(hits)
        r0 = sarif["runs"][0]["results"][0] if hits else {}
        if r0.get("ruleId") != RULE or r0.get("properties", {}).get("kev_date") != "2021-12-10" or "cvss" in json.dumps(r0).lower():
            fails.append("SARIF 結果應為 kev-hit、帶 kev_date，且不混入 CVSS")
        # vulnerable-dependency：KEV 關聯（含 GHSA→CVE）不重複列；CVE-2099-0001 列為 advisory、帶 CVSS v4 優先
        vulns = s.get("vulnerable") or []
        if [v["id"] for v in vulns] != ["CVE-2099-0001"]:
            fails.append(f"非 KEV 漏洞應只有 CVE-2099-0001：{vulns}")
        elif (vulns[0]["cvss"] or {}).get("version") != "4.0":
            fails.append(f"CVSS 應優先取 v4.0：{vulns[0]['cvss']}")
        vs = to_sarif(hits, vulns)["runs"][0]
        vr = [r for r in vs["results"] if r["ruleId"] == VULN_RULE]
        if len(vr) != 1 or vr[0]["level"] != "warning" or vr[0]["properties"]["policy_tier"] != "advisory" \
                or "epss" in json.dumps(vr[0]).lower():
            fails.append("vulnerable-dependency 應為 advisory warning，且不混入 EPSS")
        if {r["id"] for r in vs["tool"]["driver"]["rules"]} != {RULE, VULN_RULE}:
            fails.append("SARIF 應宣告兩條規則")
        # 沒有命中：pass（不是 incomplete）
        g.write_text(json.dumps({"matches": [grype["matches"][3]]}))
        if run(g, k)[0]["status"] != "pass":
            fails.append("無 KEV 命中應為 pass")
        # incomplete：缺檔、壞檔、空 feed —— 都不能變成 pass
        for label, gp, kp, setup in [
            ("缺 grype", pathlib.Path(d, "none.json"), k, None),
            ("缺 KEV", g, pathlib.Path(d, "none.json"), None),
            ("壞 KEV", g, k, lambda: k.write_text("{not json")),
            ("空 KEV", g, k, lambda: k.write_text(json.dumps({"vulnerabilities": []}))),
        ]:
            if setup: setup()
            st = run(gp, kp)[0]
            if st["status"] != "incomplete" or not st.get("status_reason"):
                fails.append(f"{label} 應為 incomplete 並附原因：{st}")
    # merge_gate：只升不降、incomplete ≠ pass
    base = {"gate": "G1", "status": "pass", "status_reason": None, "findings_count": {"blocking": 0, "advisory": 2},
            "tools": [], "coverage": []}
    hit = [{"cve": "CVE-2021-44228"}]
    m = merge_gate(base, {"status": "fail", "vulnerable": [{"id": "x"}]}, hit, "r.sarif")
    if m["status"] != "fail" or m["findings_count"] != {"blocking": 1, "advisory": 3} or m["coverage"][-1]["state"] != "fail":
        fails.append(f"KEV 命中應讓 G1 fail 並加 1 筆 blocking：{m}")
    m = merge_gate(base, {"status": "incomplete", "status_reason": "缺 KEV feed"}, [], None)
    if m["status"] != "incomplete" or "缺 KEV feed" not in (m["status_reason"] or "") or m["coverage"][-1]["state"] != "untested":
        fails.append(f"KEV incomplete 應讓原本 pass 的 G1 變 incomplete：{m}")
    m = merge_gate({**base, "status": "fail"}, {"status": "incomplete", "status_reason": "x"}, [], None)
    if m["status"] != "fail":
        fails.append("G1 已 fail 時 KEV incomplete 不得降為 incomplete")
    m = merge_gate({**base, "status": "incomplete", "status_reason": "slop"}, {"status": "pass"}, [], None)
    if m["status"] != "incomplete" or m["status_reason"] != "slop":
        fails.append("KEV pass 不得把 incomplete 的 G1 洗成 pass")
    if base["status"] != "pass" or base["tools"]:
        fails.append("merge_gate 不得修改輸入物件")
    return fails


def main(argv=None) -> int:
    if (argv if argv is not None else sys.argv[1:])[:1] == ["selftest"]:
        fails = selftest()
        print("\n".join(f"FAIL {x}" for x in fails) or "g1_kev selftest ok")
        return 1 if fails else 0
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--grype", required=True)
    ap.add_argument("--kev-feed", required=True)
    ap.add_argument("--sarif", required=True)
    ap.add_argument("--json", required=True)
    ap.add_argument("--merge-gate", help="併入既有的 G1 gate-result（就地更新）；檔案不存在則略過")
    a = ap.parse_args(argv)
    summary, hits = run(pathlib.Path(a.grype), pathlib.Path(a.kev_feed))
    for out in (a.sarif, a.json):
        pathlib.Path(out).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(a.json).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    if a.merge_gate:
        gp = pathlib.Path(a.merge_gate)
        if gp.is_file():
            ref = a.sarif if summary["status"] != "incomplete" else None
            merged = merge_gate(json.loads(gp.read_text(encoding="utf-8")), summary, hits, ref)
            gp.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
        else:
            print(f"::warning::{gp} 不存在，KEV 結果未併入 G1 gate（summary 會顯示 G1 untested）")
    if summary["status"] == "incomplete":
        print(f"::error::KEV 檢查未完成（incomplete ≠ pass）：{summary['status_reason']}")
        return 2
    vulns = summary.get("vulnerable") or []
    pathlib.Path(a.sarif).write_text(json.dumps(to_sarif(hits, vulns), ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已知漏洞（非 KEV，advisory）：{len(vulns)} 筆")
    print(f"KEV：檢查 {summary['matches_checked']} 筆 grype 結果，命中 {len(hits)} 筆"
          + "".join(f"\n  {h['cve']} {h['package']}@{h['version']}（KEV {h['kev_date']}）" for h in hits))
    if hits:
        print(f"::error::KEV 命中 {len(hits)} 筆（{RULE}，blocking）：需升級或移除受影響套件")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
