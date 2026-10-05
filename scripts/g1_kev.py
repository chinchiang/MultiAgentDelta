#!/usr/bin/env python3
"""VibeSec G1：相依套件的 CVE 若收錄於 CISA KEV → 發出 vibesec.g1.kev-hit（blocking，見 config/policy/blocking-policy.yaml）。

輸入：grype JSON（`grype ... -o json`）與 CISA KEV feed（known_exploited_vulnerabilities.json）。
輸出：SARIF（上傳 Code Scanning）與 JSON 摘要。

不可違反：
  - incomplete ≠ pass（CLAUDE.md #2）：缺 grype 結果或 KEV feed 無法解析 → 退出碼 2、JSON status=incomplete，絕不輸出「沒有命中」。
  - 評分不混算（CLAUDE.md #4）：CVSS、EPSS、KEV 分欄記錄；這裡只記 KEV 是否收錄與收錄日期，不改嚴重度、不相乘。

用法：
  python3 scripts/g1_kev.py --grype reports/grype-full.json --kev-feed .cache/kev.json \\
                            --sarif reports/g1-kev.sarif --json reports/g1-kev.json
  python3 scripts/g1_kev.py selftest
退出碼：0 已完成且無命中；1 有 KEV 命中（blocking：讓 nightly 轉紅、notify 開 issue；SARIF 照常寫出）；
        2 incomplete（輸入缺漏或無法解析）。
"""
from __future__ import annotations
import argparse, datetime, json, pathlib, re, sys

RULE = "vibesec.g1.kev-hit"
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


def to_sarif(hits: list[dict]) -> dict:
    rule = {"id": RULE, "name": RULE, "shortDescription": {"text": "相依套件 CVE 收錄於 CISA KEV（已遭實際利用）"},
            "defaultConfiguration": {"level": "error"}, "properties": {"policy_tier": "blocking"}}
    results = [{
        "ruleId": RULE, "level": "error",
        "message": {"text": f"{h['package']}@{h['version']} 含 {h['cve']}，已收錄於 CISA KEV（{h['kev_date']}）"
                            + (f"；可升級至 {', '.join(h['fixed_versions'])}" if h["fixed_versions"] else "；尚無修正版")},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": h["uri"]}}}],
        # 分欄記錄（CLAUDE.md #4）：KEV 與日期各自一欄，不與 CVSS／EPSS 混算
        "properties": {"policy_tier": "blocking", "cve": h["cve"], "kev": True, "kev_date": h["kev_date"],
                       "package": h["package"], "version": h["version"], "ecosystem": h["ecosystem"]},
    } for h in hits]
    return {"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "vibesec-g1-kev", "version": "1.0.0",
                                          "informationUri": "https://github.com/chinchiang/MultiAgentDelta",
                                          "rules": [rule]}}, "results": results}]}


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
    hits = find_hits(grype, kev)
    return {**base, "status": "fail" if hits else "pass", "status_reason": None, "kev_catalog_size": len(kev),
            "kev_catalog_released": released,
            "matches_checked": len(grype.get("matches") or []), "hits": hits}, hits


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
        {"vulnerability": {"id": "CVE-2099-0001"}, "artifact": {"name": "safe", "version": "1.0"}},
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
    a = ap.parse_args(argv)
    summary, hits = run(pathlib.Path(a.grype), pathlib.Path(a.kev_feed))
    for out in (a.sarif, a.json):
        pathlib.Path(out).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(a.json).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    if summary["status"] == "incomplete":
        print(f"::error::KEV 檢查未完成（incomplete ≠ pass）：{summary['status_reason']}")
        return 2
    pathlib.Path(a.sarif).write_text(json.dumps(to_sarif(hits), ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"KEV：檢查 {summary['matches_checked']} 筆 grype 結果，命中 {len(hits)} 筆"
          + "".join(f"\n  {h['cve']} {h['package']}@{h['version']}（KEV {h['kev_date']}）" for h in hits))
    if hits:
        print(f"::error::KEV 命中 {len(hits)} 筆（{RULE}，blocking）：需升級或移除受影響套件")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
