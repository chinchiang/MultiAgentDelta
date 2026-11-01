#!/usr/bin/env python3
"""VibeSec G1：相依套件的 CVE 若收錄於 CISA KEV → 發出 vibesec.g1.kev-hit（blocking，見 config/policy/blocking-policy.yaml）。
其餘 grype 命中的已知漏洞 → vibesec.g1.vulnerable-dependency（advisory）；同一漏洞只歸一條規則（KEV 優先）。

輸入：grype JSON（`grype ... -o json`）與 CISA KEV feed（known_exploited_vulnerabilities.json）。
輸出：SARIF（上傳 Code Scanning）與 JSON 摘要。

不可違反：
  - incomplete ≠ pass（AGENTS.md #2）：缺 grype 結果或 KEV feed 無法解析 → 退出碼 2、JSON status=incomplete，絕不輸出「沒有命中」。
  - 評分不混算（AGENTS.md #4）：CVSS、EPSS、KEV 分欄記錄；這裡只記 KEV 是否收錄與收錄日期，不改嚴重度、不相乘。

用法：
  python3 scripts/fetch_kev.py --out .cache/kev.json --meta reports/kev-source.json   # 官網 → 鏡像 → 快取
  python3 scripts/g1_kev.py --grype reports/grype-full.json --kev-feed .cache/kev.json \\
                            --sarif reports/g1-kev.sarif --json reports/g1-kev.json --kev-source reports/kev-source.json
  # PR 階段：把結果併入 g1_slopcheck.py 產生的 G1 gate-result（summary 依此彙整）
  python3 scripts/g1_kev.py ... --merge-gate reports/g1-gate.json
  python3 scripts/g1_kev.py selftest
退出碼依政策 tier（#244）：0 已完成且沒有 blocking 發現；1 有 blocking 發現（現行政策下即 KEV 命中：讓 nightly 轉紅、
        notify 開 issue；SARIF 照常寫出）；2 incomplete（輸入缺漏或無法解析）。kev-hit 只有在 tier_overrides 的
        demote_to_advisory 列出時才是 advisory（政策變更，AGENTS.md 規則 1）：這時命中只警告、退出碼 0。
"""
from __future__ import annotations
import argparse, datetime, json, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULE = "vibesec.g1.kev-hit"
VULN_RULE = "vibesec.g1.vulnerable-dependency"
TOOL_NAME, TOOL_VERSION = "vibesec-g1-kev", "1.0.0"
sys.path.insert(0, str(ROOT / "scripts"))
import gate_result  # noqa: E402  併入的 tool 列與自產 SARIF 骨架只有一份寫法（#182）；不依賴 PyYAML
CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
# Code Scanning 只收 repo 內檔案：套件位置取不到時，指向產生此結果的 workflow（與 G5 探針一致）
FALLBACK_URI = ".github/workflows/nightly-full.yml"


def load_kev(path: pathlib.Path) -> tuple[dict[str, str | None], str | None]:
    """回傳 ({CVE: dateAdded}, feed 發布時間)。發布時間寫進摘要，讓「下載失敗、改用舊快取」看得出來。
    dateReleased 缺席、無法解析或超過 fetch_kev.MAX_CACHE_AGE_DAYS → ValueError（run() 記 incomplete）：
    過期的清單比對不到之後才收錄的 CVE。不能只靠 fetch_kev.py——鏡像下載成功時它不檢查年齡，
    步驟失敗時 Actions cache 還原的舊檔也會留著。"""
    sys.path.insert(0, str(ROOT / "scripts"))
    from fetch_kev import MAX_CACHE_AGE_DAYS, _age_days
    data = json.loads(path.read_text(encoding="utf-8"))
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list) or not vulns:
        raise ValueError("KEV feed 沒有 vulnerabilities 清單")
    age = _age_days(data.get("dateReleased")) if data.get("dateReleased") else None
    if age is None or age > MAX_CACHE_AGE_DAYS:
        raise ValueError(f"KEV feed 過舊或發布時間無法判定（dateReleased {data.get('dateReleased')!r}，"
                         f"上限 {MAX_CACHE_AGE_DAYS:g} 天）")
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
    """取 grype 提供的 CVSS：v4.0 優先，其次 v3.x。只照抄向量與分數，不換算、不與 EPSS／KEV 相乘（AGENTS.md #4）。"""
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


def to_sarif(hits: list[dict], vulns: list[dict] | None, policy: "Policy") -> dict:
    """policy：tier 唯一來源（blocking-policy，第四次審視 S-11）；由進入點建立一次傳入。"""
    kev_tier, vuln_tier = policy.tier(RULE), policy.tier(VULN_RULE)
    lvl = lambda t: "error" if t == "blocking" else "warning"
    rule = {"id": RULE, "name": RULE, "shortDescription": {"text": "相依套件 CVE 收錄於 CISA KEV（已遭實際利用）"},
            "defaultConfiguration": {"level": lvl(kev_tier)}, "properties": {"policy_tier": kev_tier}}
    results = [{
        "ruleId": RULE, "level": lvl(kev_tier),
        "message": {"text": f"{h['package']}@{h['version']} 含 {h['cve']}，已收錄於 CISA KEV（{h['kev_date']}）"
                            + (f"；可升級至 {', '.join(h['fixed_versions'])}" if h["fixed_versions"] else "；尚無修正版")},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": h["uri"]}}}],
        # 分欄記錄（AGENTS.md #4）：KEV 與日期各自一欄，不與 CVSS／EPSS 混算
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
    return gate_result.sarif({"name": TOOL_NAME, "version": TOOL_VERSION}, [rule, vrule], results)


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
def tier_counts(hits: list[dict], vulns: list[dict], policy: "Policy") -> tuple[int, int]:
    """(blocking, advisory)：KEV 命中與已知漏洞各依政策 tier 計數；退出碼、併入的計數與 tool 列共用（#244）。"""
    kev_tier, vuln_tier = policy.tier(RULE), policy.tier(VULN_RULE)
    blocking = (len(hits) if kev_tier == "blocking" else 0) + (len(vulns) if vuln_tier == "blocking" else 0)
    return blocking, len(hits) + len(vulns) - blocking


def merge_gate(gate: dict, summary: dict, hits: list[dict], sarif_ref: str | None, policy: "Policy | None") -> dict:
    """把 KEV 結果（子結果）併入既有 G1 gate-result，狀態由 gate_verdict.merge 判定（只升不降、blocking 優先）。
    KEV 無法判定 → 控制 untested；命中 → 控制 fail，閘門是否 fail 依 vibesec.g1.kev-hit 的政策 tier。
    policy：None ＝ 政策讀不到（summary 為 incomplete、沒有任何發現可分類）→ tool 列為 gate_result 的統一形狀
    （error、exit_code／output_ref null，#182 決定 2）；一般 incomplete 維持 ran／exit_code 2。"""
    from gate_verdict import merge
    kev_status = summary["status"]
    # 沒有執行檢查（policy is None）：沒有命中、沒有已知漏洞，也不需要 tier
    blocking, advisory = (0, 0) if policy is None else tier_counts(hits, summary.get("vulnerable") or [], policy)
    state = {"pass": "pass", "fail": "fail", "incomplete": "untested"}[kev_status]
    return merge(gate, blocking=blocking, advisory=advisory,
                 coverage=[{"control_id": KEV_CONTROL, "state": state,
                            "reason": summary.get("status_reason") if kev_status == "incomplete" else None}],
                 problems=[f"KEV：{summary['status_reason']}"] if kev_status == "incomplete" else [],
                 notes=[f"KEV 命中 {len(hits)} 筆（{', '.join(sorted({h['cve'] for h in hits}))}）"] if hits else [],
                 tools=[gate_result.tool(TOOL_NAME, "error", version=TOOL_VERSION) if policy is None else
                        gate_result.tool(TOOL_NAME, "ran", version=TOOL_VERSION,
                                         exit_code=2 if kev_status == "incomplete" else (1 if blocking else 0),   # 依政策 tier（#244）
                                         output_ref=sarif_ref)])


def selftest() -> list[str]:
    import tempfile
    sys.path.insert(0, str(ROOT / "scripts"))
    from vibesec_policy import Policy
    P = Policy(ROOT)
    fails: list[str] = []
    ago = lambda days: (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)).isoformat()
    kev_feed = {"dateReleased": ago(1), "vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}]}
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
        sarif = to_sarif(hits, None, P)
        r0 = sarif["runs"][0]["results"][0] if hits else {}
        if r0.get("ruleId") != RULE or r0.get("properties", {}).get("kev_date") != "2021-12-10" or "cvss" in json.dumps(r0).lower():
            fails.append("SARIF 結果應為 kev-hit、帶 kev_date，且不混入 CVSS")
        # vulnerable-dependency：KEV 關聯（含 GHSA→CVE）不重複列；CVE-2099-0001 列為 advisory、帶 CVSS v4 優先
        vulns = s.get("vulnerable") or []
        if [v["id"] for v in vulns] != ["CVE-2099-0001"]:
            fails.append(f"非 KEV 漏洞應只有 CVE-2099-0001：{vulns}")
        elif (vulns[0]["cvss"] or {}).get("version") != "4.0":
            fails.append(f"CVSS 應優先取 v4.0：{vulns[0]['cvss']}")
        vs = to_sarif(hits, vulns, P)["runs"][0]
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
        # feed 年齡：比對的是過期的 KEV 清單時，之後才收錄的 CVE 都比對不到，卻照樣記 pass（fail-open）。
        # 不能只靠 fetch_kev.py：它只在改用快取時檢查年齡，鏡像下載成功不檢查，步驟失敗時 Actions cache 還原的舊檔也會留著
        g.write_text(json.dumps({"matches": [grype["matches"][3]]}))
        for label, released, want in [
            ("6 天前發布（上限內）", ago(6), "pass"),
            ("8 天前發布（超過 7 天上限）", ago(8), "incomplete"),
            ("缺 dateReleased", None, "incomplete"),
            ("dateReleased 無法解析", "上週二", "incomplete"),
        ]:
            feed = {**kev_feed, "dateReleased": released} if released else {"vulnerabilities": kev_feed["vulnerabilities"]}
            k.write_text(json.dumps(feed))
            st = run(g, k)[0]
            if st["status"] != want or (want == "incomplete" and "dateReleased" not in (st.get("status_reason") or "")):
                fails.append(f"KEV feed {label} → {want}（得到 {st['status']}：{st.get('status_reason')}）")
    # merge_gate：只升不降、incomplete ≠ pass
    base = {"gate": "G1", "status": "pass", "status_reason": None, "findings_count": {"blocking": 0, "advisory": 2},
            "tools": [], "coverage": []}
    hit = [{"cve": "CVE-2021-44228"}]
    m = merge_gate(base, {"status": "fail", "vulnerable": [{"id": "x"}]}, hit, "r.sarif", P)
    if m["status"] != "fail" or m["findings_count"] != {"blocking": 1, "advisory": 3} or m["coverage"][-1]["state"] != "fail":
        fails.append(f"KEV 命中應讓 G1 fail 並加 1 筆 blocking：{m}")
    m = merge_gate(base, {"status": "incomplete", "status_reason": "缺 KEV feed"}, [], None, P)
    if m["status"] != "incomplete" or "缺 KEV feed" not in (m["status_reason"] or "") or m["coverage"][-1]["state"] != "untested":
        fails.append(f"KEV incomplete 應讓原本 pass 的 G1 變 incomplete：{m}")
    m = merge_gate({**base, "status": "fail"}, {"status": "incomplete", "status_reason": "x"}, [], None, P)
    if m["status"] != "fail":
        fails.append("G1 已 fail 時 KEV incomplete 不得降為 incomplete")
    m = merge_gate({**base, "status": "incomplete", "status_reason": "slop"}, {"status": "pass"}, [], None, P)
    if m["status"] != "incomplete" or m["status_reason"] != "slop":
        fails.append("KEV pass 不得把 incomplete 的 G1 洗成 pass")
    if base["status"] != "pass" or base["tools"]:
        fails.append("merge_gate 不得修改輸入物件")
    # slopcheck 預留的 KEV pending：沒併入 → 最終判定 incomplete；併入後被取代（只留一筆）
    from gate_verdict import is_clean
    held = {**base, "coverage": [{"control_id": "VS-G1-SBOM", "state": "pass", "reason": None},
                                 {"control_id": KEV_CONTROL, "state": "pending", "reason": None}]}
    m = merge_gate(held, {"status": "pass"}, [], None, P)
    if is_clean(held) or not is_clean(m) or [c["state"] for c in m["coverage"] if c["control_id"] == KEV_CONTROL] != ["pass"]:
        fails.append(f"KEV 預留的 pending 應在併入時被取代，未併入則不乾淨：{m['coverage']}")
    # 政策檔讀不到 → 進入點就停：摘要 incomplete 並寫明未完成原因、沒有任何發現、退出碼 2；
    # 併入的 G1 為 incomplete、控制 untested（以前退回預設 tier 照樣判定，或以例外結束）
    import contextlib, io
    from vibesec_policy import POLICY_UNREADABLE, broken_policy_root
    with broken_policy_root() as pr, tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
        js, sf, gp = pathlib.Path(d, "out.json"), pathlib.Path(d, "out.sarif"), pathlib.Path(d, "G1.json")
        gp.write_text(json.dumps({**base, "coverage": [{"control_id": KEV_CONTROL, "state": "pending", "reason": None}]}), encoding="utf-8")
        sf.write_text('{"stale": true}', encoding="utf-8")   # 上一次留下的 SARIF
        rc = main(["--grype", str(pathlib.Path(d, "g.json")), "--kev-feed", str(pathlib.Path(d, "k.json")),
                       "--sarif", str(sf), "--json", str(js), "--merge-gate", str(gp)], policy_root=pr)
        sm, g = json.loads(js.read_text(encoding="utf-8")), json.loads(gp.read_text(encoding="utf-8"))
        st = [c["state"] for c in g["coverage"] if c["control_id"] == KEV_CONTROL]
        # 接線（#182）：併入的 tool 列是 gate_result.tool 的統一形狀（error、exit_code／output_ref null）；舊 SARIF 刪掉（以前留著）
        if rc != 2 or sm.get("status") != "incomplete" or not str(sm.get("status_reason")).startswith(POLICY_UNREADABLE + "（") \
                or g["status"] != "incomplete" or POLICY_UNREADABLE not in (g["status_reason"] or "") or st != ["untested"] \
                or g["findings_count"] != base["findings_count"] \
                or g["tools"][-1:] != [gate_result.tool(TOOL_NAME, "error", version=TOOL_VERSION)] or sf.exists():
            fails.append(f"KEV：政策檔讀不到 → 退出碼 2、incomplete、G1 incomplete 且控制 untested、tool 列 error、"
                         f"舊 SARIF 刪掉（得到 {rc}、SARIF 存在={sf.exists()}、{sm}、{g}）")
    # 一般 incomplete（grype 結果缺席）：tool 列維持 ran／exit_code 2；舊 SARIF 同樣刪掉（#182 決定 1）
    with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
        js, sf, gp = pathlib.Path(d, "out.json"), pathlib.Path(d, "out.sarif"), pathlib.Path(d, "G1.json")
        gp.write_text(json.dumps({**base, "coverage": [{"control_id": KEV_CONTROL, "state": "pending", "reason": None}]}), encoding="utf-8")
        sf.write_text('{"stale": true}', encoding="utf-8")
        rc = main(["--grype", str(pathlib.Path(d, "g.json")), "--kev-feed", str(pathlib.Path(d, "k.json")),
                   "--sarif", str(sf), "--json", str(js), "--merge-gate", str(gp)])
        g = json.loads(gp.read_text(encoding="utf-8"))
        if rc != 2 or g["status"] != "incomplete" \
                or g["tools"][-1:] != [gate_result.tool(TOOL_NAME, "ran", version=TOOL_VERSION, exit_code=2)] or sf.exists():
            fails.append(f"KEV：一般 incomplete → tool 列 ran／exit_code 2、舊 SARIF 刪掉（得到 {rc}、SARIF 存在={sf.exists()}、{g['tools']}）")
    # 退出碼、訊息與併入的 tool 列依政策 tier（#244）：kev-hit 只能由 tier_overrides 的 demote_to_advisory 降級（政策變更，
    # AGENTS.md 規則 1；Policy.tier 不套用路徑型的政策例外）。降級後命中是 advisory → 退出碼 0、只警告，不再讓 nightly 轉紅
    from vibesec_policy import temp_policy_root, write_policy_key
    import yaml
    no_hit = {"matches": [m for m in grype["matches"] if m["artifact"]["name"] == "safe"]}
    for label, demote, data, want_rc, want_level in [
        ("現行政策（kev-hit blocking）有命中", False, grype, 1, "error"),
        ("kev-hit 由 demote_to_advisory 降級、有命中", True, grype, 0, "warning"),
        ("沒有 KEV 命中", False, no_hit, 0, None),
    ]:
        out = io.StringIO()
        with temp_policy_root() as pr, tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(out):
            if demote:   # 每個風險層級都降級：不依賴 repo 目前的 risk_tier
                pol = yaml.safe_load((pr / "config/policy/blocking-policy.yaml").read_text(encoding="utf-8"))
                write_policy_key(pr, "tier_overrides", {t: {**ov, "demote_to_advisory": [*(ov.get("demote_to_advisory") or []), RULE]}
                                                        for t, ov in (pol.get("tier_overrides") or {}).items()})
            g, k, js, sf, gp = (pathlib.Path(d, n) for n in ("g.json", "k.json", "out.json", "out.sarif", "G1.json"))
            g.write_text(json.dumps(data)); k.write_text(json.dumps(kev_feed))
            gp.write_text(json.dumps({**base, "coverage": [{"control_id": KEV_CONTROL, "state": "pending", "reason": None}]}), encoding="utf-8")
            rc = main(["--grype", str(g), "--kev-feed", str(k), "--sarif", str(sf), "--json", str(js), "--merge-gate", str(gp)],
                      policy_root=pr)
            merged = json.loads(gp.read_text(encoding="utf-8"))
        tool_rc = [x.get("exit_code") for x in merged["tools"] if x["name"] == TOOL_NAME]
        kev_lines = [ln for ln in out.getvalue().splitlines() if ln.startswith("::") and "KEV 命中" in ln]
        want_lines = [] if want_level is None else [f"::{want_level}::"]
        tier_word = "advisory" if demote else "blocking"
        if rc != want_rc or tool_rc != [want_rc] or [ln[:len(want_lines[0])] for ln in kev_lines] != want_lines \
                or (kev_lines and f"（{RULE}，{tier_word}）" not in kev_lines[0]):
            fails.append(f"KEV 進入點「{label}」：應為退出碼 {want_rc}、併入的 tool 列 exit_code {want_rc}、"
                         f"命中訊息 {want_level or '無'}（{tier_word}）（得到 {rc}、{tool_rc}、{kev_lines}）")
    return fails


def main(argv=None, policy_root: pathlib.Path = ROOT) -> int:
    """policy_root：阻擋政策所在的 repo（selftest 指向壞政策檔）。"""
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
    ap.add_argument("--kev-source", help="scripts/fetch_kev.py 的來源紀錄（--meta）；附進摘要，看得出用了官網、鏡像或舊快取")
    a = ap.parse_args(argv)
    sys.path.insert(0, str(ROOT / "scripts"))
    from vibesec_policy import load_policy
    policy, problem = load_policy(policy_root)   # 進入點只建立一次；讀不到 → incomplete，不執行檢查（不再退回規則預設 tier）
    if problem:
        summary, hits = {"rule_id": RULE, "status": "incomplete", "status_reason": problem}, []
    else:
        summary, hits = run(pathlib.Path(a.grype), pathlib.Path(a.kev_feed))
    if a.kev_source:
        try:
            summary["kev_source"] = json.loads(pathlib.Path(a.kev_source).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            summary["kev_source"] = {"status": "unknown", "status_reason": f"來源紀錄無法讀取：{type(e).__name__}"}
    for out in (a.sarif, a.json):
        pathlib.Path(out).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(a.json).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    if a.merge_gate:
        gp = pathlib.Path(a.merge_gate)
        if gp.is_file():
            ref = a.sarif if summary["status"] != "incomplete" else None
            merged = merge_gate(json.loads(gp.read_text(encoding="utf-8")), summary, hits, ref, policy)
            gp.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
        else:
            print(f"::warning::{gp} 不存在，KEV 結果未併入 G1 gate（summary 會顯示 G1 untested）")
    if summary["status"] == "incomplete":
        # 沒有判定任何發現：刪掉上一次的 SARIF（以前留著，會被當成這一次的結果；上傳步驟以 hashFiles 略過，#182 決定 1）
        gate_result.remove_stale(a.sarif)
        print(f"::error::KEV 檢查未完成（incomplete ≠ pass）：{summary['status_reason']}")
        return 2
    vulns = summary.get("vulnerable") or []
    pathlib.Path(a.sarif).write_text(json.dumps(to_sarif(hits, vulns, policy), ensure_ascii=False, indent=2), encoding="utf-8")
    kev_tier, vuln_tier = policy.tier(RULE), policy.tier(VULN_RULE)
    print(f"已知漏洞（非 KEV，{vuln_tier}）：{len(vulns)} 筆")
    print(f"KEV：檢查 {summary['matches_checked']} 筆 grype 結果，命中 {len(hits)} 筆"
          + "".join(f"\n  {h['cve']} {h['package']}@{h['version']}（KEV {h['kev_date']}）" for h in hits))
    # 退出碼與訊息依政策 tier（#244）：有 blocking 發現 → 1（讓 nightly 轉紅）；kev-hit 被 tier_overrides 降級時只警告
    if hits:
        level = "error" if kev_tier == "blocking" else "warning"
        print(f"::{level}::KEV 命中 {len(hits)} 筆（{RULE}，{kev_tier}）：需升級或移除受影響套件")
    return 1 if tier_counts(hits, vulns, policy)[0] else 0


if __name__ == "__main__":
    sys.exit(main())
