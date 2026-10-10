#!/usr/bin/env python3
"""VibeSec G1：相依套件已停止維護或被標記 deprecated → vibesec.g1.unmaintained-dependency（advisory）。

資料來源：SBOM（Syft CycloneDX）列出的套件，逐一查 deps.dev v3 API（Google Open Source Insights）。
判定（兩個訊號，任一成立即命中）：
  - deprecated：所用版本在套件登錄處被標記 deprecated（deps.dev isDeprecated）
  - stale：套件的預設（最新）版本發布已超過 vibesec.yaml gates.g1_supply_chain.unmaintained_days 天
範圍：deps.dev 支援的生態系（pypi / npm / golang / maven / cargo / nuget）。GitHub Actions（pkg:github）不在範圍，
      列為 not_applicable 並附原因（Actions 版本由 Dependabot 追蹤）。

不可違反：
  - incomplete ≠ pass（CLAUDE.md #2）：SBOM 缺漏、API 失敗、套件查無資料 → 退出碼 2、JSON status=incomplete，
    絕不把「沒查到」寫成「沒有命中」。
  - 只記錄日期與旗標，不換算分數、不與 CVSS／EPSS 混算（CLAUDE.md #4）。

用法：
  python3 scripts/g1_maintenance.py --sbom reports/sbom.cdx.json --sarif reports/g1-maintenance.sarif \\
                                    --json reports/g1-maintenance.json
  python3 scripts/g1_maintenance.py selftest
退出碼：0 已完成（有無命中皆是；advisory 不讓步驟失敗）；2 incomplete。
"""
from __future__ import annotations
import argparse, datetime, json, os, pathlib, re, ssl, sys, time, urllib.error, urllib.parse, urllib.request

RULE = "vibesec.g1.unmaintained-dependency"
ROOT = pathlib.Path(__file__).resolve().parent.parent
API_BASE = "https://api.deps.dev"
API_PATH = "/v3/systems/{system}/packages/{name}"
SYSTEMS = {"pypi": "pypi", "npm": "npm", "golang": "go", "maven": "maven", "cargo": "cargo", "nuget": "nuget"}
DEFAULT_DAYS = 730
FALLBACK_URI = ".github/workflows/nightly-full.yml"
PURL = re.compile(r"^pkg:(?P<type>[a-z]+)/(?P<path>[^@?#]+)@(?P<version>[^?#]+)")


def configured_days() -> int:
    """讀 vibesec.yaml 的 unmaintained_days（無 PyYAML 也能讀：只取這一個純量）。"""
    try:
        txt = (ROOT / "vibesec.yaml").read_text(encoding="utf-8")
        m = re.search(r"^\s*unmaintained_days\s*:\s*(\d+)", txt, re.M)
        return int(m.group(1)) if m else DEFAULT_DAYS
    except OSError:
        return DEFAULT_DAYS


def _norm(ptype: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if ptype == "pypi" else name


def first_party(root: pathlib.Path = ROOT) -> set[tuple[str, str]]:
    """本 repo 自己宣告的專案（pyproject.toml [project].name、package.json name）。
    它們會出現在 SBOM 裡，但不是發布到登錄處的相依套件，查不到維護資料是正常的，不算 incomplete。"""
    names: set[tuple[str, str]] = set()
    skip = {".git", "node_modules", ".venv", "venv"}
    for p in root.rglob("pyproject.toml"):
        if skip & set(p.relative_to(root).parts):
            continue
        txt = p.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"^\[project\][^\[]*?^name\s*=\s*[\"']([^\"']+)[\"']", txt, re.M | re.S)
        if m:
            names.add(("pypi", _norm("pypi", m.group(1))))
    for p in root.rglob("package.json"):
        if skip & set(p.relative_to(root).parts):
            continue
        try:
            n = json.loads(p.read_text(encoding="utf-8")).get("name")
        except (ValueError, OSError):
            continue
        if isinstance(n, str) and n:
            names.add(("npm", n))
    return names


def parse_sbom(sbom: dict, own: set[tuple[str, str]] | None = None) -> tuple[list[dict], list[dict]]:
    """回傳 (要查的套件, not_applicable 套件)。同一 (system, name, version) 只查一次。"""
    own = own or set()
    todo, na, seen = [], [], set()
    for c in sbom.get("components") or []:
        m = PURL.match(str(c.get("purl") or ""))
        if not m:
            continue
        ptype = m["type"]
        name = urllib.parse.unquote(m["path"])
        version = urllib.parse.unquote(m["version"])
        if ptype == "maven":
            name = name.replace("/", ":")          # pkg:maven/group/artifact → group:artifact
        key = (ptype, name, version)
        if key in seen:
            continue
        seen.add(key)
        if (ptype, _norm(ptype, name)) in own:
            na.append({"purl": c.get("purl"), "reason": "本 repo 自身宣告的專案，不是登錄處的相依套件"})
            continue
        if ptype not in SYSTEMS:
            na.append({"purl": c.get("purl"), "reason": f"deps.dev 不支援 {ptype}（GitHub Actions 由 Dependabot 追蹤）"})
            continue
        locs = [p.get("value") for p in c.get("properties") or []
                if p.get("name") == "syft:location:0:path" and p.get("value")]
        uri = (locs[0].lstrip("/") if locs else "") or FALLBACK_URI
        if ".." in pathlib.PurePosixPath(uri).parts:
            uri = FALLBACK_URI
        todo.append({"system": SYSTEMS[ptype], "name": name, "version": version, "purl": c.get("purl"), "uri": uri})
    return todo, na


class FetchError(Exception):
    pass


def _https_only_opener() -> urllib.request.OpenerDirector:
    """只裝 HTTPS（驗證憑證與主機名）與 proxy 的 opener：沒有 FileHandler／HTTPHandler／FTPHandler，
    所以 file://、http://（含被重導到 http）等一律無法開啟——不只靠 URL 是常數字串來保證。"""
    opener = urllib.request.OpenerDirector()
    https_proxy = {k: v for k, v in urllib.request.getproxies().items() if k == "https"}   # 只讓 https 走 proxy
    for h in (urllib.request.ProxyHandler(https_proxy),
              urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=os.environ.get("SSL_CERT_FILE") or None)),
              urllib.request.UnknownHandler(),   # 其他 scheme（file://、http://、ftp://）→ URLError
              urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor()):
        opener.add_handler(h)
    return opener


def fetch_deps_dev(system: str, name: str, retries: int = 3) -> dict | None:
    """回傳套件資料；404 → None（查無此套件）；其他錯誤重試後拋出 FetchError。"""
    url = API_BASE + API_PATH.format(system=urllib.parse.quote(system, safe=""), name=urllib.parse.quote(name, safe=""))
    opener = _https_only_opener()
    for i in range(retries):
        # 每次重試都建新的 Request：ProxyHandler 會改寫傳入的 Request，重用時經 http:// proxy 的重試會以
        # 「unknown url type: http」失敗（同 g1_slopcheck.http_json）
        req = urllib.request.Request(url, headers={"User-Agent": "vibesec-g1-maintenance", "Accept": "application/json"})
        try:
            with opener.open(req, timeout=30) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code < 500 or i == retries - 1:
                raise FetchError(f"HTTP {e.code}") from e
        except (OSError, ValueError) as e:   # URLError 是 OSError 的子類別
            if i == retries - 1:
                raise FetchError(f"{type(e).__name__}: {e}") from e
        time.sleep(2 ** i)
    return None


def _date(s: str | None) -> datetime.datetime | None:
    if not s:
        return None
    try:
        return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def assess(pkg: dict, data: dict, days: int, now: datetime.datetime) -> dict | None:
    versions = data.get("versions") or []
    used = next((v for v in versions if (v.get("versionKey") or {}).get("version") == pkg["version"]), None)
    default = next((v for v in versions if v.get("isDefault")), None)
    signals = []
    if used and used.get("isDeprecated"):
        signals.append({"signal": "deprecated", "detail": used.get("deprecatedReason") or None})
    latest_at = _date((default or {}).get("publishedAt"))
    if latest_at and (now - latest_at).days > days:
        signals.append({"signal": "stale", "detail": f"最新版 {(default.get('versionKey') or {}).get('version')} 發布於 "
                                                     f"{latest_at.date().isoformat()}，已 {(now - latest_at).days} 天"})
    if not signals:
        return None
    return {**pkg, "signals": signals, "latest_version": (default or {}).get("versionKey", {}).get("version"),
            "latest_published_at": latest_at.date().isoformat() if latest_at else None}


def run(sbom_path: pathlib.Path, fetch=fetch_deps_dev, days: int | None = None,
        now: datetime.datetime | None = None, own: set[tuple[str, str]] | None = None) -> tuple[dict, list[dict]]:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    days = days if days is not None else configured_days()
    base = {"rule_id": RULE, "checked_at": now.replace(microsecond=0).isoformat(), "unmaintained_days": days}
    if not sbom_path.is_file():
        return {**base, "status": "incomplete", "status_reason": f"缺 SBOM：{sbom_path}"}, []
    try:
        todo, na = parse_sbom(json.loads(sbom_path.read_text(encoding="utf-8")),
                              first_party() if own is None else own)
    except (ValueError, TypeError) as e:
        return {**base, "status": "incomplete", "status_reason": f"SBOM 無法解析：{type(e).__name__}: {e}"}, []
    hits, unresolved, cache = [], [], {}
    for pkg in todo:
        key = (pkg["system"], pkg["name"])
        try:
            if key not in cache:
                cache[key] = fetch(*key)
        except Exception as e:  # 網路／API 失敗：記下來，整體 incomplete
            unresolved.append({"purl": pkg["purl"], "reason": f"deps.dev 查詢失敗：{type(e).__name__}"})
            cache[key] = False
            continue
        data = cache[key]
        if data is False:
            unresolved.append({"purl": pkg["purl"], "reason": "deps.dev 查詢失敗（同套件先前已失敗）"})
            continue
        if data is None:
            unresolved.append({"purl": pkg["purl"], "reason": "deps.dev 查無此套件"})
            continue
        h = assess(pkg, data, days, now)
        if h:
            hits.append(h)
    summary = {**base, "packages_checked": len(todo) - len(unresolved), "not_applicable": na,
               "unresolved": unresolved, "hits": hits}
    if unresolved:
        summary.update(status="incomplete",
                       status_reason=f"{len(unresolved)} 個套件無法判定維護狀態（incomplete ≠ pass）")
    else:
        summary.update(status="pass", status_reason=None)   # advisory 命中不改變閘門結論
    return summary, hits


def _policy_tier() -> str:
    """tier 唯一來源是 blocking-policy（第四次審視 S-11）。"""
    sys.path.insert(0, str(ROOT / "scripts"))
    from vibesec_policy import Policy
    return Policy(ROOT).tier(RULE)


def to_sarif(hits: list[dict]) -> dict:
    _TIER = _policy_tier(); _LEVEL = "error" if _TIER == "blocking" else "warning"
    rule = {"id": RULE, "name": RULE, "shortDescription": {"text": "相依套件已停止維護或被標記 deprecated"},
            "defaultConfiguration": {"level": _LEVEL}, "properties": {"policy_tier": _TIER}}
    def msg(h):
        parts = [("已被標記 deprecated" + (f"（{s['detail']}）" if s["detail"] else "")) if s["signal"] == "deprecated"
                 else s["detail"] for s in h["signals"]]
        return f"{h['name']}@{h['version']}：" + "；".join(parts)
    results = [{"ruleId": RULE, "level": _LEVEL, "message": {"text": msg(h)},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": h["uri"]}}}],
                "properties": {"policy_tier": _TIER, "purl": h["purl"], "signals": [s["signal"] for s in h["signals"]],
                               "latest_version": h["latest_version"], "latest_published_at": h["latest_published_at"]}}
               for h in hits]
    return {"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "vibesec-g1-maintenance", "version": "1.0.0",
                                          "informationUri": "https://github.com/chinchiang/MultiAgentDelta",
                                          "rules": [rule]}}, "results": results}]}


def selftest() -> list[str]:
    import tempfile
    fails: list[str] = []
    now = datetime.datetime(2026, 10, 5, tzinfo=datetime.timezone.utc)
    def ver(v, at, default=False, dep=False, reason=""):
        return {"versionKey": {"version": v}, "publishedAt": at, "isDefault": default,
                "isDeprecated": dep, "deprecatedReason": reason}
    DB = {
        ("pypi", "fresh"): {"versions": [ver("1.0", "2026-01-01T00:00:00Z", default=True)]},
        ("pypi", "old"): {"versions": [ver("0.9", "2019-01-01T00:00:00Z", default=True)]},
        ("npm", "dep"): {"versions": [ver("1.0", "2026-09-01T00:00:00Z", dep=True, reason="use other"),
                                      ver("2.0", "2026-09-02T00:00:00Z", default=True)]},
        ("maven", "org.x:lib"): {"versions": [ver("1", "2026-01-01T00:00:00Z", default=True)]},
    }
    calls = []
    def fake(system, name):
        calls.append((system, name))
        if name == "boom":
            raise FetchError("down")
        return DB.get((system, name))
    comps = [{"purl": p} for p in ["pkg:pypi/fresh@1.0", "pkg:pypi/old@0.9", "pkg:npm/dep@1.0", "pkg:npm/dep@1.0",
                                   "pkg:maven/org.x/lib@1", "pkg:github/actions/checkout@v7"]]
    with tempfile.TemporaryDirectory() as d:
        sp = pathlib.Path(d, "sbom.json")
        sp.write_text(json.dumps({"components": comps}))
        s, hits = run(sp, fetch=fake, days=730, now=now, own=set())
        got = {(h["name"], tuple(x["signal"] for x in h["signals"])) for h in hits}
        if s["status"] != "pass" or got != {("old", ("stale",)), ("dep", ("deprecated",))}:
            fails.append(f"應命中 old(stale) 與 dep(deprecated)，fresh 不命中：{s['status']} {got}")
        if len(s["not_applicable"]) != 1 or "github" not in s["not_applicable"][0]["reason"]:
            fails.append(f"pkg:github 應列 not_applicable 並附原因：{s['not_applicable']}")
        if calls.count(("npm", "dep")) != 1:
            fails.append("同一套件只應查詢一次")
        if ("maven", "org.x:lib") not in calls:
            fails.append("maven purl 應轉為 group:artifact")
        r = to_sarif(hits)["runs"][0]["results"]
        if len(r) != 2 or any(x["level"] != "warning" or x["properties"]["policy_tier"] != "advisory" for x in r):
            fails.append("SARIF 應為 2 筆 advisory warning")
        # incomplete：API 失敗、查無套件、缺 SBOM、壞 SBOM —— 都不能變成 pass
        for label, comps2 in [("API 失敗", [{"purl": "pkg:pypi/boom@1"}]), ("查無套件", [{"purl": "pkg:pypi/ghost@1"}])]:
            sp.write_text(json.dumps({"components": comps2}))
            st = run(sp, fetch=fake, days=730, now=now, own=set())[0]
            if st["status"] != "incomplete" or not st["unresolved"]:
                fails.append(f"{label} 應為 incomplete 並列出 unresolved：{st}")
        # 本 repo 自己的專案（名稱正規化後比對）→ not_applicable，不查詢、不算 incomplete；第三方同名以外照查
        sp.write_text(json.dumps({"components": [{"purl": "pkg:pypi/My_Project@0.1"}, {"purl": "pkg:pypi/ghost@1"}]}))
        st = run(sp, fetch=fake, days=730, now=now, own={("pypi", "my-project")})[0]
        if [n["purl"] for n in st["not_applicable"]] != ["pkg:pypi/My_Project@0.1"] or len(st["unresolved"]) != 1:
            fails.append(f"自身專案應 not_applicable、第三方查無仍應 unresolved：{st}")
        pp = pathlib.Path(d, "proj"); (pp / "sub").mkdir(parents=True)
        (pp / "sub/pyproject.toml").write_text('[build-system]\nrequires = []\n\n[project]\nname = "Demo_App"\n')
        (pp / "package.json").write_text('{"name": "@acme/web"}')
        if first_party(pp) != {("pypi", "demo-app"), ("npm", "@acme/web")}:
            fails.append(f"first_party 應讀到 pyproject 與 package.json 名稱：{first_party(pp)}")
        for bad in ("file:///etc/passwd", "http://example.com/"):
            try:
                _https_only_opener().open(bad, timeout=5)
                fails.append(f"opener 不應開啟 {bad}")
            except urllib.error.URLError:
                pass
        # 經 http:// proxy（已關閉的埠）重試：每次都應是連線錯誤，不能變成 Request 被改寫後的「unknown url type」
        import socket
        with socket.socket() as s_:
            s_.bind(("127.0.0.1", 0)); dead = s_.getsockname()[1]
        saved = {k: os.environ.pop(k) for k in list(os.environ) if k.lower() in ("https_proxy", "http_proxy", "all_proxy", "no_proxy")}
        os.environ["https_proxy"] = f"http://127.0.0.1:{dead}"
        try:
            fetch_deps_dev("pypi", "requests", retries=3)   # 症狀在第三次嘗試才出現
            fails.append("fetch_deps_dev 經已關閉的 proxy 不應成功")
        except FetchError as e:
            if "unknown url type" in str(e):
                fails.append(f"fetch_deps_dev 經 http:// proxy 重試時 Request 被改寫：{e}")
        finally:
            os.environ.pop("https_proxy", None); os.environ.update(saved)
        if run(pathlib.Path(d, "none.json"), fetch=fake, now=now)[0]["status"] != "incomplete":
            fails.append("缺 SBOM 應為 incomplete")
        sp.write_text("{bad")
        if run(sp, fetch=fake, now=now)[0]["status"] != "incomplete":
            fails.append("壞 SBOM 應為 incomplete")
    return fails


def main(argv=None) -> int:
    if (argv if argv is not None else sys.argv[1:])[:1] == ["selftest"]:
        fails = selftest()
        print("\n".join(f"FAIL {x}" for x in fails) or "g1_maintenance selftest ok")
        return 1 if fails else 0
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--sbom", required=True)
    ap.add_argument("--sarif", required=True)
    ap.add_argument("--json", required=True)
    a = ap.parse_args(argv)
    summary, hits = run(pathlib.Path(a.sbom))
    for out in (a.sarif, a.json):
        pathlib.Path(out).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(a.json).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    pathlib.Path(a.sarif).write_text(json.dumps(to_sarif(hits), ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"維護狀態：查 {summary.get('packages_checked', 0)} 個套件，命中 {len(hits)} 個；"
          f"不適用 {len(summary.get('not_applicable') or [])} 個；無法判定 {len(summary.get('unresolved') or [])} 個"
          + "".join(f"\n  {h['name']}@{h['version']}：{', '.join(s['signal'] for s in h['signals'])}" for h in hits))
    if summary["status"] == "incomplete":
        for u in summary.get("unresolved") or []:
            print(f"  無法判定 {u.get('purl')}：{u.get('reason')}")
        print(f"::error::維護狀態檢查未完成（incomplete ≠ pass）：{summary['status_reason']}")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
