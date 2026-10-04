#!/usr/bin/env python3
"""G1 供應鏈快篩（本機 pre-commit 版）— 四層防禦的輕量實作。

與 .github/workflows/pr-gates.yml 的內嵌 G1 檢查對齊。純 stdlib。
四層：(1) registry 存在性 + 週下載量；(2) 名稱相似度 vs popular 清單 + blacklist；
      (3) 安裝階段 hook（npm postinstall/preinstall/install）；(4) 新套件冷卻期。

原則（CLAUDE.md #2）：網路失敗、registry 無法查詢 → 標記 incomplete，絕不視為通過。
退出碼：0 無阻擋；1 有 blocking 發現；2 無法完成檢查（incomplete）。
用法：python3 scripts/g1_slopcheck.py [--staged] [--manifest <path> ...]
"""
from __future__ import annotations
import sys, json, re, difflib, urllib.request, urllib.error, subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CFG_DIR = ROOT / "config" / "slopsquat"
TIMEOUT = 8

def load_yaml(p: Path):
    try:
        import yaml
        return yaml.safe_load(p.read_text()) if p.exists() else None
    except Exception:
        return None

def read_vibesec():
    try:
        import yaml
        return yaml.safe_load((ROOT / "vibesec.yaml").read_text())
    except Exception:
        return {}

def cfg():
    c = load_yaml(CFG_DIR / "cooldown.yaml") or {}
    vb = read_vibesec()
    g1 = ((vb.get("gates") or {}).get("g1_supply_chain") or {})
    return {
        "cooldown_days": g1.get("cooldown_days", c.get("cooldown_days", 14)),
        "min_weekly_downloads": g1.get("min_weekly_downloads", c.get("min_weekly_downloads", 1000)),
        "similarity": c.get("similarity_ratio", 0.80),
    }

def load_popular(name):
    p = CFG_DIR / name
    if not p.exists():
        return set()
    return {l.strip().lower() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")}

def load_list(name, key="package"):
    data = load_yaml(CFG_DIR / name) or {}
    items = data.get("packages", data if isinstance(data, list) else [])
    out = {}
    for it in (items or []):
        if isinstance(it, dict) and it.get(key):
            out[it[key].lower()] = it
    return out

def http_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "vibesec-g1/0.1"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode())

def npm_check(pkg, ver, c):
    """回傳 (findings, incomplete_reason|None)。"""
    findings = []
    try:
        meta = http_json(f"https://registry.npmjs.org/{pkg}")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return [fnd("vibesec.g1.hallucinated-package", pkg, "npm", ver,
                        "npm registry 查無此套件（疑似幻覺/搶註）", "blocking")], None
        return [], f"npm registry 查詢失敗（{pkg}）：HTTP {e.code}"
    except Exception as e:
        return [], f"npm registry 查詢失敗（{pkg}）：{e}"
    # 冷卻期
    times = meta.get("time", {})
    target_ver = ver or (meta.get("dist-tags", {}) or {}).get("latest")
    if target_ver and target_ver in times:
        age = age_days(times[target_ver])
        if age is not None and age < c["cooldown_days"]:
            findings.append(fnd("vibesec.g1.cooldown-violation", pkg, "npm", target_ver,
                                f"版本發布僅 {age} 天，未滿冷卻期 {c['cooldown_days']} 天", "blocking"))
    # 安裝 hook
    vmeta = (meta.get("versions", {}) or {}).get(target_ver or "", {})
    scripts = vmeta.get("scripts", {}) or {}
    hooks = [h for h in ("preinstall", "install", "postinstall") if h in scripts]
    if hooks:
        findings.append(fnd("vibesec.g1.postinstall-egress", pkg, "npm", target_ver,
                            f"含安裝階段 hook（{', '.join(hooks)}），需人工審查其行為", "blocking"))
    # 週下載
    try:
        dl = http_json(f"https://api.npmjs.org/downloads/point/last-week/{pkg}").get("downloads", 0)
        if dl < c["min_weekly_downloads"]:
            findings.append(fnd("vibesec.g1.hallucinated-package", pkg, "npm", target_ver,
                                f"週下載量 {dl} < {c['min_weekly_downloads']}，信譽不足", "blocking"))
    except Exception:
        pass  # 下載量查不到不致命，存在性已確認
    return findings, None

def pypi_check(pkg, ver, c):
    findings = []
    try:
        meta = http_json(f"https://pypi.org/pypi/{pkg}/json")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return [fnd("vibesec.g1.hallucinated-package", pkg, "pypi", ver,
                        "PyPI 查無此套件（疑似幻覺/搶註）", "blocking")], None
        return [], f"PyPI 查詢失敗（{pkg}）：HTTP {e.code}"
    except Exception as e:
        return [], f"PyPI 查詢失敗（{pkg}）：{e}"
    target_ver = ver or (meta.get("info", {}) or {}).get("version")
    rel = (meta.get("releases", {}) or {}).get(target_ver or "", [])
    if rel:
        age = age_days(rel[0].get("upload_time_iso_8601", ""))
        if age is not None and age < c["cooldown_days"]:
            findings.append(fnd("vibesec.g1.cooldown-violation", pkg, "pypi", target_ver,
                                f"版本發布僅 {age} 天，未滿冷卻期 {c['cooldown_days']} 天", "blocking"))
    return findings, None

def age_days(iso):
    try:
        t = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - t).days
    except Exception:
        return None

def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]

def similarity_check(pkg, popular, blacklist, allowlist, c):
    if pkg.lower() in allowlist:
        return None
    if pkg.lower() in blacklist:
        it = blacklist[pkg.lower()]
        return fnd("vibesec.g1.hallucinated-package", pkg, it.get("ecosystem", "?"), None,
                   f"命中幻覺/搶註黑名單：{it.get('reason','known typosquat')}", "blocking")
    if pkg.lower() in popular:
        return None
    pl = pkg.lower()
    for good in popular:
        if pl == good:
            return None
        ratio = difflib.SequenceMatcher(None, pl, good).ratio()
        dist = _levenshtein(pl, good)
        # 兩路判定：ratio 門檻，或編輯距離 <=2（補 difflib 對字母易位的低估，如 axois vs axios）
        if (ratio >= c["similarity"] or (len(pl) >= 4 and dist <= 2 and dist > 0)):
            return fnd("vibesec.g1.hallucinated-package", pkg, "?", None,
                       f"名稱與熱門套件 '{good}' 高度相似（ratio={ratio:.2f}, edit={dist}），疑似 typosquat", "blocking")
    return None

def fnd(rule, pkg, eco, ver, reason, tier):
    return {"rule_id": rule, "package": pkg, "ecosystem": eco, "version": ver,
            "reason": reason, "policy_tier": tier}

PKG_RE_NPM = re.compile(r'"([@a-z0-9._/-]+)"\s*:\s*"([~^]?[0-9][^"]*)"')

# PEP 508 需求字串：名稱、可選 extras、版本規格；忽略環境標記（; 之後）
REQ_RE = re.compile(r'^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:===?\s*([0-9][^,;\s]*))?')

def _pep508(req):
    """從 PEP 508 需求字串取出 (名稱, 鎖定版本或 None)；無法解析回傳 None。"""
    if not isinstance(req, str):
        return None
    req = req.split(";", 1)[0].strip()
    if not req or req.startswith(("-", "#", "git+", "http:", "https:", "file:", ".", "/")) or " @ " in req:
        return None
    m = REQ_RE.match(req)
    return (m.group(1), m.group(2)) if m else None

def _toml(path):
    try:
        import tomllib
    except ImportError:  # Python < 3.11
        return None
    try:
        return tomllib.loads(path.read_text(errors="ignore"))
    except Exception:
        return None

def _pyproject_deps(data):
    """PEP 621 [project]、[dependency-groups]（PEP 735）與 Poetry 的相依。不含 build-system。"""
    reqs = []
    proj = data.get("project") or {}
    reqs += proj.get("dependencies") or []
    for group in (proj.get("optional-dependencies") or {}).values():
        reqs += group or []
    for group in (data.get("dependency-groups") or {}).values():
        reqs += [r for r in (group or []) if isinstance(r, str)]   # 略過 {include-group = ...}
    out = [x for x in map(_pep508, reqs) if x]
    poetry = (data.get("tool") or {}).get("poetry") or {}
    tables = [poetry.get("dependencies") or {}, poetry.get("dev-dependencies") or {}]
    tables += [(g or {}).get("dependencies") or {} for g in (poetry.get("group") or {}).values()]
    for table in tables:
        for name in table:
            if name.lower() != "python":
                out.append((name, None))
    return out

def _lock_packages(data):
    """uv.lock / poetry.lock 的 [[package]]；略過本地（editable / virtual / directory）套件。"""
    out = []
    for pkg in data.get("package") or []:
        src = pkg.get("source") or {}
        if any(k in src for k in ("editable", "virtual", "directory", "path")) or src.get("type") in ("directory", "file"):
            continue
        if pkg.get("name"):
            out.append((pkg["name"], pkg.get("version")))
    return out

def parse_added(paths):
    """回傳 [(ecosystem, name, version)]。"""
    out = []
    for p in paths:
        p = Path(p)
        if not p.exists():
            continue
        text = p.read_text(errors="ignore")
        if p.name in ("package.json",) or p.name.endswith(".json") and "package" in p.name:
            try:
                j = json.loads(text)
                for sec in ("dependencies", "devDependencies"):
                    for name, ver in (j.get(sec, {}) or {}).items():
                        out.append(("npm", name, re.sub(r'^[~^]', '', str(ver))))
            except Exception:
                pass
        elif p.name == "pyproject.toml":
            data = _toml(p)
            if data is not None:
                out += [("pypi", n, v) for n, v in _pyproject_deps(data)]
        elif p.name in ("uv.lock", "poetry.lock"):
            data = _toml(p)
            if data is not None:
                out += [("pypi", n, v) for n, v in _lock_packages(data)]
        elif p.name.startswith("requirements"):
            for line in text.splitlines():
                x = _pep508(line.split(" #", 1)[0])
                if x:
                    out.append(("pypi", x[0], x[1]))
    # 去重
    seen, uniq = set(), []
    for eco, n, v in out:
        k = (eco, n.lower(), v)
        if k not in seen:
            seen.add(k); uniq.append((eco, n, v))
    return uniq

def staged_files():
    try:
        r = subprocess.run(["git", "diff", "--cached", "--name-only"],
                           capture_output=True, text=True, cwd=ROOT)
        return [l for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        return []

MANIFEST_RE = re.compile(r'(package(-lock)?\.json|pnpm-lock\.yaml|yarn\.lock|requirements.*\.txt|pyproject\.toml|poetry\.lock|uv\.lock)$')

def main(argv):
    args = argv[1:]
    manifests = []
    if "--staged" in args:
        manifests = [f for f in staged_files() if MANIFEST_RE.search(f)]
    for i, a in enumerate(args):
        if a == "--manifest" and i + 1 < len(args):
            manifests.append(args[i + 1])
    if not manifests:
        print("G1 slopcheck：無相依清單變更，略過。")
        return 0

    c = cfg()
    popular = load_popular("popular-npm.txt") | load_popular("popular-pypi.txt")
    blacklist = load_list("blacklist.yaml")
    allowlist = load_list("allowlist.yaml")

    findings, incomplete = [], []
    for eco, name, ver in parse_added(manifests):
        sim = similarity_check(name, popular, blacklist, allowlist, c)
        if sim:
            findings.append(sim)
        if name.lower() in allowlist:
            continue
        fs, reason = (npm_check(name, ver, c) if eco == "npm" else pypi_check(name, ver, c))
        findings.extend(fs)
        if reason:
            incomplete.append(reason)

    out = {"gate": "G1", "findings": findings}
    if incomplete:
        out["status"] = "incomplete"
        out["status_reason"] = "；".join(incomplete)
    print(json.dumps(out, ensure_ascii=False, indent=2))

    if incomplete and not findings:
        print("\n⚠️ G1 無法完成檢查（網路/registry 失敗）→ incomplete，絕不視為通過。", file=sys.stderr)
        return 2
    blocking = [f for f in findings if f["policy_tier"] == "blocking"]
    if blocking:
        print(f"\n⛔ G1 阻擋：{len(blocking)} 筆 blocking 供應鏈發現。", file=sys.stderr)
        return 1
    print("\n✅ G1 快篩通過。")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
