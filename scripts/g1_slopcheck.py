#!/usr/bin/env python3
"""G1 供應鏈快篩（本機 pre-commit 版）— 四層防禦的輕量實作。

與 .github/workflows/pr-gates.yml 的內嵌 G1 檢查對齊。純 stdlib。
四層：(1) registry 存在性 + 週下載量；(2) 名稱相似度 vs popular 清單 + blacklist；
      (3) 安裝階段 hook（npm postinstall/preinstall/install）；(4) 新套件冷卻期。

原則（CLAUDE.md #2）：網路失敗、registry 無法查詢、鎖定檔尚無解析器 → 標記 incomplete，絕不視為通過。
退出碼：0 無阻擋；1 有 blocking 發現；2 無法完成檢查（incomplete）。
用法：python3 scripts/g1_slopcheck.py [--target <dir>] [--staged] [--manifest <path> ...]

--target <dir>：被掃描的專案根目錄（預設本 repo）。設定、清單與阻擋政策一律取自本 repo；
  相對路徑、--staged、--changed-files、--base 都以目標專案為準。只給 --target、沒指定要掃哪些檔時，
  全量掃描目標專案追蹤中的所有 manifest 與 agent 規則檔（scope: full）。
  blocking-policy 的 exceptions 只核准給本 repo 的路徑，掃其他專案時不套用（fail closed）。
"""
from __future__ import annotations
import sys, os, ssl, json, re, difflib, fnmatch, urllib.parse, urllib.request, urllib.error, subprocess
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent      # VibeSec 本身：設定、清單、政策
CFG_DIR = ROOT / "config" / "slopsquat"
TIMEOUT = 8
TARGET = ROOT                                      # 被掃描的專案根目錄；--target 改寫

def external_target():
    """目標不是本 repo → 本 repo 的 blocking-policy exceptions 不適用。"""
    return TARGET.resolve() != ROOT.resolve()

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

def canon(eco, name):
    """比對用的套件名稱。PyPI 依 PEP 503 正規化：大小寫不分，連續的 -、_、. 視為同一個 -
    （typing_extensions 與 typing-extensions 是同一個專案，不能另外註冊）；npm 只轉小寫（_ 與 - 是不同套件）。"""
    name = str(name).lower()
    return re.sub(r"[-_.]+", "-", name) if eco == "pypi" else name

def load_list(name):
    """讀 blacklist / allowlist：鍵為 (ecosystem, 名稱小寫)；ecosystem 缺省時記為 None（適用所有生態系）。

    條目名稱可用 `name`（blacklist.yaml）或 `package`（allowlist.yaml）欄位。
    """
    data = load_yaml(CFG_DIR / name) or {}
    items = data.get("packages", data if isinstance(data, list) else [])
    out = {}
    for it in (items or []):
        if not isinstance(it, dict):
            continue
        pkg = it.get("name") or it.get("package")
        if pkg:
            out[((it.get("ecosystem") or None), str(pkg).lower())] = it
    return out

def lookup(entries, eco, pkg):
    """依生態系查清單（名稱以 canon() 比對）；先找同生態系，再找未指定生態系的條目。"""
    key = canon(eco, pkg)
    for want in (eco, None):
        for (e, n), it in entries.items():
            if e == want and canon(eco, n) == key:
                return it
    return None

# 套件名稱來自 PR 內的 manifest（不可信）：先依 registry 命名規則驗證，再 percent-encode 組 URL。
# 不合法的名稱不送出查詢，記為 incomplete（incomplete ≠ pass）。
NPM_NAME = re.compile(r"^(?:@[a-z0-9~-][a-z0-9._~-]*/)?[a-z0-9~-][a-z0-9._~-]*$", re.I)
PYPI_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")

def valid_name(eco, pkg):
    if not pkg or len(pkg) > 214:
        return False
    return bool((NPM_NAME if eco == "npm" else PYPI_NAME).match(pkg))

def _https_only_opener():
    """只裝 HTTPS（驗證憑證與主機名）、https proxy 與 UnknownHandler：file://、http:// 等一律 URLError。"""
    opener = urllib.request.OpenerDirector()
    https_proxy = {k: v for k, v in urllib.request.getproxies().items() if k == "https"}
    for h in (urllib.request.ProxyHandler(https_proxy),
              urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=os.environ.get("SSL_CERT_FILE") or None)),
              urllib.request.UnknownHandler(),
              urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor()):
        opener.add_handler(h)
    return opener

def http_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "vibesec-g1/0.1"})
    with _https_only_opener().open(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode())

def npm_check(pkg, ver, c):
    """回傳 (findings, incomplete_reason|None)。"""
    findings = []
    if not valid_name("npm", pkg):
        return [], f"npm 套件名稱不合法，未查詢 registry：{pkg!r}"
    q = urllib.parse.quote(pkg, safe="@/")
    try:
        meta = http_json(f"https://registry.npmjs.org/{q}")
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
        f = cooldown_finding(pkg, "npm", target_ver, age_days(times[target_ver]), c)
        if f:
            findings.append(f)
    # 安裝 hook
    vmeta = (meta.get("versions", {}) or {}).get(target_ver or "", {})
    f = install_hook_finding(pkg, "npm", target_ver, vmeta.get("scripts", {}) or {})
    if f:
        findings.append(f)
    # 週下載
    try:
        dl = http_json(f"https://api.npmjs.org/downloads/point/last-week/{q}").get("downloads", 0)
        if dl < c["min_weekly_downloads"]:
            findings.append(fnd("vibesec.g1.low-download-package", pkg, "npm", target_ver,
                                f"週下載量 {dl} < {c['min_weekly_downloads']}，信譽不足，需人工判斷", "advisory"))
    except Exception:
        pass  # 下載量查不到不致命，存在性已確認
    return findings, None

def pypi_check(pkg, ver, c):
    findings = []
    if not valid_name("pypi", pkg):
        return [], f"PyPI 套件名稱不合法，未查詢 registry：{pkg!r}"
    try:
        meta = http_json(f"https://pypi.org/pypi/{urllib.parse.quote(pkg, safe='')}/json")
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
        f = cooldown_finding(pkg, "pypi", target_ver, age_days(rel[0].get("upload_time_iso_8601", "")), c)
        if f:
            findings.append(f)
    return findings, None

def cooldown_finding(pkg, eco, ver, age, c):
    """發布天數未滿冷卻期 → blocking；天數未知（None）不判定。純函式，run_evals.py 以合成 fixture 直接呼叫。"""
    if age is None or age >= c["cooldown_days"]:
        return None
    return fnd("vibesec.g1.cooldown-violation", pkg, eco, ver,
               f"版本發布僅 {age} 天，未滿冷卻期 {c['cooldown_days']} 天", "blocking")

def _hook_patterns():
    return ((load_yaml(CFG_DIR / "cooldown.yaml") or {}).get("install_hooks") or {}).get("suspicious_patterns") or {}

def install_hook_finding(pkg, eco, ver, scripts, patterns=None):
    """依 cooldown.yaml install_hooks 分類安裝階段 hook（docs/02 第 3 層）。
    外連 + 讀環境變數／執行、憑證路徑、濫用本機 AI CLI → blocking；只有動態執行 → advisory；
    其餘（例如 node-gyp rebuild）不判 egress，回傳 None。純函式，run_evals.py 以合成 fixture 直接呼叫。"""
    hooks = {h: str(scripts[h]) for h in ("preinstall", "install", "postinstall") if h in scripts}
    if not hooks:
        return None
    pats = patterns if patterns is not None else _hook_patterns()
    body = "\n".join(hooks.values())
    hit = {k: any(re.search(rx, body) for rx in pats.get(k) or []) for k in
           ("network", "env_read", "credential_paths", "ai_cli_abuse", "exec")}
    names = ", ".join(hooks)
    if hit["credential_paths"] or hit["ai_cli_abuse"] or (hit["network"] and (hit["env_read"] or hit["exec"])):
        why = [k for k in ("network", "env_read", "credential_paths", "ai_cli_abuse", "exec") if hit[k]]
        return fnd("vibesec.g1.postinstall-egress", pkg, eco, ver,
                   f"安裝階段 hook（{names}）命中可疑樣式：{', '.join(why)}", "blocking")
    if hit["exec"] or hit["network"]:
        return fnd("vibesec.g1.postinstall-egress", pkg, eco, ver,
                   f"安裝階段 hook（{names}）含動態執行或外連，需人工審查", "advisory")
    return None

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

def similarity_check(pkg, eco, popular, blacklist, allowlist, c):
    if lookup(allowlist, eco, pkg):
        return None
    it = lookup(blacklist, eco, pkg)
    if it:
        hint = f"；正確名稱應為 {it['looks_like']}" if it.get("looks_like") else ""
        tier = "advisory" if it.get("action") == "warn" else "blocking"
        return fnd("vibesec.g1.hallucinated-package", pkg, eco, None,
                   f"命中黑名單（{it.get('status', '?')}）：{it.get('reason', 'known typosquat')}{hint}", tier)
    pl = canon(eco, pkg)
    canon_popular = {canon(eco, g): g for g in popular}
    if pl in canon_popular:
        return None
    for cg, good in canon_popular.items():
        ratio = difflib.SequenceMatcher(None, pl, cg).ratio()
        dist = _levenshtein(pl, cg)
        # 兩路判定：ratio 門檻，或編輯距離 <=2（補 difflib 對字母易位的低估，如 axois vs axios）
        if (ratio >= c["similarity"] or (len(pl) >= 4 and dist <= 2 and dist > 0)):
            return fnd("vibesec.g1.hallucinated-package", pkg, eco, None,
                       f"名稱與熱門套件 '{good}' 高度相似（ratio={ratio:.2f}, edit={dist}），疑似 typosquat", "blocking")
    return None

def fnd(rule, pkg, eco, ver, reason, tier):
    # tier 只能降級（advisory 線索），不能高於 blocking-policy（scripts/vibesec_policy.py）
    return {"rule_id": rule, "package": pkg, "ecosystem": eco, "version": ver,
            "reason": reason, "policy_tier": _policy().cap(rule, tier)}

_POLICY = None
def _policy():
    global _POLICY
    if _POLICY is None:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from vibesec_policy import Policy
        _POLICY = Policy(ROOT)
    return _POLICY

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
        if not p.exists() or UNPARSED_RE.search(p.name):
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
        elif re.search(r'requirements.*\.txt$', p.name):
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

POLICY_FILE = ROOT / "config" / "policy" / "blocking-policy.yaml"

def load_exceptions(today=None):
    """讀 blocking-policy.yaml 的 exceptions，只保留欄位完整且未過期者（fail closed）。

    回傳 (有效例外清單, 被忽略的例外說明清單)。
    """
    today = today or date.today()
    data = load_yaml(POLICY_FILE) or {}
    valid, ignored = [], []
    for ex in data.get("exceptions") or []:
        if not isinstance(ex, dict):
            continue
        missing = [k for k in ("rule_id", "path_glob", "reason", "approved_by", "expires") if not ex.get(k)]
        if missing:
            ignored.append(f"{ex.get('rule_id', '?')}：缺少欄位 {', '.join(missing)}")
            continue
        exp = ex["expires"]
        try:
            exp = exp if isinstance(exp, date) else date.fromisoformat(str(exp))
        except ValueError:
            ignored.append(f"{ex['rule_id']}：expires 格式無效（{ex['expires']}）")
            continue
        if exp < today:
            ignored.append(f"{ex['rule_id']} @ {ex['path_glob']}：已於 {exp} 過期")
            continue
        valid.append(dict(ex, expires=str(exp)))
    return valid, ignored

def rel_path(path):
    """manifest 路徑轉成相對目標專案根目錄的 POSIX 路徑；目標外的檔案保持原樣。"""
    p = Path(path).resolve()
    try:
        return p.relative_to(TARGET.resolve()).as_posix()
    except ValueError:
        return Path(path).as_posix()

def resolve(path):
    """相對路徑先以目標專案為基準，找不到再以目前目錄為基準（相容 --manifest 傳入工作目錄相對路徑）。"""
    p = Path(path)
    if p.is_absolute() or not (TARGET / p).exists():
        return p
    return TARGET / p

def apply_exceptions(finding, exceptions):
    """命中 rule_id 與 path_glob 的例外時把 blocking 降為 advisory；例外不刪除發現。"""
    for ex in exceptions:
        if finding["rule_id"] == ex["rule_id"] and fnmatch.fnmatchcase(finding.get("manifest") or "", ex["path_glob"]):
            if finding["policy_tier"] == "blocking":
                finding["policy_tier"] = "advisory"
            finding["exception"] = {k: ex[k] for k in ("path_glob", "reason", "approved_by", "expires")}
            break
    return finding

def staged_files():
    try:
        r = subprocess.run(["git", "diff", "--cached", "--name-only", "--relative"],
                           capture_output=True, text=True, cwd=TARGET)
        return [l for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        return []

MANIFEST_RE = re.compile(r'(package(-lock)?\.json|pnpm-lock\.yaml|yarn\.lock|requirements.*\.txt|pyproject\.toml|poetry\.lock|uv\.lock)$')
# 有 manifest 樣式但尚無解析器的鎖定檔：其中的套件無法逐一檢查 → incomplete（不是 pass）
UNPARSED_RE = re.compile(r'(package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$')
# 全量掃描（--target、非 git 目錄）時略過的目錄：安裝產物與快取，不是專案宣告的相依
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", "dist", "build"}

def discover(target):
    """列出目標專案的所有 manifest 與 agent 規則檔（相對目標根目錄）。git repo 取追蹤中的檔案，否則走訪目錄。"""
    try:
        r = subprocess.run(["git", "ls-files", "-z"], capture_output=True, text=True, cwd=target)
        files = [f for f in r.stdout.split("\0") if f] if r.returncode == 0 else None
    except OSError:
        files = None
    if files is None:
        files = []
        for d, dirs, names in os.walk(target):
            dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
            files += [Path(d, n).relative_to(target).as_posix() for n in names]
    return sorted(files)
RULE_FILE_NAMES = (".cursorrules", "AGENTS.md", "SKILL.md")
# 安裝指令中「後面接一個值」的旗標：緊接在這類旗標後的是檔案、路徑、URL 或設定值，不是套件名
# （pip install -r requirements.txt、-e git+https://…、-i https://…）。只列文件明載需要值的旗標，以免把真正的套件漏掉。
VALUE_FLAGS = {
    "npm": {"--prefix", "--registry", "--tag", "-w", "--workspace", "--cache", "--userconfig", "--omit", "--include",
            "--install-strategy", "--before", "--otp", "--loglevel", "--filter", "-F", "--dir", "-C", "--cwd"},
    "pypi": {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url", "--extra-index-url",
             "-f", "--find-links", "-t", "--target", "--prefix", "--root", "--src", "--trusted-host", "--python", "-p",
             "--platform", "--python-version", "--implementation", "--abi", "--only-binary", "--no-binary",
             "--upgrade-strategy", "-C", "--config-settings", "--global-option", "--proxy", "--retries", "--timeout",
             "--exists-action", "--cert", "--client-cert", "--cache-dir", "--log", "--report", "--progress-bar",
             "--root-user-action", "--keyring-provider", "--group", "--suffix", "--pip-args", "--preinstall"},
}
INSTALL_RE = {
    "npm": re.compile(r'\b(?:npm|pnpm|yarn)\s+(?:install|add|i)\s+((?:-{1,2}[A-Za-z-]+\s+)*)([@A-Za-z0-9][@A-Za-z0-9._/-]*)'),
    "pypi": re.compile(r'\b(?:pip3?|pipx|uv\s+pip)\s+install\s+((?:-{1,2}[A-Za-z-]+\s+)*)([A-Za-z0-9][A-Za-z0-9._-]*)'),
}

def is_rule_file(path):
    name = Path(path).name
    return name in RULE_FILE_NAMES or name.endswith(".md")

def rule_file_mentions(path):
    """agent 規則檔／markdown 中 `npm install X`、`pip install X` 提及的套件（不含 `from X import`：模組名不等於套件名）。"""
    try:
        text = Path(path).read_text(errors="ignore")
    except OSError:
        return []
    out = []
    for eco, rx in INSTALL_RE.items():
        for m in rx.finditer(text):
            flags = m.group(1).split()
            if flags and flags[-1] in VALUE_FLAGS[eco]:
                continue                    # 例如 pip install -r requirements.txt：名稱位置是旗標的值
            name = m.group(2).rstrip(".,;:)`'\"")
            if name and not name.startswith(("-", ".", "/")):
                out.append((eco, name, None))
    return list(dict.fromkeys(out))         # 同一個檔提到同一個套件多次只算一次

def git_show(ref, path):
    """回傳 ref 版本的檔案內容；不存在（新檔）回傳 None。"""
    try:
        r = subprocess.run(["git", "show", f"{ref}:./{rel_path(path)}"], capture_output=True, text=True, cwd=TARGET)
        return r.stdout if r.returncode == 0 else None
    except Exception:
        return None

def added_packages(path, base):
    """diff-aware：只回傳相對 base 新增或改版的 (eco, name, version)。base 為 None 時回傳全部。"""
    head = parse_added([path])
    if not base:
        return head
    old_text = git_show(base, path)
    if old_text is None:
        return head
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        old = Path(d) / Path(path).name
        old.write_text(old_text)
        before = {(e, n.lower(), v) for e, n, v in parse_added([old])}
    return [(e, n, v) for e, n, v in head if (e, n.lower(), v) not in before]

LEVEL = {"blocking": "error", "advisory": "warning"}

def write_sarif(path, findings):
    rules, results = {}, []
    for f in findings:
        rules.setdefault(f["rule_id"], {"id": f["rule_id"], "name": f["rule_id"],
                                        "shortDescription": {"text": f["rule_id"]},
                                        "properties": {"policy_tier": f["policy_tier"]}})
        results.append({
            "ruleId": f["rule_id"],
            "level": LEVEL.get(f["policy_tier"], "warning"),
            "message": {"text": f"[{f['ecosystem']}] {f['package']}@{f['version'] or '?'} — {f['reason']}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.get("manifest") or "unknown"}}}],
            "partialFingerprints": {"vibesecPackage": f"{f['rule_id']}|{f['ecosystem']}|{f['package'].lower()}|{f.get('manifest')}"},
            "properties": {k: f.get(k) for k in ("package", "ecosystem", "version", "policy_tier", "manifest")}
                          | ({"exception": f["exception"]} if f.get("exception") else {}),
        })
    sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
             "runs": [{"tool": {"driver": {"name": "vibesec-slopcheck", "version": "2.0.0",
                                           "informationUri": "https://github.com/chinchiang/MultiAgentDelta",
                                           "rules": list(rules.values())}},
                       "results": results}]}
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")

CONTROL_OF = {
    "vibesec.g1.hallucinated-package": "VS-G1-SLOPSQUAT",
    "vibesec.g1.rules-file-unknown-package": "VS-G1-SLOPSQUAT",
    "vibesec.g1.low-download-package": "VS-G1-SLOPSQUAT",
    "vibesec.g1.cooldown-violation": "VS-G1-COOLDOWN",
    "vibesec.g1.postinstall-egress": "VS-G1-INSTALL-HOOK",
}

def write_gate(path, findings, incomplete, started, base, scope, sarif_ref, notes=()):
    vb = read_vibesec() or {}
    mode = vb.get("mode", "shadow"); tier = vb.get("risk_tier", "L2")
    blocking = sum(f["policy_tier"] == "blocking" for f in findings)
    advisory = sum(f["policy_tier"] == "advisory" for f in findings)
    if incomplete:
        status, reason = "incomplete", "；".join(list(incomplete) + list(notes))
    else:
        status, reason = ("fail" if blocking else "pass"), ("；".join(notes) or None)
    coverage = []
    for ctl in ("VS-G1-SLOPSQUAT", "VS-G1-COOLDOWN", "VS-G1-INSTALL-HOOK"):
        hit = [f for f in findings if CONTROL_OF.get(f["rule_id"]) == ctl and f["policy_tier"] == "blocking"]
        coverage.append({"control_id": ctl, "state": "untested" if incomplete else ("fail" if hit else "pass"), "reason": None})
    coverage.append({"control_id": "VS-G1-SBOM", "state": "pending", "reason": None})
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=TARGET).stdout.strip() or None
    except Exception:
        commit = None
    gate = {"gate": "G1", "status": status, "status_reason": reason, "mode": mode, "risk_tier": tier,
            "scope": scope, "diff_base": base, "commit": commit,
            "started_at": started, "finished_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [{"name": "vibesec-slopcheck", "version": "2.0.0", "state": "ran", "exit_code": None,
                       "output_ref": sarif_ref, "duration_seconds": None}],
            "findings_count": {"blocking": blocking, "advisory": advisory},
            "coverage": coverage}
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(gate, ensure_ascii=False, indent=2), encoding="utf-8")

def _opt(args, name):
    """收集重複出現的 `--name value` 參數。"""
    return [args[i + 1] for i, a in enumerate(args[:-1]) if a == name]

def selftest():
    """離線自我測試 --target：registry 查詢以替身取代，只驗證路徑、全量探索、鎖定檔與例外範圍。"""
    import contextlib, io, tempfile
    from jsonschema import Draft202012Validator
    global TARGET, npm_check, pypi_check, load_exceptions
    fails = []
    schema = Draft202012Validator(json.loads((ROOT / "schemas/gate-result.schema.json").read_text(encoding="utf-8")))
    real = (npm_check, pypi_check, load_exceptions)
    stub = lambda pkg, ver, c: ([fnd("vibesec.g1.cooldown-violation", pkg, "pypi", ver, "selftest 替身", "blocking")], None)
    npm_check = pypi_check = stub
    # 合成例外（不依賴政策檔現有例外與其到期日）
    load_exceptions = lambda today=None: ([{"rule_id": "vibesec.g1.cooldown-violation", "path_glob": "examples/vulnapp/**",
                                            "reason": "selftest", "approved_by": "selftest", "expires": "2099-12-31"}], [])

    def run(*argv):
        global TARGET
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(["g1_slopcheck.py", *argv])
        finally:
            TARGET = ROOT
        return code, (json.loads(out.getvalue()) if out.getvalue().strip() else {})

    def git(d, *a):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *a], cwd=d, capture_output=True, check=True)

    try:
        # PEP 503：PyPI 的 _ / . / 大小寫與 - 是同一個專案；npm 不正規化；真正的拼錯仍要抓到
        c = {"similarity": 0.80}
        for name in ("typing_extensions", "Typing.Extensions", "TYPING-extensions"):
            if similarity_check(name, "pypi", {"typing-extensions"}, {}, {}, c):
                fails.append(f"PyPI {name} 與 typing-extensions 是同一個專案（PEP 503），不得判 typosquat")
        if not similarity_check("typing-extensionz", "pypi", {"typing-extensions"}, {}, {}, c):
            fails.append("PyPI typing-extensionz 仍要判 typosquat")
        if not similarity_check("left_pad", "npm", {"left-pad"}, {}, {}, c):
            fails.append("npm 的 left_pad 與 left-pad 是不同套件，不做 PEP 503 正規化")
        bl = {("pypi", "foo-bar"): {"reason": "t"}, (None, "baz_qux"): {"reason": "u"}}
        if not lookup(bl, "pypi", "Foo_Bar") or not lookup(bl, "pypi", "baz.qux") or lookup(bl, "npm", "baz-qux"):
            fails.append("黑名單／允許清單查詢：PyPI 依 PEP 503 比對，npm 只比對小寫")
        with tempfile.TemporaryDirectory() as d:
            rf = Path(d) / "AGENTS.md"
            rf.write_text("pip install -r requirements.lock.txt\n`pip install -e git+https://example.com/x.git`\n"
                          "uv pip install --index-url https://pypi.org/simple foo\npip install --requirement req.txt\n"
                          "npm install --registry https://r.example.com bar\npip install -U fastapi-auth-helperz\n"
                          "npm install -D left-pad\nRun `pip install requests`, then `pip install requests` again.\n",
                          encoding="utf-8")
            got = rule_file_mentions(rf)
            want = [("npm", "left-pad", None), ("pypi", "fastapi-auth-helperz", None), ("pypi", "requests", None)]
            if sorted(got) != want:
                fails.append(f"規則檔：帶值旗標（-r、-e、--index-url、--registry）的值不是套件名，重複提及只算一次（得到 {got}）")
        with tempfile.TemporaryDirectory() as d:
            D = Path(d)
            (D / "examples/vulnapp").mkdir(parents=True)
            (D / "examples/vulnapp/requirements.txt").write_text("requests==2.0.0\n")
            (D / "deploy").mkdir()
            (D / "deploy/python-requirements.txt").write_text("fastapi==0.1.0 \\\n    --hash=sha256:00\n")
            (D / "frontend").mkdir()
            (D / "frontend/package-lock.json").write_text('{"lockfileVersion": 3, "packages": {}}')
            (D / "README.md").write_text("沒有安裝指令。\n")
            (D / "node_modules/x").mkdir(parents=True)
            (D / "node_modules/x/package.json").write_text('{"dependencies": {"evil": "1.0.0"}}')
            git(D, "init", "-q"); git(D, "add", "examples", "deploy", "frontend", "README.md"); git(D, "commit", "-qm", "t")
            files = discover(D)
            if "node_modules/x/package.json" in files or "deploy/python-requirements.txt" not in files:
                fails.append(f"git repo 的全量探索只取追蹤中的檔案（得到 {files}）")
            gate = D.parent / f"{D.name}-gate.json"
            code, out = run("--target", str(D), "--gate", str(gate))
            pkgs = {f["package"]: f for f in out.get("findings", [])}
            if set(pkgs) != {"requests", "fastapi"}:
                fails.append(f"只給 --target → 全量掃描 requirements（含 python-requirements.txt），不掃 node_modules（得到 {sorted(pkgs)}）")
            if pkgs.get("requests", {}).get("policy_tier") != "blocking" or "exception" in pkgs.get("requests", {}):
                fails.append("外部目標：本 repo 的 examples/vulnapp/** 例外不得套用（仍為 blocking）")
            if pkgs.get("fastapi", {}).get("manifest") != "deploy/python-requirements.txt":
                fails.append("manifest 路徑相對目標專案根目錄")
            if code != 1 or out.get("status") != "incomplete" or "frontend/package-lock.json" not in out.get("status_reason", ""):
                fails.append(f"尚無解析器的鎖定檔 → incomplete 並列出檔名（exit {code}，{out.get('status_reason')}）")
            g = json.loads(gate.read_text(encoding="utf-8"))
            gate.unlink()
            errs = list(schema.iter_errors(g))
            if errs:
                fails.append(f"gate JSON 不符 schema：{errs[0].message}")
            head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=D).stdout.strip()
            if g.get("commit") != head or g.get("scope") != "full" or "exceptions" not in (g.get("status_reason") or ""):
                fails.append("gate JSON 的 commit 取目標專案 HEAD、scope full、status_reason 註明例外未套用")
            code, out = run("--target", str(D), "--manifest", "examples/vulnapp/requirements.txt")
            if [f["package"] for f in out.get("findings", [])] != ["requests"] or code != 1:
                fails.append("--target 搭配 --manifest：相對路徑以目標專案為準，只掃指定的檔")
        code, out = run("--target", str(ROOT), "--manifest", "examples/vulnapp/pyproject.toml")
        if not out.get("findings") or any(f["policy_tier"] != "advisory" or "exception" not in f for f in out["findings"]):
            fails.append("目標是本 repo 時照常套用 blocking-policy 例外")
        code, _ = run("--target", str(ROOT / "no-such-dir"))
        if code != 2:
            fails.append("--target 不是目錄 → exit 2（incomplete）")
    finally:
        npm_check, pypi_check, load_exceptions = real
        TARGET = ROOT
    return fails

def main(argv):
    global TARGET
    args = argv[1:]
    if args[:1] == ["selftest"]:
        fails = selftest()
        for f in fails:
            print(f"FAIL {f}")
        print("selftest " + ("通過" if not fails else f"失敗 {len(fails)} 項"))
        return 1 if fails else 0
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    target = (_opt(args, "--target") or [None])[-1]
    if target:
        TARGET = Path(target).expanduser().resolve()
        if not TARGET.is_dir():
            print(f"⚠️ G1 無法完成檢查：--target 不是目錄（{target}）→ incomplete。", file=sys.stderr)
            return 2
    manifests = list(_opt(args, "--manifest"))
    rule_files = list(_opt(args, "--rules-file"))
    base = (_opt(args, "--base") or [None])[-1]
    sarif_out = (_opt(args, "--sarif") or [None])[-1]
    gate_out = (_opt(args, "--gate") or [None])[-1]
    changed = []
    if "--staged" in args:
        changed += staged_files()
    for lst in _opt(args, "--changed-files"):
        try:
            changed += [l.strip() for l in Path(lst).read_text().splitlines() if l.strip()]
        except OSError:
            pass
    selected = manifests or rule_files or changed or "--staged" in args or _opt(args, "--changed-files")
    if target and not selected:
        changed = discover(TARGET)          # 只給 --target：全量掃描目標專案
    for f in changed:
        if MANIFEST_RE.search(f):
            manifests.append(f)
        elif is_rule_file(f) and not (f.startswith("config/slopsquat/") and not external_target()):
            rule_files.append(f)
    manifests = [resolve(m) for m in dict.fromkeys(manifests) if resolve(m).exists()]
    rule_files = [resolve(r) for r in dict.fromkeys(rule_files) if resolve(r).exists()]
    scope = "diff" if base else "full"
    notes = []
    if external_target():
        notes.append(f"目標專案 {TARGET.name}：blocking-policy exceptions 只核准給本 repo 路徑，未套用")

    if not manifests and not rule_files:
        out = {"gate": "G1", "findings": []}
        if external_target():
            out["target"] = str(TARGET)
        print(json.dumps(out, ensure_ascii=False, indent=2))
        if sarif_out:
            write_sarif(sarif_out, [])
        if gate_out:
            write_gate(gate_out, [], [], started, base, scope, sarif_out, notes)
        print("G1 slopcheck：無相依清單或規則檔變更，略過。", file=sys.stderr)
        return 0

    c = cfg()
    # 相似度只比對同生態系的熱門清單（npm 的 request 不該被比成 PyPI 的 requests）
    popular = {"npm": load_popular("popular-npm.txt"), "pypi": load_popular("popular-pypi.txt")}
    blacklist = load_list("blacklist.yaml")
    allowlist = load_list("allowlist.yaml")
    exceptions, ignored_exceptions = load_exceptions() if not external_target() else ([], [])

    targets = [(m, added_packages(m, base), False) for m in manifests]
    targets += [(r, rule_file_mentions(r), True) for r in rule_files]

    findings, incomplete = [], []
    unparsed = [rel_path(m) for m in manifests if UNPARSED_RE.search(Path(m).name)]
    if unparsed:
        incomplete.append(f"鎖定檔尚無解析器，其中的套件未逐一檢查：{', '.join(unparsed)}")
    for source, packages, from_rules in targets:
        source_rel = rel_path(source)
        for eco, name, ver in packages:
            found = []
            sim = similarity_check(name, eco, popular.get(eco, set()), blacklist, allowlist, c)
            if sim:
                found.append(sim)
            if not lookup(allowlist, eco, name):
                fs, reason = (npm_check(name, ver, c) if eco == "npm" else pypi_check(name, ver, c))
                if from_rules:
                    for f in fs:
                        if f["rule_id"] == "vibesec.g1.hallucinated-package":
                            f["rule_id"] = "vibesec.g1.rules-file-unknown-package"
                            f["policy_tier"] = _policy().cap(f["rule_id"], f["policy_tier"])   # 改名後依政策重算
                found.extend(fs)
                if reason:
                    incomplete.append(reason)
            for f in found:
                f["manifest"] = source_rel
                findings.append(apply_exceptions(f, exceptions))

    out = {"gate": "G1", "findings": findings}
    if external_target():
        out["target"] = str(TARGET)
        out["notes"] = notes
    if ignored_exceptions:
        out["ignored_exceptions"] = ignored_exceptions
    if incomplete:
        out["status"] = "incomplete"
        out["status_reason"] = "；".join(incomplete)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    if sarif_out:
        write_sarif(sarif_out, findings)
    if gate_out:
        write_gate(gate_out, findings, incomplete, started, base, scope, sarif_out, notes)

    blocking = [f for f in findings if f["policy_tier"] == "blocking"]
    if blocking:
        print(f"\n⛔ G1 阻擋：{len(blocking)} 筆 blocking 供應鏈發現。", file=sys.stderr)
        return 1
    if incomplete:
        print("\n⚠️ G1 無法完成檢查（網路/registry 失敗或鎖定檔未解析）→ incomplete，絕不視為通過。", file=sys.stderr)
        return 2
    print("\n✅ G1 快篩通過。", file=sys.stderr)
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
