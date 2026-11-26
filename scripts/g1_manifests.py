#!/usr/bin/env python3
"""清單與鎖定檔解析：快篩（g1_slopcheck）與 SBOM 核對（g1_sbom）共用同一份「哪些檔案是清單、裡面釘選了哪些套件」的認定。

行程內、只用標準函式庫、沒有全域狀態：不連網、不呼叫 git、不讀政策（#262，#260 的 S1）。
介面：
  parse_manifest(paths, *, root) -> Parsed   檔案內容 → 套件條目；無法解析、非 registry 來源、無解析器的清單都回報，
                                               不靜默略過（AGENTS.md 規則 2：拿不到證據就是未完成，不是通過）
  classify(path, *, view)        -> Classified  這個路徑算不算清單、有沒有解析器、是不是鎖定檔
  pep508(req)                                  PEP 508 需求字串 → (名稱, 鎖定版本)

分類有兩個檢視：view="screen" 是快篩選檔（含未釘選清單如 package.json、pyproject.toml、Pipfile、setup.py／setup.cfg，以及全部鎖定檔），
view="sbom" 是 SBOM 核對（只看鎖定檔，不看 setup.py／setup.cfg／Pipfile）。兩者對尚無解析器的鎖定檔（pnpm-lock.yaml、yarn.lock、
bun.lock、bun.lockb、Pipfile.lock、pdm.lock、pylock*.toml）一致標為 unparsed（#269）。
"""
from __future__ import annotations
import json, re
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------- 分類

# requirements 檔：檔名含 requirements 的 .txt（requirements-dev.txt、locks/python-requirements.txt），或 requirements/ 目錄下的
# .txt（requirements/base.txt）。選檔與解析共用這一條：以前選檔對整段路徑比對、解析只看檔名，requirements/base.txt
# 被選進來卻一個套件都沒查，G1 照樣 pass。
REQUIREMENTS_RE = re.compile(r'(?:[^/]*requirements[^/]*|(?:^|/)requirements/(?:[^/]+/)*[^/]+)\.txt$')
# SBOM 核對看的是「鎖定檔」（與 REQUIREMENTS_RE 一致：檔名含 requirements 的 .txt（locks/python-requirements.txt），
# 或 requirements/ 目錄下的 .txt（requirements/base.txt））；LOCKFILE_RE 與 LOCK_UNPARSED_RE 兩條原樣取自 g1_sbom.py 重構前的 LOCKFILE 與 UNPARSED
LOCKFILE_RE = re.compile(r"(?:(?:^|/)(?:package-lock\.json|npm-shrinkwrap\.json|uv\.lock|poetry\.lock)"
                         r"|[^/]*requirements[^/]*\.txt|(?:^|/)requirements/(?:[^/]+/)*[^/]+\.txt)$")
# npm／PyPI 生態系中尚無解析器的鎖定檔：裡面釘選的套件無法逐一核對是否出現在 SBOM，快篩亦無法逐一檢查套件 → incomplete（不是 pass，#269）。
_NEW_UNPARSED_LOCKS = r"(?:bun\.lockb?|pdm\.lock|pylock(?:\.[^/]+)?\.toml)"
LOCK_UNPARSED_RE = re.compile(rf"(?:^|/)(?:pnpm-lock\.yaml|yarn\.lock|Pipfile\.lock|{_NEW_UNPARSED_LOCKS})$")

MANIFEST_RE = re.compile(r'(package(-lock)?\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|pyproject\.toml|poetry\.lock|uv\.lock|Pipfile(\.lock)?|setup\.py|setup\.cfg)$'
                         rf'|(?:^|/){_NEW_UNPARSED_LOCKS}$|' + REQUIREMENTS_RE.pattern)
# 有 manifest 樣式但尚無解析器的檔（比對檔名）：其中的套件無法逐一檢查 → incomplete（不是 pass；以前 Pipfile／setup.py／bun.lock／pdm.lock／pylock*.toml 不被當無解析器清單）
UNPARSED_RE = re.compile(r'(pnpm-lock\.yaml|yarn\.lock|Pipfile(\.lock)?|setup\.py|setup\.cfg)$'
                         rf'|^{_NEW_UNPARSED_LOCKS}$')

# npm／PyPI 以外生態系的慣例清單檔（#316）：repo 尚未支援這些生態系，其中的套件沒有被檢查 → 快篩記 incomplete（不是 pass）。
# 只比對慣例檔名（不看內容）；以後支援某個生態系時，從這裡移到有解析器的那一類。SBOM 核對（view="sbom"）不看這份清單。
UNSUPPORTED_ECOSYSTEMS = (
    ("go", r"go\.mod|go\.sum"),
    ("rust", r"Cargo\.toml|Cargo\.lock"),
    ("maven", r"pom\.xml"),
    ("gradle", r"build\.gradle(?:\.kts)?"),
    ("ruby", r"Gemfile(?:\.lock)?"),
    ("php", r"composer\.(?:json|lock)"),
    ("nuget", r"[^/]+\.csproj|packages\.config|Directory\.Packages\.props"),
    ("deno", r"deno\.jsonc?"),
    ("elixir", r"mix\.exs"),
    ("swift", r"Package\.swift"),
    ("dart", r"pubspec\.yaml"),
    ("conda", r"environment\.ya?ml"),
)
_UNSUPPORTED_RE = [(eco, re.compile(rf"(?:^|/)(?:{pat})$")) for eco, pat in UNSUPPORTED_ECOSYSTEMS]

VIEWS = ("screen", "sbom")


@dataclass(frozen=True)
class Classified:
    kind: str       # "parsed"（有解析器）｜"unparsed"（清單，但尚無解析器）｜"unsupported"（不支援的生態系清單，#316）｜"other"
    is_lock: bool   # 鎖定檔：釘選到確切版本的清單（SBOM 核對用的樣式）
    ecosystem: str | None = None   # kind="unsupported" 時的生態系名稱（例如 go、rust）；其餘為 None


def classify(path, *, view: str = "screen") -> Classified:
    """路徑 → 是不是清單、有沒有解析器、是不是鎖定檔。view 選用哪一組現有樣式（見檔頭）：
    screen＝快篩選檔（MANIFEST_RE／UNPARSED_RE）；sbom＝SBOM 核對（LOCKFILE_RE／LOCK_UNPARSED_RE）。"""
    if view not in VIEWS:
        raise ValueError(f"view 必須是 {VIEWS} 之一：{view!r}")
    s = path if isinstance(path, str) else Path(path).as_posix()
    is_lock, eco = bool(LOCKFILE_RE.search(s)), None
    if view == "sbom":
        kind = "parsed" if is_lock else "unparsed" if LOCK_UNPARSED_RE.search(s) else "other"
    elif not MANIFEST_RE.search(s):
        eco = next((e for e, rx in _UNSUPPORTED_RE if rx.search(s)), None)
        kind = "unsupported" if eco else "other"
    else:
        kind = "unparsed" if UNPARSED_RE.search(Path(s).name) else "parsed"
    return Classified(kind, is_lock, eco)


# ---------------------------------------------------------------- 回傳形狀

@dataclass(frozen=True)
class Dep:
    eco: str                 # "npm"｜"pypi"
    name: str
    version: str | None      # 鎖定版本；tag／範圍／未釘選為 None
    direct: bool | None      # True＝直接相依；False＝只因其他套件宣告而出現；None＝無法確定，呼叫端一律視同直接（較嚴的一側）


@dataclass(frozen=True)
class Parsed:
    entries: tuple[Dep, ...]   # 去重（生態系、名稱小寫、版本）後依首次出現的順序
    bad: tuple[str, ...]       # 無法解析、不是 registry 來源、沒有對應解析器的條目：其中的套件沒有被檢查
    unparsed: tuple[str, ...]  # 被選為清單、但尚無解析器的檔案（依輸入順序、原樣回報輸入路徑）；套件沒有被檢查


# ---------------------------------------------------------------- PEP 508 與 requirements

# PEP 508 需求字串：名稱、可選 extras、版本規格；忽略環境標記（; 之後）
REQ_RE = re.compile(r'^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:===?\s*([0-9][^,;\s]*))?')

# 直接 URL／VCS 來源（pkg @ https://…、git+…、-e git+…）：registry 查不到，不能當成已檢查
URL_REQ = re.compile(r'^(-e\s+)?(git\+|https?:|ssh:|svn\+|hg\+|bzr\+|file:)|\s@\s')


def pep508(req):
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

# requirements 檔的選項行：以前 pep508 對所有 - 開頭的行回傳 None，-r base.in 引入的套件從頭到尾沒查，
# --index-url／--extra-index-url 指向私有 index 也照樣以公開 PyPI 的結果判定（第五次審查 G1-3）。
REQ_PYPI_INDEXES = {"https://pypi.org/simple", "https://pypi.python.org/simple"}
REQ_INCLUDE = re.compile(r'^(?:-r|--requirement)(?:\s*=\s*|\s+|(?=[^\s-]))(\S+)')
REQ_SOURCE = re.compile(r'^(-i|--index-url|--extra-index-url|-f|--find-links|--no-index)\b(?:\s*=\s*|\s+)?(\S*)')


def _requirements(path, boundary, seen=None):
    """requirements 檔（含 -r 遞迴引入）→ ([(名稱, 版本)], [無法驗證的條目])。
    -r 的檔案相對於引入它的檔案；不存在、超出 boundary（目標專案根目錄）或循環引入 → 記入無法驗證。
    套件來源不是公開 PyPI（私有／額外 index、find-links、--no-index）→ 記入無法驗證：registry 檢查查的是 PyPI。
    -c／--constraint 只限制版本、不安裝套件，與其他選項（--hash、--pre…）一樣略過。"""
    path = Path(path)
    seen = set() if seen is None else seen
    real = path.resolve()
    if real in seen:
        return [], [f"{path.name}: -r 循環引入，略過重複的檔案"]
    seen.add(real)
    out, bad = [], []
    for raw in path.read_text(errors="ignore").splitlines():
        line = raw.split(" #", 1)[0].strip().rstrip("\\").strip()
        m = REQ_INCLUDE.match(line)
        if m:
            ref = m.group(1)
            inc = (path.parent / ref).resolve()
            if "$" in ref:
                bad.append(f"{path.name}: -r {ref[:60]}（含環境變數，無法確定引入的檔案）")
            elif boundary not in inc.parents:
                bad.append(f"{path.name}: -r {ref[:60]}（超出目標專案，未檢查）")
            elif not inc.is_file():
                bad.append(f"{path.name}: -r {ref[:60]}（檔案不存在，其中的套件未檢查）")
            else:
                e, b = _requirements(inc, boundary, seen)
                out += e; bad += b
            continue
        m = REQ_SOURCE.match(line)
        if m:
            opt, url = m.group(1), m.group(2).rstrip("/")
            if not (opt in ("-i", "--index-url") and url in REQ_PYPI_INDEXES):
                bad.append(f"{path.name}: {line[:80]}（套件來源不是公開 PyPI，registry 檢查不代表實際安裝的套件）")
            continue
        x = pep508(line)
        if x:
            out.append(x)
        elif x is False:
            bad.append(f"{path.name}: {line[:60]}")
    return out, bad


# ---------------------------------------------------------------- pyproject.toml、uv.lock、poetry.lock

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
        x = pep508(r)
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


PYPI_INDEXES = ("https://pypi.org/simple", "https://pypi.org/simple/", "https://pypi.org/pypi", "https://pypi.org/pypi/")
ARCHIVE_RE = re.compile(r"\.(whl|zip|tar\.gz|tgz|tar\.bz2)$", re.I)


def _lock_packages(data):
    """uv.lock / poetry.lock 的 [[package]] → ([(名稱, 版本)], [無法以 registry 驗證的條目])。
    略過本地專案（editable / virtual / directory、非封存檔的 path，即專案自己的程式碼）。git、url、本地封存檔、
    私有 registry 來源查公開 PyPI 不代表裝的是那一份 → 回報給呼叫端記 incomplete（同 _npm_lock 的非 registry 條目）。"""
    out, bad = [], []
    for pkg in data.get("package") or []:
        if not isinstance(pkg, dict) or not pkg.get("name"):
            continue
        name, src = pkg["name"], pkg.get("source") or {}
        kind = src.get("type")                       # poetry.lock：git／url／file／directory／legacy（私有 index）
        if any(k in src for k in ("editable", "virtual", "directory")) or kind == "directory" \
                or ("path" in src and not ARCHIVE_RE.search(str(src["path"]))):
            continue
        why = None
        if "git" in src or kind == "git":
            why = "git"
        elif kind == "url" or ("url" in src and kind != "legacy"):
            why = "url"
        elif "path" in src or kind == "file":
            why = "本地封存檔"
        elif "registry" in src and str(src["registry"]) not in PYPI_INDEXES:
            why = f"registry {src['registry']}"
        elif kind == "legacy" and str(src.get("url") or "") not in PYPI_INDEXES:
            why = f"私有 index {src.get('url') or src.get('reference') or '?'}"
        if why:
            bad.append(f"{name}（{why}）")
        else:
            out.append((name, pkg.get("version")))
    return out, bad


# ---------------------------------------------------------------- package.json、package-lock.json

DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
NPM_REGISTRIES = ("https://registry.npmjs.org/", "https://registry.yarnpkg.com/")
SEMVER = re.compile(r"^\d+\.\d+\.\d+")


def _npm_lock(path):
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


# ---------------------------------------------------------------- 入口

def _merge_direct(a, b):
    """同一個套件出現多次時合併直接／間接：任何一次是直接 → 直接；否則只要有一次無法確定 → 無法確定（視同直接）；
    只有每一次都確定是間接才算間接。"""
    if a is True or b is True:
        return True
    if a is None or b is None:
        return None
    return False


def parse_manifest(paths, *, root) -> Parsed:
    """清單檔 → Parsed。root：-r 引入的包含邊界（目標專案根目錄）。檔案在 root 之下時邊界是 root；
    不在 root 之下（例如單獨傳入樹外的檔案）時退回該檔所在目錄。

    無法解析的檔、非 registry 來源的條目、沒有對應解析器的檔都回報，不靜默略過（incomplete ≠ pass，第四次審視 S-1／S-2）。
    不存在的檔案略過（指定的檔案不存在由呼叫端另外處理）。"""
    root = Path(root).resolve()
    out, bad, unparsed = [], [], []
    for p in paths:
        p = Path(p)
        if not p.exists():
            continue
        if UNPARSED_RE.search(p.name):
            unparsed.append(str(p))
            continue
        text = p.read_text(errors="ignore")
        if p.name in ("package-lock.json", "npm-shrinkwrap.json"):
            e, b = _npm_lock(p)
            out += [("npm", n, v, d) for n, v, d in e]
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
                        out.append(("npm", real, ver, True))
        elif p.name == "pyproject.toml":
            data = _toml(p)
            if data is None:
                bad.append(f"{p.name}: TOML 無法解析（或 tomllib 缺席）"); continue
            e, b = _pyproject_deps(data)
            out += [("pypi", n, v, True) for n, v in e]
            bad += [f"{p.name}: {x}" for x in b]
        elif p.name in ("uv.lock", "poetry.lock"):
            data = _toml(p)
            if data is None:
                bad.append(f"{p.name}: TOML 無法解析（或 tomllib 缺席）"); continue
            e, b = _lock_packages(data)
            out += [("pypi", n, v, None) for n, v in e]
            bad += [f"{p.name}: {x}" for x in b]
        elif REQUIREMENTS_RE.search(p.as_posix()):
            e, b = _requirements(p, root if root in p.resolve().parents else p.resolve().parent)
            out += [("pypi", n, v, None) for n, v in e]
            bad += b
        else:
            # 被當成 manifest 卻沒有對應的解析器：套件一個都沒查，不能當成「沒有相依」（incomplete ≠ pass）
            bad.append(f"{p.name}: 沒有對應的解析器，其中的套件未檢查")
    # 去重
    seen, uniq = {}, []
    for eco, n, v, d in out:
        k = (eco, n.lower(), v)
        if k in seen:
            i = seen[k]
            uniq[i] = Dep(eco, uniq[i].name, v, _merge_direct(uniq[i].direct, d))
        else:
            seen[k] = len(uniq)
            uniq.append(Dep(eco, n, v, d))
    return Parsed(tuple(uniq), tuple(bad), tuple(unparsed))
