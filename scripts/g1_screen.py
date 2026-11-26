#!/usr/bin/env python3
"""G1 供應鏈快篩深模組（#266，#260 的 S5）：Request、Env、resolve_scope、screen 與 Outcome。

快篩從呼叫方看只需要兩樣東西：一個範圍（Request：命令列參數解析後的純值）與一組注入的外部依賴（Env：Git、套件登錄庫、
已載入的 Policy、設定根目錄、今天日期、並行數），回傳不可變純值 Outcome。這個模組沒有任何模組層的可變狀態：
所有預期失敗（registry 查詢失敗、無解析器清單、設定檔缺席或毀損、--staged 取不到、--changed-files 讀不到、政策讀不到）
都轉成未完成原因，不丟例外、絕不當成通過（AGENTS.md 規則 2）；退出碼只在 Outcome 內由閘門狀態唯一推導。

政策與執行模式仍只經 vibesec_policy.load_policy 取得，由呼叫端載入後放進 Env（ADR 0001、0002 不動）；
政策讀不到時走 Outcome.unreadable(...) 路徑。
"""
from __future__ import annotations
import difflib
import itertools
import json
import os
import re
import sys
import tempfile
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

ROOT = Path(__file__).resolve().parent.parent      # VibeSec 本身：設定、清單、政策
sys.path.insert(0, str(Path(__file__).resolve().parent))
import gate_result  # noqa: E402  閘門結果與自產 SARIF 骨架（不依賴 PyYAML）
from gate_verdict import REQUIRED_CONTROLS, verdict  # noqa: E402  狀態判定的唯一來源（不依賴 PyYAML）
from g1_git import GitFailure, SubprocessGit  # noqa: E402
from g1_manifests import REQUIREMENTS_RE, classify, parse_manifest, pep508  # noqa: E402
from g1_registry import HttpRegistry, NotFound, Unavailable, Unknown, canon, valid_name  # noqa: E402

if TYPE_CHECKING:       # 只給型別標註：快篩不在匯入時就要求 PyYAML（政策在 default_env 才載入）
    from vibesec_policy import Policy

WORKERS = 8                                        # registry 並行查詢數的預設值
RULE_FILE_DEFAULTS = (".cursorrules", "AGENTS.md", "SKILL.md", "CLAUDE.md", ".cursor/rules/**/*.mdc", "**/*.md")
# 全量掃描（--target、非 git 目錄）時略過的目錄：安裝產物與快取，不是專案宣告的相依
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", "dist", "build"}

LEVEL = {"blocking": "error", "advisory": "warning"}
TOOL_NAME, TOOL_VERSION = "vibesec-slopcheck", "2.0.0"
CONTROLS = ("VS-G1-SLOPSQUAT", "VS-G1-COOLDOWN", "VS-G1-INSTALL-HOOK")
_CONTROL_OF = {
    "vibesec.g1.hallucinated-package": "VS-G1-SLOPSQUAT",
    "vibesec.g1.rules-file-unknown-package": "VS-G1-SLOPSQUAT",
    "vibesec.g1.low-download-package": "VS-G1-SLOPSQUAT",
    "vibesec.g1.cooldown-violation": "VS-G1-COOLDOWN",
    "vibesec.g1.postinstall-egress": "VS-G1-INSTALL-HOOK",
}
EXIT_CODE_OF = {"pass": 0, "fail": 1, "incomplete": 2}

__all__ = [
    "Env",
    "Outcome",
    "Request",
    "RuleCfg",
    "Scope",
    "ScopeFailure",
    "TOOL_NAME",
    "TOOL_VERSION",
    "build_env",
    "default_env",
    "dumps_json",
    "resolve_scope",
    "screen",
]


# ---------------------------------------------------------------- 設定讀取（以設定根目錄為準，沒有全域路徑）
def load_yaml(p: Path):
    """讀 YAML；缺席、無法解析或缺 PyYAML 都回 None（呼叫端退回預設值）。
    會讓檢查變寬鬆的設定是否讀得到，由 config_problems() 另外檢查並記 incomplete。"""
    try:
        import yaml
        return yaml.safe_load(p.read_text()) if p.exists() else None
    except Exception:
        return None


def mapping(x):
    return x if isinstance(x, dict) else {}


class RuleCfg(NamedTuple):
    globs: list                     # 規則檔的 glob 清單
    install_command: object         # 設定的安裝指令 regex（re.Pattern）或 None


def _rule_cfg_of(config_root: Path) -> RuleCfg:
    """(規則檔 glob 清單, 設定的安裝指令 regex 或 None)。glob 取 vibesec.yaml scan_agent_rule_files 與 cooldown.yaml
    agent_rule_files 的聯集（只會多掃，不會少掃）；兩者都缺席時用 RULE_FILE_DEFAULTS。regex 無法編譯 → 只用內建樣式。"""
    c = mapping(load_yaml(config_root / "config" / "slopsquat" / "cooldown.yaml"))
    g1 = (mapping(load_yaml(config_root / "vibesec.yaml")).get("gates") or {}).get("g1_supply_chain") or {}
    globs = [str(x) for x in (g1.get("scan_agent_rule_files") or []) + (c.get("agent_rule_files") or [])]
    try:
        rx = re.compile(c["install_command_regex"]) if c.get("install_command_regex") else None
    except (re.error, TypeError):
        rx = None
    return RuleCfg(list(dict.fromkeys(globs)) or list(RULE_FILE_DEFAULTS), rx)


# ---------------------------------------------------------------- Request、Env、Scope
@dataclass(frozen=True)
class Request:
    """要掃什麼（命令列參數解析後的純值）。target 是 --target；None＝沒有指定（範圍就是明確選的檔，不做全量探索）。
    changed_lists 是 --changed-files 指向的清單檔（由 resolve_scope 讀，讀不到是未完成原因）。"""
    target: Path | None = None
    manifests: tuple = ()
    rule_files: tuple = ()
    changed_lists: tuple = ()
    staged: bool = False
    base: str | None = None

    @property
    def kind(self):
        """只看變更（--base、--staged、--changed-files 任一個）→ diff；否則 full。"""
        return "diff" if self.base or self.staged or self.changed_lists else "full"

    @property
    def root(self) -> Path:
        """被掃描的專案根目錄；沒有指定 --target 時是本 repo。"""
        return self.target if self.target is not None else ROOT


@dataclass(frozen=True)
class Env:
    """外部依賴與設定。每個欄位都有兩個實際的轉接器（生產與測試替身），沒有任何模組層的覆寫點。"""
    policy: "Policy"                # 已載入的 vibesec_policy.Policy（讀不到政策由呼叫端以 Outcome.unreadable 處理）
    git: object                     # Git 接縫：staged()、tracked_files()、show(ref, path)（SubprocessGit／FakeGit）
    registry: object                # 套件登錄庫接縫：facts()、requires()（HttpRegistry／FakeRegistry）
    config_root: Path               # 放 vibesec.yaml 與 config/slopsquat/ 的目錄
    today: date
    workers: int
    rule_cfg: RuleCfg               # _rule_cfg_of(config_root)：每次執行讀一次，不是每個檔讀一次

    @property
    def config_dir(self) -> Path:
        return self.config_root / "config" / "slopsquat"

    @property
    def vibesec_file(self) -> Path:
        return self.config_root / "vibesec.yaml"


def build_env(policy, *, git, registry=None, config_root: Path = ROOT, today: date | None = None,
              workers: int = WORKERS, rule_cfg=None) -> Env:
    """policy 與 git 一定要給：政策不從全域取得（讀不到政策走 Outcome.unreadable），git 的工作目錄是被掃描的專案。
    registry 缺省用生產的 HttpRegistry。"""
    return Env(policy=policy, git=git, registry=registry if registry is not None else HttpRegistry(),
               config_root=Path(config_root), today=today or date.today(), workers=workers,
               rule_cfg=rule_cfg if rule_cfg is not None else _rule_cfg_of(Path(config_root)))


def default_env(root, policy_root=ROOT, registry=None):
    """生產預設的 Env：政策從 policy_root 載入（讀不到 → (None, 未完成原因)）、Git 是生產的 SubprocessGit（工作目錄是被掃描的專案）、
    登錄庫缺省是生產的 HttpRegistry、設定取自本 repo。"""
    from vibesec_policy import load_policy
    policy, problem = load_policy(policy_root)
    if problem:
        return None, problem
    return build_env(policy, git=SubprocessGit(root), registry=registry), None


@dataclass(frozen=True)
class ScopeFailure:
    """範圍本身就無法決定（--target 不是目錄、--staged 取不到暫存區、變更清單讀不到）：不知道改了什麼 ≠ 沒有變更。
    problem 是閘門結果的未完成原因；message 是標準錯誤的那一行（逐字沿用以前的訊息）。"""
    problem: str
    message: str


@dataclass(frozen=True)
class Scope:
    manifests: tuple = ()           # 要掃的清單與鎖定檔（絕對路徑）
    rule_files: tuple = ()          # 要掃的 agent 規則檔（絕對路徑）
    problems: tuple = ()            # 未完成原因：指定的檔不存在、變更清單的檔在 base 也查不到
    notes: tuple = ()               # 備註：變更清單中已刪除的檔
    kind: str = "full"
    failure: ScopeFailure | None = None


# ---------------------------------------------------------------- 路徑與分類（以目標專案為準，沒有全域的 TARGET）
def rel_path(root: Path, path):
    """路徑轉成相對目標專案根目錄的 POSIX 路徑；目標外的檔案保持原樣。"""
    p = Path(path).resolve()
    try:
        return p.relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        return Path(path).as_posix()


def resolve(root: Path, path):
    """相對路徑先以目標專案為基準，找不到再以目前目錄為基準（相容 --manifest 傳入工作目錄相對路徑）。"""
    p = Path(path)
    if p.is_absolute() or not (root / p).exists():
        return p
    return root / p


def is_external_project(env, root: Path) -> bool:
    """受驗樹不是本 repo（外部專案）：判斷交給 Policy.is_this_repo（與政策例外是否套用同一份條件；CI 以 VIBESEC_PROJECT_ROOT 指出受驗樹）。"""
    return not env.policy.is_this_repo(root)


def discover(root: Path, git):
    """列出目標專案的所有 manifest 與 agent 規則檔（相對目標根目錄）。git repo 取追蹤中的檔案，否則走訪目錄。"""
    files = git.tracked_files()
    if files is None:
        files = []
        for d, dirs, names in os.walk(root):
            dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
            files += [Path(d, n).relative_to(root).as_posix() for n in names]
    return sorted(files)


def _glob_re(pat):
    """gitignore 式 glob → regex：** 跨目錄（**/ 可為空）、* 與 ? 不跨 /。"""
    out, i = "", 0
    while i < len(pat):
        if pat.startswith("**/", i):
            out, i = out + "(?:.*/)?", i + 3
        elif pat.startswith("**", i):
            out, i = out + ".*", i + 2
        else:
            out += {"*": "[^/]*", "?": "[^/]"}.get(pat[i], re.escape(pat[i]))
            i += 1
    return re.compile(out + r"\Z")


def is_rule_file(env, root: Path, path, globs=None):
    """不含 / 的樣式比對檔名（AGENTS.md 在任何目錄都算），含 / 的比對相對路徑（.cursor/rules/**/*.mdc）。"""
    p = rel_path(root, path) if Path(path).is_absolute() else Path(path).as_posix()
    for pat in globs if globs is not None else env.rule_cfg.globs:
        if _glob_re(pat).match(p if "/" in pat else Path(p).name):
            return True
    return False


# ---------------------------------------------------------------- 範圍解析
def resolve_scope(request, env):
    """Request＋Env → Scope：要掃哪些清單與規則檔、有哪些未完成原因與備註。順序與以前的 main 完全相同：
    先檢查目標目錄、取暫存區、讀變更清單、沒有選任何檔且有 --target 才做全量探索，最後把指定與變更的檔分類。"""
    root, git, kind = request.root, env.git, request.kind
    if request.target is not None and not Path(request.target).is_dir():
        return Scope(kind=kind, failure=ScopeFailure(
            problem=f"--target 不是目錄：{request.target}",
            message=f"⚠️ G1 無法完成檢查：--target 不是目錄（{request.target}）→ incomplete。"))
    changed = []
    if request.staged:
        staged = git.staged()
        if isinstance(staged, GitFailure):
            return Scope(kind=kind, failure=ScopeFailure(
                problem=f"--staged 取不到暫存區變更：{staged.reason}",
                message=f"⚠️ G1 無法完成檢查：--staged 取不到暫存區變更（{staged.reason}）→ incomplete。"))
        changed += staged
    for lst in request.changed_lists:
        try:
            # surrogateescape：清單裡一個非 UTF-8 的路徑不得讓整份清單崩潰（嚴格解碼會丟 UnicodeDecodeError，#283）
            changed += [l.strip() for l in Path(lst).read_text(encoding="utf-8", errors="surrogateescape").splitlines() if l.strip()]
        except OSError as e:
            return Scope(kind=kind, failure=ScopeFailure(
                problem=f"變更檔清單讀不到：{lst}",
                message=f"⚠️ G1 無法完成檢查：--changed-files {lst} 讀不到（{e}）→ incomplete。"))
    manifests, rule_files = list(request.manifests), list(request.rule_files)
    selected = manifests or rule_files or changed or request.staged or request.changed_lists
    if request.target is not None and not selected:
        changed = discover(root, git)       # 只給 --target：全量掃描目標專案
    problems, notes = [], []
    missing = [p for p in dict.fromkeys(manifests + rule_files) if not resolve(root, p).exists()]
    if missing:
        problems.append(f"指定的檔案不存在，未檢查：{', '.join(missing)}")
    gone, unknown = [], []
    for f in dict.fromkeys(changed):
        is_m = classify(f).kind != "other"
        is_r = not is_m and is_rule_file(env, root, f) and not (f.startswith("config/slopsquat/") and not is_external_project(env, root))
        if not (is_m or is_r):
            continue
        if not resolve(root, f).exists():
            if request.base and git.show(request.base, rel_path(root, f if Path(f).is_absolute() else root / f)) is None:
                unknown.append(f)
            else:
                gone.append(f)
            continue
        (manifests if is_m else rule_files).append(f)
    if gone:
        notes.append(f"變更清單中已刪除的檔（略過）：{', '.join(gone)}")
    if unknown:
        problems.append(f"變更清單中的檔案不存在，且不在 base {request.base}：{', '.join(unknown)}")
    return Scope(manifests=tuple(resolve(root, m) for m in dict.fromkeys(manifests) if resolve(root, m).exists()),
                 rule_files=tuple(resolve(root, r) for r in dict.fromkeys(rule_files) if resolve(root, r).exists()),
                 problems=tuple(problems), notes=tuple(notes), kind=kind)


# ---------------------------------------------------------------- 設定完整性、門檻、熱門清單、黑名單與允許清單
def read_vibesec(env):
    return mapping(load_yaml(env.vibesec_file))


def config_problems(env):
    """缺席或壞掉就會讓 G1 變寬鬆的設定（門檻退回內建值、安裝腳本樣式／黑名單／熱門清單變空）：
    回傳未完成原因（incomplete ≠ pass，AGENTS.md 規則 2）。allowlist.yaml 與 blocking-policy 的例外壞掉只會更嚴，不在此列。"""
    out = []
    try:
        import yaml
    except Exception as e:
        return [f"G1 設定無法讀取：缺 PyYAML（{type(e).__name__}），門檻、黑名單與安裝腳本樣式都無法載入"]
    shown = lambda p: Path(p).resolve().relative_to(ROOT).as_posix() if Path(p).resolve().is_relative_to(ROOT) else str(p)
    for p, kinds in ((env.vibesec_file, (dict,)), (env.config_dir / "cooldown.yaml", (dict,)), (env.config_dir / "blacklist.yaml", (dict, list))):
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
        except FileNotFoundError:
            out.append(f"G1 設定 {shown(p)} 缺席")
            continue
        except Exception as e:
            out.append(f"G1 設定 {shown(p)} 無法解析（{type(e).__name__}）")
            continue
        if not isinstance(data, kinds):
            out.append(f"G1 設定 {shown(p)} 格式不符（最上層為 {type(data).__name__}）")
    for name in ("popular-npm.txt", "popular-pypi.txt"):
        p = env.config_dir / name
        try:
            p.read_text(encoding="utf-8")
        except Exception as e:
            out.append(f"G1 設定 {shown(p)} " + ("缺席" if isinstance(e, FileNotFoundError) else f"無法讀取（{type(e).__name__}）"))
    return out


def cfg(env):
    """vibesec.yaml 優先，cooldown.yaml 補細節。"""
    c = mapping(load_yaml(env.config_dir / "cooldown.yaml"))
    th, sim = c.get("thresholds") or {}, c.get("similarity") or {}
    vb = read_vibesec(env)
    g1 = ((vb.get("gates") or {}).get("g1_supply_chain") or {})
    return {
        "cooldown_days": g1.get("cooldown_days", th.get("cooldown_days", 14)),
        "min_weekly_downloads": g1.get("min_weekly_downloads", th.get("min_weekly_downloads", 1000)),
        "similarity": sim.get("difflib_ratio_min", 0.85),
        "levenshtein_max": sim.get("levenshtein_max", 2),
        "min_name_length": sim.get("min_name_length", 4),
    }


def load_popular(env, name):
    p = env.config_dir / name
    if not p.exists():
        return set()
    return {l.strip().lower() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")}


_CONFUSABLE = str.maketrans({"0": "o", "1": "i", "l": "i", "3": "e", "5": "s", "7": "t"})


def _defang(name):
    """同形字折疊 + 去分隔符（cooldown.yaml 的 homoglyph_check / separator_variants）。"""
    return re.sub(r"[-_.]+", "", name.translate(_CONFUSABLE))


def load_list(env, name):
    """讀 blacklist：鍵為 (ecosystem, 名稱小寫)；ecosystem 缺省時記為 None（適用所有生態系）。"""
    data = load_yaml(env.config_dir / name)
    data = data if isinstance(data, (dict, list)) else {}
    items = data.get("packages", []) if isinstance(data, dict) else data
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
    target = canon(eco, pkg)
    for want in (eco, None):
        for (e, n), it in entries.items():
            if e == want and canon(eco, n) == target:
                return it
    return None


# ---------------------------------------------------------------- 四層套件判定
def _eco_label(eco):
    return "npm" if eco == "npm" else "PyPI"


def check_package(env, eco, pkg, ver, c):
    """回傳 (findings, incomplete_reason|None)。查無此套件是正常發現（疑似幻覺／搶註）；查不到、缺資料都是未完成原因，
    不得當成通過（AGENTS.md 規則 2）。"""
    if not valid_name(eco, pkg):
        return [], f"{_eco_label(eco)} 套件名稱不合法，未查詢 registry：{pkg!r}"
    r = env.registry.facts(eco, pkg, ver)
    who = "npm registry" if eco == "npm" else "PyPI"
    if isinstance(r, NotFound):
        return [fnd(env, "vibesec.g1.hallucinated-package", pkg, eco, ver,
                    f"{who} 查無此套件（疑似幻覺/搶註）", "blocking", "registry_health")], None
    if isinstance(r, Unavailable):
        return [], f"{who} 查詢失敗（{pkg}）：{r.reason}"
    return (_judge_npm if eco == "npm" else _judge_pypi)(env, pkg, r.facts, c)


def _judge_npm(env, pkg, f, c):
    findings, gaps = [], []
    age = age_days(f.published_at) if f.version and not isinstance(f.published_at, Unknown) else None
    if age is None:
        gaps.append("冷卻期")
    else:
        found = _cooldown_finding(env, pkg, "npm", f.version, age, c)
        if found:
            findings.append(found)
    if f.install_scripts is None or isinstance(f.install_scripts, Unknown):
        gaps.append("安裝 hook")
    else:
        found = _install_hook_finding(env, pkg, "npm", f.version, f.install_scripts)
        if found:
            findings.append(found)
    dl = f.weekly_downloads
    if not isinstance(dl, int):
        gaps.append(f"週下載量（{dl.why if isinstance(dl, Unknown) else type(dl).__name__}）")
    elif dl < c["min_weekly_downloads"]:
        findings.append(fnd(env, "vibesec.g1.low-download-package", pkg, "npm", f.version,
                            f"週下載量 {dl} < {c['min_weekly_downloads']}，信譽不足，需人工判斷", "advisory"))
    if gaps:
        return findings, f"npm {pkg}@{f.version or '?'}：{'、'.join(gaps)}未檢查（版本不在 registry 發布紀錄、發布時間不明或查詢失敗）"
    return findings, None


def _judge_pypi(env, pkg, f, c):
    age = age_days(f.published_at) if not isinstance(f.published_at, Unknown) else None
    if age is None:
        return [], f"PyPI {pkg}@{f.version or '?'}：冷卻期未檢查（版本不在 PyPI 發布紀錄或發布時間不明）"
    found = _cooldown_finding(env, pkg, "pypi", f.version, age, c)
    return ([found] if found else []), None


def _check_job(env, eco, name, ver, c):
    """並行查詢的一筆。任何意外的錯誤都轉成這一筆的未完成原因，不讓整批查詢中斷（AGENTS.md 規則 2）。"""
    try:
        return check_package(env, eco, name, ver, c)
    except Exception as e:
        return [], f"{_eco_label(eco)} {name}@{ver or '?'}：檢查時發生未預期的錯誤（{type(e).__name__}：{e}）"


def requirements_indirect(env, path, requires=None):
    """requirements*.txt 中由同檔其他套件宣告為相依的 (名稱小寫, 版本)，即間接相依，不做名稱相似度。"""
    requires = requires or env.registry.requires
    pins = []
    for line in Path(path).read_text(errors="ignore").splitlines():
        x = pep508(line.split(" #", 1)[0])
        if x and x[1]:
            pins.append(x)
    if len(pins) < 2:
        return set()
    with ThreadPoolExecutor(max_workers=env.workers) as ex:
        deps = list(ex.map(lambda p: requires(*p), pins))
    required_by = {}
    for (name, _), ds in zip(pins, deps):
        for d in ds - {canon("pypi", name)}:
            required_by.setdefault(d, set()).add(canon("pypi", name))
    return {(n.lower(), v) for n, v in pins if required_by.get(canon("pypi", n))}


def _cooldown_finding(env, pkg, eco, ver, age, c):
    """發布天數未滿冷卻期 → blocking；天數未知（None）不判定。"""
    if age is None or age >= c["cooldown_days"]:
        return None
    return fnd(env, "vibesec.g1.cooldown-violation", pkg, eco, ver,
               f"版本發布僅 {age} 天，未滿冷卻期 {c['cooldown_days']} 天", "blocking")


def _install_hooks_cfg(env):
    return mapping(load_yaml(env.config_dir / "cooldown.yaml")).get("install_hooks") or {}


_HOOK_CONDS = {
    "any_network_and_exec": lambda h: h["network"] and h["exec"],
    "any_network_and_env_read": lambda h: h["network"] and h["env_read"],
    "credential_path_access": lambda h: h["credential_paths"],
    "ai_cli_abuse": lambda h: h["ai_cli_abuse"],
    "exec_only": lambda h: h["exec"] or h["network"],
}
_HOOK_DECISION_DEFAULT = {
    "any_network_and_exec": "block", "any_network_and_env_read": "block",
    "credential_path_access": "block", "ai_cli_abuse": "block", "exec_only": "advisory",
}
_DECISION_TIER = {"block": "blocking", "blocking": "blocking", "advisory": "advisory"}
_NPM_HOOK_DEFAULT = ["preinstall", "install", "postinstall", "prepare"]


def _install_hook_finding(env, pkg, eco, ver, scripts):
    """依 cooldown.yaml install_hooks 分類安裝階段 hook（docs/02 第 3 層）。"""
    ih = _install_hooks_cfg(env)
    pats = ih.get("suspicious_patterns") or {}
    hook_names = ih.get("npm_scripts") or _NPM_HOOK_DEFAULT
    dec = ih.get("decision") or {}
    hooks = {h: str(scripts[h]) for h in hook_names if h in scripts}
    if not hooks:
        return None
    body = "\n".join(hooks.values())
    hit = {k: any(re.search(rx, body) for rx in pats.get(k) or []) for k in
           ("network", "env_read", "credential_paths", "ai_cli_abuse", "exec")}
    names = ", ".join(hooks)
    tiers = {_DECISION_TIER.get(str(dec.get(k, _HOOK_DECISION_DEFAULT[k])).lower())
             for k, cond in _HOOK_CONDS.items() if cond(hit)}
    tiers.discard(None)
    if not tiers:
        return None
    why = [k for k in ("network", "env_read", "credential_paths", "ai_cli_abuse", "exec") if hit[k]]
    if "blocking" in tiers:
        return fnd(env, "vibesec.g1.postinstall-egress", pkg, eco, ver,
                   f"安裝階段 hook（{names}）命中可疑樣式：{', '.join(why)}", "blocking")
    return fnd(env, "vibesec.g1.postinstall-egress", pkg, eco, ver,
               f"安裝階段 hook（{names}）含動態執行或外連，需人工審查", "advisory")


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


def similarity_check(env, pkg, eco, popular, blacklist, c, fuzzy=True):
    """blacklist → 與熱門清單的名稱相似度（fuzzy=False 為鎖定檔中的間接相依，只查黑名單）。"""
    it = lookup(blacklist, eco, pkg)
    if it:
        hint = f"；正確名稱應為 {it['looks_like']}" if it.get("looks_like") else ""
        tier = "advisory" if it.get("action") == "warn" else "blocking"
        return fnd(env, "vibesec.g1.hallucinated-package", pkg, eco, None,
                   f"命中黑名單（{it.get('status', '?')}）：{it.get('reason', 'known typosquat')}{hint}", tier, "blacklist")
    if not fuzzy:
        return None
    pl = canon(eco, pkg)
    canon_popular = {canon(eco, g): g for g in popular}
    if pl in canon_popular:
        return None
    pl_defang = _defang(pl)
    for cg, good in canon_popular.items():
        if pl != cg and pl_defang == _defang(cg):
            return fnd(env, "vibesec.g1.hallucinated-package", pkg, eco, None,
                       f"名稱與熱門套件 '{good}' 僅差同形字或分隔符，疑似 typosquat", "blocking", "similarity")
    for cg, good in canon_popular.items():
        ratio = difflib.SequenceMatcher(None, pl, cg).ratio()
        dist = _edit_distance(pl, cg)
        if ratio >= c["similarity"] or (len(pl) >= c.get("min_name_length", 4)
                                        and 0 < dist <= (1 if len(pl) <= 5 else c.get("levenshtein_max", 2))):
            return fnd(env, "vibesec.g1.hallucinated-package", pkg, eco, None,
                       f"名稱與熱門套件 '{good}' 高度相似（ratio={ratio:.2f}, edit={dist}），疑似 typosquat", "blocking",
                       "similarity")
    return None


CHECK_OF_RULE = {"vibesec.g1.cooldown-violation": "cooldown", "vibesec.g1.low-download-package": "low_download",
                 "vibesec.g1.postinstall-egress": "install_hook"}


def fnd(env, rule, pkg, eco, ver, reason, tier, check=None):
    return {"rule_id": rule, "package": pkg, "ecosystem": eco, "version": ver,
            "reason": reason, "policy_tier": env.policy.cap(rule, tier), "check": check or CHECK_OF_RULE.get(rule)}


def self_install_hooks(env, path):
    """專案自己的 package.json scripts（preinstall／postinstall…）也要查外連與讀憑證。"""
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
    return _install_hook_finding(env, f"{j.get('name') or p.name}（本專案 scripts）", "npm", str(j.get("version") or ""), scripts)


def apply_exceptions(finding, project):
    """命中 rule_id 與 path_glob 的例外（project：Policy.for_project 的結果）時把 blocking 降為 advisory，發現保留。"""
    c = project.classify(finding["rule_id"], finding.get("manifest") or "", requested=finding["policy_tier"])
    finding["policy_tier"] = c["policy_tier"]
    if c["exception"]:
        finding["exception"] = c["exception"]
    return finding


BYPASSABLE = ("registry_health", "low_download", "cooldown", "blacklist", "similarity")
_VCMP = re.compile(r"^(>=|<=|==|=|>|<)?v?(\d+(?:\.\d+)*)$")


def _ver_tuple(v):
    """版本的比較元組；只接受純數字段（1.2.3）。有預發布／後綴（1.2.3-beta、1.2.3.post1）→ None：範圍比對時不放行。"""
    m = re.fullmatch(r"v?(\d+(?:\.\d+)*)", str(v))
    if not m:
        return None
    t = [int(x) for x in m.group(1).split(".")]
    return tuple(t + [0] * (4 - len(t)))


def parse_version_spec(spec):
    """allowlist 的 version → None（所有版本）、("exact", "1.2.3") 或 ("range", [(運算子, 比較元組)...])。"""
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
    return ("range", [(op, _ver_tuple(v)) for op, v in cmps])


def version_matches(spec, ver):
    """parse_version_spec 的結果是否涵蓋 ver；版本未知或無法比較 → False（不放行）。"""
    if spec is None:
        return True
    if not ver:
        return False
    if spec[0] == "exact":
        return str(ver).lstrip("v") == spec[1]
    vt = _ver_tuple(ver)
    if vt is None:
        return False
    ops = {">=": vt.__ge__, "<=": vt.__le__, ">": vt.__gt__, "<": vt.__lt__, "==": vt.__eq__, "=": vt.__eq__}
    return all(ops[op](v) for op, v in spec[1])


def load_allowlist(env, path=None):
    """讀 allowlist.yaml 的 entries（舊格式 packages 也接受），只保留合規且未過期的條目（fail closed）。"""
    today = env.today
    data = load_yaml(path or env.config_dir / "allowlist.yaml") or {}
    items = data.get("entries", data.get("packages")) if isinstance(data, dict) else data
    valid, ignored = [], []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        name = it.get("package") or it.get("name") or "?"
        missing = [k for k in ("package", "approved_by", "expires", "reason", "bypass") if not it.get(k)]
        if missing:
            ignored.append(f"{name}：缺少欄位 {', '.join(missing)}")
            continue
        bypass = it["bypass"] if isinstance(it["bypass"], list) else [it["bypass"]]
        bad = [b for b in bypass if b not in BYPASSABLE]
        if bad:
            ignored.append(f"{name}：bypass 不可為 {', '.join(map(str, bad))}（只能放行 {', '.join(BYPASSABLE)}）")
            continue
        try:
            exp = it["expires"] if isinstance(it["expires"], date) else date.fromisoformat(str(it["expires"]))
        except ValueError:
            ignored.append(f"{name}：expires 格式無效（{it['expires']}）")
            continue
        if exp < today:
            ignored.append(f"{name}：已於 {exp} 過期")
            continue
        try:
            spec = parse_version_spec(it.get("version"))
        except ValueError as e:
            ignored.append(f"{name}：{e}")
            continue
        valid.append({"package": str(it["package"]), "ecosystem": it.get("ecosystem") or None, "spec": spec,
                      "bypass": set(bypass), "approved_by": it["approved_by"], "expires": str(exp),
                      "ticket": it.get("ticket"), "reason": it["reason"]})
    return valid, ignored


def apply_allowlist(finding, entries, ver=None):
    """發現的 check 在某條目的 bypass 內、套件與生態系相符、版本在範圍內 → blocking 降為 advisory，發現保留。"""
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


# ---------------------------------------------------------------- 規則檔散文掃描與 diff-aware 新增套件
VALUE_FLAGS = {
    "npm": {"--prefix", "--registry", "--tag", "-w", "--workspace", "--cache", "--userconfig", "--omit", "--include",
            "--install-strategy", "--before", "--otp", "--loglevel", "--filter", "-F", "--dir", "-C", "--cwd"},
    "pypi": {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url", "--extra-index-url",
             "-f", "--find-links", "-t", "--target", "--prefix", "--root", "--src", "--trusted-host", "--python", "-p",
             "--platform", "--python-version", "--implementation", "--abi", "--only-binary", "--no-binary",
             "--upgrade-strategy", "-C", "--config-settings", "--global-option", "--proxy", "--retries", "--timeout",
             "--exists-action", "--cert", "--client-cert", "--cache-dir", "--log", "--report", "--progress-bar",
             "--root-user-action", "--keyring-provider", "--group", "--suffix", "--pip-args", "--preinstall",
             "-G", "--extra", "--index"},
}
INSTALL_RE = {
    "npm": re.compile(r'\b(?:npm|pnpm|yarn|bun)\s+(?:install|add|i)\s+((?:-{1,2}[A-Za-z-]+\s+)*)([@A-Za-z0-9][@A-Za-z0-9._/-]*)'),
    "pypi": re.compile(r'\b(?:(?:pip3?|pipx|uv\s+pip|python3?\s+-m\s+pip)\s+install|(?:uv|poetry|pdm|rye)\s+add)\s+'
                       r'((?:-{1,2}[A-Za-z-]+\s+)*)([A-Za-z0-9][A-Za-z0-9._-]*)'),
}
NAME_RE = {"npm": re.compile(r'^[@A-Za-z0-9][@A-Za-z0-9._/-]*$'), "pypi": re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*$')}


def _install_token_name(eco, tok):
    if not tok or tok.startswith(("-", ".", "/")):
        return None
    if eco == "npm":
        if tok.count("@") > (1 if tok.startswith("@") else 0):
            tok = tok.rsplit("@", 1)[0]
    else:
        tok = re.split(r'[=<>!~\[]', tok, maxsplit=1)[0]
    return tok if NAME_RE[eco].match(tok) else None


def _install_names(eco, flags, tokens):
    if flags and flags[-1] in VALUE_FLAGS[eco]:
        return []
    out = []
    for tok in tokens:
        if tok.startswith("-") or tok in ("&&", "||", ";", "|", ">", "<", "\\"):
            break
        name = _install_token_name(eco, tok.rstrip(".,;:)`'\""))
        if not name:
            break
        out.append(name)
        if tok.endswith("`"):
            break
    return out


def rule_file_mentions(env, path):
    """agent 規則檔／markdown 中 `npm install X`、`pip install X`、`uv add X` 等提及的套件。"""
    try:
        text = Path(path).read_text(errors="ignore")
    except OSError:
        return []
    out = []
    for eco, rx in INSTALL_RE.items():
        for m in rx.finditer(text):
            line_end = text.find("\n", m.end())
            rest = text[m.end():line_end if line_end >= 0 else len(text)]
            out += [(eco, n, None) for n in _install_names(eco, m.group(1).split(), [m.group(2)] + rest.split())]
    rx = env.rule_cfg.install_command
    groups = [(g, eco) for g, eco in (("pypi", "pypi"), ("npm", "npm")) if rx is not None and g in rx.groupindex] \
        or [(i, eco) for i, eco in ((1, "pypi"), (2, "npm")) if rx is not None and rx.groups >= i]
    for m in (rx.finditer(text) if rx is not None else ()):
        for g, eco in groups:
            if m.group(g):
                toks = m.group(g).split("`", 1)[0].split()
                flags = list(itertools.takewhile(lambda t: t.startswith("-"), toks))
                out += [(eco, n, None) for n in _install_names(eco, flags, toks[len(flags):])]
    return list(dict.fromkeys(out))


def _entries(root, path):
    return [(d.eco, d.name, d.version) for d in parse_manifest([path], root=root).entries]


def added_packages(root, path, base, git):
    """diff-aware：只回傳相對 base 新增或改版的 (eco, name, version)。base 為 None 時回傳全部。"""
    head = _entries(root, path)
    if not base or not head:
        return head
    old_text = git.show(base, rel_path(root, path))
    if old_text is None:
        return head
    with tempfile.TemporaryDirectory() as d:
        old = Path(d) / Path(path).name
        old.write_text(old_text, encoding="utf-8", errors="surrogateescape")
        before = {(e, n.lower(), v) for e, n, v in _entries(root, old)}
    return [(e, n, v) for e, n, v in head if (e, n.lower(), v) not in before]


# ---------------------------------------------------------------- 輸出邊界與控制覆蓋／判定
def _escape_surrogate(ch):
    o = ord(ch)
    if 0xDC80 <= o <= 0xDCFF:
        return f"\\x{o - 0xDC00:02x}"
    if 0xD800 <= o <= 0xDFFF:
        return f"\\u{o:04x}"
    return ch


def printable(obj):
    """輸出邊界：把物件裡含代理字元（surrogateescape 保留的原始位元組）的字串轉成可輸出的文字，合法 UTF-8 原樣不動。"""
    if isinstance(obj, str):
        try:
            obj.encode("utf-8")
            return obj
        except UnicodeEncodeError:
            return "".join(map(_escape_surrogate, obj))
    if isinstance(obj, dict):
        return {printable(k): printable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [printable(v) for v in obj]
    return obj


def sarif_uri(path):
    """SARIF 的 artifactLocation.uri：合法 UTF-8 原樣不動，含非 UTF-8 位元組的路徑改用百分比編碼。"""
    try:
        path.encode("utf-8")
        return path
    except UnicodeEncodeError:
        pass
    try:
        return urllib.parse.quote(path.encode("utf-8", "surrogateescape"), safe="/")
    except UnicodeEncodeError:
        return printable(path)


def dumps_json(obj) -> str:
    """所有 JSON 輸出（SARIF、閘門結果、標準輸出）共用：先轉義代理字元，再序列化。"""
    return json.dumps(printable(obj), ensure_ascii=False, indent=2)


NO_MANIFEST_REASON = "受驗樹沒有任何已知的相依清單"
UNSUPPORTED_PREFIX = "生態系尚未支援，其中的套件未檢查："


def gate_coverage(findings, incomplete, pypi_checked=0, not_applicable=None):
    """G1 快篩三個控制的 coverage（VS-G1-SBOM 與 ASVS5-V15.2 由後續步驟併入）。
    not_applicable：理由字串時三個控制都記 not_applicable（full 掃描時受驗樹沒有任何已知清單，#316）。"""
    coverage = []
    for ctl in CONTROLS:
        hit = [f for f in findings if _CONTROL_OF.get(f["rule_id"]) == ctl and f["policy_tier"] == "blocking"]
        if not_applicable and not incomplete:
            state, why = "not_applicable", not_applicable
        elif incomplete:
            state, why = "untested", None
        elif hit:
            state, why = "fail", None
        elif ctl == "VS-G1-INSTALL-HOOK" and pypi_checked:
            state, why = "untested", f"{pypi_checked} 個 PyPI 套件的安裝腳本尚無檢查（只檢查 npm scripts）"
        else:
            state, why = "pass", None
        coverage.append({"control_id": ctl, "state": state, "reason": why})
    return coverage


def gate_status(findings, incomplete, coverage, notes=()):
    """整體狀態與 status_reason：交給全 repo 唯一的 gate_verdict.verdict。"""
    return verdict(blocking=sum(f["policy_tier"] == "blocking" for f in findings), coverage=coverage,
                   problems=list(dict.fromkeys(incomplete)), notes=list(notes))


# ---------------------------------------------------------------- Outcome 與四個純函式檢視
def _build_sarif_doc(findings) -> dict:
    rules, results = {}, []
    for f in findings:
        rules.setdefault(f["rule_id"], {"id": f["rule_id"], "name": f["rule_id"],
                                        "shortDescription": {"text": f["rule_id"]},
                                        "properties": {"policy_tier": f["policy_tier"]}})
        results.append({
            "ruleId": f["rule_id"],
            "level": LEVEL.get(f["policy_tier"], "warning"),
            "message": {"text": f"[{f['ecosystem']}] {f['package']}@{f['version'] or '?'} — {f['reason']}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": sarif_uri(f.get("manifest") or "unknown")}}}],
            "partialFingerprints": {"vibesecPackage": f"{f['rule_id']}|{f['ecosystem']}|{f['package'].lower()}|{f.get('manifest')}"},
            "properties": {k: f.get(k) for k in ("package", "ecosystem", "version", "policy_tier", "manifest")}
                          | ({"exception": f["exception"]} if f.get("exception") else {})
                          | ({"allowlist": f["allowlist"]} if f.get("allowlist") else {}),
        })
    return printable(gate_result.sarif({"name": TOOL_NAME, "version": TOOL_VERSION}, list(rules.values()), results))


def _populate_gate_run(outcome: "Outcome", *, mode, risk_tier, base, started, commit, output_ref) -> dict:
    run = gate_result.GateRun("G1", controls=CONTROLS, deferred=REQUIRED_CONTROLS["G1"], mode=mode,
                              scope=outcome.scope, commit=commit, diff_base=base, risk_tier=risk_tier,
                              started_at=started)
    run.tool(TOOL_NAME, "ran", version=TOOL_VERSION, output_ref=output_ref)
    for c in outcome.coverage:
        run.cover(c["control_id"], c["state"], c["reason"])
    run.count(blocking=sum(f["policy_tier"] == "blocking" for f in outcome.findings),
              advisory=sum(f["policy_tier"] == "advisory" for f in outcome.findings))
    for p in outcome.problems:
        run.problem(p)
    for n in outcome.notes:
        run.note(n)
    return printable(run.result())


@dataclass(frozen=True)
class _UnreadableView:
    base: str | None
    risk_tier: object
    message: str

    def to_stdout(self, outcome: "Outcome") -> dict | None:
        return None

    def to_sarif(self, outcome: "Outcome") -> dict | None:
        return None

    def to_gate_run(self, outcome: "Outcome", started, commit, sarif_ref) -> dict:
        run = gate_result.GateRun("G1", controls=CONTROLS, deferred=REQUIRED_CONTROLS["G1"], mode=None,
                                  scope=outcome.scope, commit=commit, diff_base=self.base, risk_tier=self.risk_tier,
                                  started_at=started)
        return printable(run.unreadable(outcome.problems[0], tool_name=TOOL_NAME, version=TOOL_VERSION))

    def result_line(self, outcome: "Outcome") -> str:
        return self.message


@dataclass(frozen=True)
class _ScopeFailureView:
    mode: str
    risk_tier: object
    base: str | None
    message: str

    def to_stdout(self, outcome: "Outcome") -> dict | None:
        return None

    def to_sarif(self, outcome: "Outcome") -> dict | None:
        return None

    def to_gate_run(self, outcome: "Outcome", started, commit, sarif_ref) -> dict:
        return _populate_gate_run(outcome, mode=self.mode, risk_tier=self.risk_tier, base=self.base,
                                  started=started, commit=commit, output_ref=None)

    def result_line(self, outcome: "Outcome") -> str:
        return self.message


@dataclass(frozen=True)
class _EmptyScopeView:
    mode: str
    risk_tier: object
    base: str | None
    external_project_path: str | None

    def to_stdout(self, outcome: "Outcome") -> dict | None:
        out = {"gate": "G1", "findings": []}
        if self.external_project_path is not None:
            out["target"] = self.external_project_path
        if outcome.problems:
            out["status"], out["status_reason"] = "incomplete", "；".join(outcome.problems)
        return printable(out)

    def to_sarif(self, outcome: "Outcome") -> dict | None:
        return _build_sarif_doc(())

    def to_gate_run(self, outcome: "Outcome", started, commit, sarif_ref) -> dict:
        return _populate_gate_run(outcome, mode=self.mode, risk_tier=self.risk_tier, base=self.base,
                                  started=started, commit=commit, output_ref=sarif_ref)

    def result_line(self, outcome: "Outcome") -> str:
        if outcome.problems:
            return f"⚠️ G1 無法完成檢查：{'；'.join(outcome.problems)} → incomplete。"
        return "G1 slopcheck：無相依清單或規則檔變更，略過。"


@dataclass(frozen=True)
class _ScannedView:
    mode: str = "shadow"
    risk_tier: object = "L2"
    base: str | None = None
    external_project_path: str | None = None
    ignored_exceptions: tuple = ()
    ignored_allowlist: tuple = ()
    stdout_reason: str | None = None

    def to_stdout(self, outcome: "Outcome") -> dict | None:
        out = {"gate": "G1", "findings": list(outcome.findings)}
        if self.external_project_path is not None:
            out["target"] = self.external_project_path
            out["notes"] = list(outcome.notes)
        if self.ignored_exceptions:
            out["ignored_exceptions"] = list(self.ignored_exceptions)
        if self.ignored_allowlist:
            out["ignored_allowlist"] = list(self.ignored_allowlist)
        if outcome.status != "pass":
            out["status"] = outcome.status
            out["status_reason"] = self.stdout_reason
        if outcome.status == "incomplete" or outcome.problems:
            out["incomplete_checks"] = list(outcome.problems)
            out["untested_controls"] = [c["control_id"] for c in outcome.coverage if c["state"] == "untested"]
        return printable(out)

    def to_sarif(self, outcome: "Outcome") -> dict | None:
        return _build_sarif_doc(outcome.findings)

    def to_gate_run(self, outcome: "Outcome", started, commit, sarif_ref) -> dict:
        return _populate_gate_run(outcome, mode=self.mode, risk_tier=self.risk_tier, base=self.base,
                                  started=started, commit=commit, output_ref=sarif_ref)

    def result_line(self, outcome: "Outcome") -> str:
        blocking_n = sum(f["policy_tier"] == "blocking" for f in outcome.findings)
        if blocking_n:
            return f"\n⛔ G1 阻擋：{blocking_n} 筆 blocking 供應鏈發現。"
        if outcome.problems:
            return "\n⚠️ G1 無法完成檢查（網路/registry 失敗或鎖定檔未解析）→ incomplete，絕不視為通過。"
        if outcome.status == "incomplete":
            return f"\n⚠️ G1 有控制未實測 → incomplete，絕不視為通過：{self.stdout_reason}"
        return "\n✅ G1 快篩通過。"


@dataclass(frozen=True)
class Outcome:
    """快篩單次執行的不可變純值結果，以及四個純函式檢視（to_stdout、to_sarif、to_gate_run、result_line）。
    退出碼只在這裡由閘門狀態唯一推導（EXIT_CODE_OF），不另立報告模組。"""
    findings: tuple = ()
    problems: tuple = ()
    notes: tuple = ()
    coverage: tuple = ()
    status: str = "pass"
    status_reason: str | None = None
    scope: str = "full"
    exit_code: int = 0
    _view: object = _ScannedView()

    @classmethod
    def unreadable(cls, problem: str, request: Request, *, config_root: Path = ROOT) -> "Outcome":
        """政策讀不到：不分類任何發現、不查登錄庫，沿用 GateRun.unreadable 的未完成閘門結果。"""
        vb = mapping(load_yaml(Path(config_root) / "vibesec.yaml"))
        cov = tuple({"control_id": ctl, "state": "untested", "reason": problem} for ctl in CONTROLS)
        return cls(
            findings=(), problems=(problem,), notes=(), coverage=cov,
            status="incomplete", status_reason=problem, scope=request.kind,
            exit_code=EXIT_CODE_OF["incomplete"],
            _view=_UnreadableView(
                base=request.base,
                risk_tier=vb.get("risk_tier", "L2"),
                message=f"⚠️ G1 無法完成檢查：{problem} → incomplete。",
            ),
        )

    def to_stdout(self) -> dict | None:
        """標準輸出的 JSON 物件（兩種形狀：無變更／有掃描）；政策讀不到或範圍失敗時無標準輸出（None）。"""
        return self._view.to_stdout(self)

    def to_sarif(self) -> dict | None:
        """SARIF 2.1.0 物件；政策讀不到或範圍失敗時回傳 None（由命令列入口刪除舊 SARIF）。"""
        return self._view.to_sarif(self)

    def to_gate_run(self, started=None, commit=None, *, sarif_ref=None) -> dict:
        """產出閘門執行結果 dict（含政策讀不到的 unreadable 路徑；無 SARIF 檢視時 output_ref 為 None）。"""
        return self._view.to_gate_run(self, started, commit, sarif_ref)

    def result_line(self) -> str:
        """標準錯誤的單次結果行（字串與前導換行逐字維持既有契約）。"""
        return self._view.result_line(self)


# ---------------------------------------------------------------- 快篩主流程
def screen(request: Request, env: Env) -> Outcome:
    """純計算快篩主流程：Request＋Env → Outcome，不寫檔、不印輸出、預期失敗不丟例外。"""
    root, base, scope = request.root, request.base, request.kind
    risk_tier = read_vibesec(env).get("risk_tier", "L2")
    scoped = resolve_scope(request, env)
    if scoped.failure:
        problems = (scoped.failure.problem,)
        cov = tuple(gate_coverage((), problems, 0))
        status, status_reason = gate_status((), problems, cov)
        return Outcome(
            findings=(), problems=problems, notes=(), coverage=cov,
            status=status, status_reason=status_reason, scope=scope, exit_code=EXIT_CODE_OF[status],
            _view=_ScopeFailureView(mode=env.policy.mode, risk_tier=risk_tier, base=base, message=scoped.failure.message),
        )

    pre_incomplete, notes = list(scoped.problems), list(scoped.notes)
    manifests, rule_files = list(scoped.manifests), list(scoped.rule_files)
    # 不支援的生態系清單（#316）：其中的套件沒有被檢查 → 未完成原因（不是 pass），不交給 npm／PyPI 的解析器
    kinds = {m: classify(m) for m in manifests}
    unsupported = sorted((m for m in manifests if kinds[m].kind == "unsupported"), key=lambda m: rel_path(root, m))
    if unsupported:
        manifests = [m for m in manifests if m not in unsupported]
        pre_incomplete.append(UNSUPPORTED_PREFIX + "、".join(f"{kinds[m].ecosystem}（{rel_path(root, m)}）" for m in unsupported))
    project = env.policy.for_project(root)
    if project.note:
        notes.append(project.note)
    ext_path = str(root) if is_external_project(env, root) else None

    # 只有不支援的清單時照常走完整掃描的檢視：輸出形狀與結果行比照 #269 的無解析器清單（ADR 0003 對外契約）
    if not manifests and not rule_files and not unsupported:
        problems = tuple(dict.fromkeys(pre_incomplete))
        # full 掃描、受驗樹什麼清單都沒有 → not_applicable（#316）；diff 模式沒改到清單 → 維持 pass（這次變更沒有引入新的相依）
        cov = tuple(gate_coverage((), problems, 0, not_applicable=NO_MANIFEST_REASON if scope == "full" else None))
        status, status_reason = gate_status((), problems, cov, notes)
        return Outcome(
            findings=(), problems=problems, notes=tuple(notes), coverage=cov,
            status=status, status_reason=status_reason, scope=scope, exit_code=EXIT_CODE_OF[status],
            _view=_EmptyScopeView(mode=env.policy.mode, risk_tier=risk_tier, base=base, external_project_path=ext_path),
        )

    c = cfg(env)
    popular = {"npm": load_popular(env, "popular-npm.txt"), "pypi": load_popular(env, "popular-pypi.txt")}
    blacklist = load_list(env, "blacklist.yaml")
    allowlist, ignored_allowlist = load_allowlist(env)
    if ignored_allowlist:
        notes.append("忽略的 allowlist 條目：" + "；".join(ignored_allowlist))

    targets = [(m, added_packages(root, m, base, env.git), False) for m in manifests]
    targets += [(r, rule_file_mentions(env, r), True) for r in rule_files]

    findings, incomplete = [], list(pre_incomplete) + config_problems(env)
    parsed = {m: parse_manifest([m], root=root) for m in manifests}
    unparsed = [rel_path(root, u) for m in manifests for u in parsed[m].unparsed]
    if unparsed:
        incomplete.append(f"鎖定檔尚無解析器，其中的套件未逐一檢查：{', '.join(unparsed)}")
    indirect = {}
    for m in manifests:
        bad = parsed[m].bad
        if bad:
            incomplete.append(f"{rel_path(root, m)}：{len(bad)} 筆無法解析或不是 registry 來源，未檢查"
                              f"（{', '.join(bad[:5])}{' …' if len(bad) > 5 else ''}）")
        if Path(m).name in ("package-lock.json", "npm-shrinkwrap.json"):
            indirect[m] = {(d.name.lower(), d.version) for d in parsed[m].entries if d.direct is False}
        elif REQUIREMENTS_RE.search(Path(m).as_posix()):
            indirect[m] = requirements_indirect(env, m)

    jobs = list(dict.fromkeys((e, n, v) for _, pk, _ in targets for e, n, v in pk))
    with ThreadPoolExecutor(max_workers=env.workers) as ex:
        checked = dict(zip(jobs, ex.map(lambda j: _check_job(env, j[0], j[1], j[2], c), jobs)))

    for source, packages, from_rules in targets:
        source_rel = rel_path(root, source)
        for eco, name, ver in packages:
            found = []
            fuzzy = (name.lower(), ver) not in indirect.get(source, ())
            sim = similarity_check(env, name, eco, popular.get(eco, set()), blacklist, c, fuzzy)
            if sim:
                found.append(sim)
            fs, reason = checked[(eco, name, ver)]
            fs = [dict(f) for f in fs]
            if from_rules:
                for f in fs:
                    if f["rule_id"] == "vibesec.g1.hallucinated-package":
                        f["rule_id"] = "vibesec.g1.rules-file-unknown-package"
                        f["policy_tier"] = env.policy.cap(f["rule_id"], f["policy_tier"])
            found.extend(fs)
            if reason:
                incomplete.append(reason)
            for f in found:
                f["manifest"] = source_rel
                findings.append(apply_exceptions(apply_allowlist(f, allowlist, ver), project))

    for m in manifests:
        f = self_install_hooks(env, m)
        if f:
            f["manifest"] = rel_path(root, m)
            findings.append(apply_exceptions(f, project))
    pypi_checked = sum(1 for e, _, _ in jobs if e == "pypi")
    notes += project.report(findings, "G1")

    problems = tuple(dict.fromkeys(incomplete))
    # full 掃描、三種清單都沒有命中、規則檔也沒提到任何套件（實際檢查 0 個套件）→ not_applicable（#316；規則檔樣式含 **/*.md）
    na = NO_MANIFEST_REASON if scope == "full" and not manifests and not unsupported and not jobs else None
    cov = tuple(gate_coverage(findings, problems, pypi_checked, not_applicable=na))
    status, stdout_reason = gate_status(findings, problems, cov)
    _, gate_reason = gate_status(findings, problems, cov, notes)
    return Outcome(
        findings=tuple(findings), problems=problems, notes=tuple(notes), coverage=cov,
        status=status, status_reason=gate_reason, scope=scope, exit_code=EXIT_CODE_OF[status],
        _view=_ScannedView(
            mode=env.policy.mode, risk_tier=risk_tier, base=base, external_project_path=ext_path,
            ignored_exceptions=tuple(project.ignored), ignored_allowlist=tuple(ignored_allowlist),
            stdout_reason=stdout_reason,
        ),
    )
