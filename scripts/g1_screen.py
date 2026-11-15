#!/usr/bin/env python3
"""快篩的範圍解析（#266 的前半，#260 的 S5）：Request、Env 與 resolve_scope。

快篩從呼叫方看只需要兩樣東西：一個範圍（Request：命令列參數解析後的純值）與一組注入的外部依賴（Env：Git、套件登錄庫、
已載入的 Policy、設定根目錄、今天日期、並行數）。這個模組沒有任何模組層的可變狀態：以前靠覆寫全域變數（TARGET、GIT、REGISTRY、
_POLICY、CFG_DIR…）注入的東西，現在都經過 Env 進來。

resolve_scope(request, env) -> Scope 只決定「要掃哪些檔」：暫存區、變更清單、全量探索、指定的清單與規則檔、分類成清單或規則檔、
變更清單裡的檔在 base 查不到。它不查套件登錄庫、不寫任何輸出；預期的失敗（--staged 取不到、變更清單讀不到、指定的檔不存在）
一律以未完成原因表達，不丟例外、不當成通過（AGENTS.md 規則 2）。

政策與執行模式仍只經 vibesec_policy.load_policy 取得，由呼叫端載入後放進 Env（ADR 0001、0002 不動）。
"""
from __future__ import annotations
import os
import re
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

ROOT = Path(__file__).resolve().parent.parent      # VibeSec 本身：設定、清單、政策
sys.path.insert(0, str(Path(__file__).resolve().parent))
from g1_git import GitFailure  # noqa: E402
from g1_manifests import classify  # noqa: E402
from g1_registry import HttpRegistry  # noqa: E402

if TYPE_CHECKING:       # 只給型別標註：快篩不在匯入時就要求 PyYAML（政策在 default_env 才載入）
    from vibesec_policy import Policy

WORKERS = 8                                        # registry 並行查詢數的預設值
RULE_FILE_DEFAULTS = (".cursorrules", "AGENTS.md", "SKILL.md", "CLAUDE.md", ".cursor/rules/**/*.mdc", "**/*.md")
# 全量掃描（--target、非 git 目錄）時略過的目錄：安裝產物與快取，不是專案宣告的相依
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", "dist", "build"}


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
    policy: "Policy"                # 已載入的 vibesec_policy.Policy（讀不到政策由呼叫端以未完成處理，不會有 Env）
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
    """policy 與 git 一定要給：政策不從全域取得（讀不到政策是呼叫端的未完成路徑），git 的工作目錄是被掃描的專案。
    registry 缺省用生產的 HttpRegistry。"""
    return Env(policy=policy, git=git, registry=registry if registry is not None else HttpRegistry(),
               config_root=Path(config_root), today=today or date.today(), workers=workers,
               rule_cfg=rule_cfg if rule_cfg is not None else _rule_cfg_of(Path(config_root)))


@dataclass(frozen=True)
class ScopeFailure:
    """範圍本身就無法決定（--staged 取不到暫存區、變更清單讀不到）：不知道改了什麼 ≠ 沒有變更。
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


def external_target(env, root: Path) -> bool:
    """目標不是本 repo：判斷交給 Policy.is_this_repo（與例外是否套用同一份條件；CI 以 VIBESEC_PROJECT_ROOT 指出受驗樹）。"""
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
            out += {"*": "[^/]*", "?": "[^/]"}.get(pat[i], re.escape(pat[i])); i += 1
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
    先取暫存區、再讀變更清單、沒有選任何檔且有 --target 才做全量探索，最後把指定與變更的檔分類。"""
    root, git, kind = request.root, env.git, request.kind
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
            # 清單讀不到 = 不知道改了什麼；以前靜默當成「沒有變更」而 pass（第四次審視 S-8）
            return Scope(kind=kind, failure=ScopeFailure(
                problem=f"變更檔清單讀不到：{lst}",
                message=f"⚠️ G1 無法完成檢查：--changed-files {lst} 讀不到（{e}）→ incomplete。"))
    manifests, rule_files = list(request.manifests), list(request.rule_files)
    selected = manifests or rule_files or changed or request.staged or request.changed_lists
    if request.target is not None and not selected:
        changed = discover(root, git)       # 只給 --target：全量掃描目標專案
    problems, notes = [], []
    # 明確指定（--manifest／--rules-file）卻不存在 → 要掃的東西沒掃到，incomplete（以前靜默丟掉而 pass）
    missing = [p for p in dict.fromkeys(manifests + rule_files) if not resolve(root, p).exists()]
    if missing:
        problems.append(f"指定的檔案不存在，未檢查：{', '.join(missing)}")
    gone, unknown = [], []
    for f in dict.fromkeys(changed):
        is_m = classify(f).kind != "other"
        is_r = not is_m and is_rule_file(env, root, f) and not (f.startswith("config/slopsquat/") and not external_target(env, root))
        if not (is_m or is_r):
            continue
        if not resolve(root, f).exists():
            # 變更清單中的檔不存在：在 base 有、HEAD 沒有 = 這次 diff 刪掉的檔，正常略過；
            # 給了 --base 卻在 base 也找不到 → 清單與 diff 對不上，incomplete
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
