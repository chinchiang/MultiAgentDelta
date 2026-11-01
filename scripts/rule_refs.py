#!/usr/bin/env python3
"""VibeSec：規則引用的檢查（#239）。每一處「檔名＋規則編號」的引用都要指向 AGENTS.md，而且編號真的存在。

程式碼、設定與文件用「AGENTS.md 規則 3」「AGENTS.md #2」「AGENTS.md 第 1 條」「AGENTS.md rule 1」引用不可違反的規則。
#235 把規範從 CLAUDE.md 搬到 AGENTS.md 時漏改兩處；AGENTS.md 也只用文字要求「既有編號保持不變」。本模組讓兩者都有機械保護。

由 scripts/validate.py 呼叫：
  problems(root)   root 底下 git 追蹤的文字檔（含尚未 git add、沒被 .gitignore 排除的新檔；不含 reports/）中，
                   每個有問題的引用一項：檔名不是 AGENTS.md（規範的唯一來源）、或編號超出 AGENTS.md「不可違反的規則」的範圍。
                   AGENTS.md 缺席、讀不出規則清單、清單編號不連續、git 列不出檔案 → 也是問題（拿不到證據 ≠ 沒有問題）。

認得的寫法：<檔名>（AGENTS.md 或 CLAUDE.md，可加反引號）之後，可隔空白或冒號，接
  規則 N／規則N／#N／第 N 條／第N條／rule N／rule #N（含列舉：規則 3、7；規則 1 與 9；第 1、9 條；#2、#7；
  rules 1, 2, and 9；範圍：規則 1–9 檢查兩個端點）。只比對同一行之內。
「AGENTS.md #N」一律視為規則引用：檔名後面緊接 issue 編號的寫法有歧義，會被報成編號超出範圍。
只認 ASCII 數字，所以 AGENTS.md 說明引用格式的那句（字面上的「規則 N」）不算引用；
規則檔清單裡的 CLAUDE.md（後面不接編號）也不算。

  python3 scripts/rule_refs.py selftest
"""
from __future__ import annotations
import os, pathlib, re, subprocess, sys
from typing import NamedTuple

SOURCE = "AGENTS.md"
SECTION_TITLE = "不可違反的規則"
SECTION = f"## {SECTION_TITLE}"
EXCLUDE_DIRS = ("reports/",)   # 執行期報告


def rule_count(agents_text: str) -> tuple[int | None, str | None]:
    """AGENTS.md 全文 →（規則數, None）；找不到「不可違反的規則」一節、節內沒有編號清單、或編號不是 1..N 連續 →（None, 原因）。"""
    lines = agents_text.splitlines()
    try:
        start = next(i for i, ln in enumerate(lines) if ln.strip() == SECTION)
    except StopIteration:
        return None, f"找不到「{SECTION_TITLE}」一節"
    nums = []
    for ln in lines[start + 1:]:
        if ln.startswith("## "):
            break
        if m := re.match(r"^([0-9]+)\. ", ln):
            nums.append(int(m[1]))
    if not nums:
        return None, f"「{SECTION_TITLE}」一節沒有編號清單"
    if nums != list(range(1, len(nums) + 1)):
        return None, f"「{SECTION_TITLE}」的編號不是 1 起連續（{nums}）"
    return len(nums), None


class Ref(NamedTuple):
    line: int        # 行號（1 起）
    file: str        # 引用的檔名：AGENTS.md 或 CLAUDE.md
    numbers: list    # 引用的規則編號（列舉與範圍的每個端點）
    raw: str         # 原文


# 只認 ASCII 數字（\d 也會比對全形數字）。列舉：、,，與和及 and（含 ", and"）；範圍：1–9 只檢查兩個端點
_N = r"[0-9]+"
_AND = r"(?:\s*[、,，]\s*(?:and\s+)?|\s*[與和及]\s*|\s+and\s+)"
_TO = r"\s*[–\-~～]\s*"
# <檔名>（前面要是邊界，可加反引號）＋可隔空白或冒號＋一種寫法
_REF = re.compile(
    rf"(?<![\w-])`?(?P<file>AGENTS\.md|CLAUDE\.md)`?\s*[：:]?\s*"
    rf"(?P<nums>規則\s*{_N}(?:(?:{_AND}|{_TO}){_N})*"
    rf"|#{_N}(?:{_AND}#?{_N})*"
    rf"|第\s*{_N}(?:{_AND}{_N})*\s*條"
    rf"|[Rr]ules?\s+#?{_N}(?:(?:{_AND}|{_TO})#?{_N})*)")


def references(text: str) -> list[Ref]:
    """一份文字 → 每個規則引用一個 Ref。只比對同一行之內。"""
    return [Ref(i, m["file"], [int(n) for n in re.findall(_N, m["nums"])], m[0])
            for i, ln in enumerate(text.splitlines(), 1) for m in _REF.finditer(ln)]


def text_problems(text: str, n_rules: int) -> list[tuple[int, str]]:
    """一份文字裡有問題的引用：[(行號, 訊息)]。"""
    out = []
    for r in references(text):
        if r.file != SOURCE:
            out.append((r.line, f"「{r.raw}」：規範的唯一來源是 {SOURCE}，引用要指向 {SOURCE}"))
        bad = [n for n in r.numbers if not 1 <= n <= n_rules]
        if bad:
            out.append((r.line, f"「{r.raw}」：{SOURCE} 只有規則 1–{n_rules}，沒有 {'、'.join(map(str, bad))}"))
    return out


def tracked_files(root: pathlib.Path) -> list[str]:
    """root 底下 git 追蹤的檔案，加上尚未 git add、沒被 .gitignore 排除的新檔（相對路徑；不含 reports/）；
    git 失敗 → RuntimeError。巢狀 repo（例如 CI 的 _trusted/）會以目錄出現，由 problems 略過。"""
    try:
        r = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise RuntimeError(f"無法執行 git：{type(e).__name__}") from e
    if r.returncode != 0:
        raise RuntimeError(f"git ls-files 失敗：{r.stderr.strip()[:200]}")
    return sorted({f for f in r.stdout.split("\0") if f and not f.startswith(EXCLUDE_DIRS)})


def problems(root) -> list[str]:
    """root 底下每個有問題的引用一項（「路徑:行：…」）；拿不到規則數或檔案清單 → 一項說明，不回傳空清單。
    略過：目錄（巢狀 repo、submodule）、工作樹已刪的檔、含 NUL 的二進位檔。讀不到或不是 UTF-8 的文字檔 → 問題。"""
    root = pathlib.Path(root)
    try:
        n, why = rule_count((root / SOURCE).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as e:
        return [f"{SOURCE} 讀不到（{type(e).__name__}）：無法確認規則引用的編號"]
    if n is None:
        return [f"{SOURCE}：{why}，無法確認規則引用的編號"]
    try:
        files = tracked_files(root)
    except RuntimeError as e:
        return [f"列不出要掃描的檔案（{e}）：無法確認規則引用"]
    out = []
    for f in files:
        path = root / f
        if path.is_dir() or not path.exists():
            continue
        try:
            data = path.read_bytes()
        except OSError as e:
            out.append(f"{f}：讀不到（{type(e).__name__}），無法確認規則引用")
            continue
        if b"\0" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            out.append(f"{f}：不是 UTF-8 文字，無法確認規則引用")
            continue
        out += [f"{f}:{line}：{msg}" for line, msg in text_problems(text, n)]
    return out


# ---------------------------------------------------------------- selftest
# fixture 的引用用串接組出來：本檔也在掃描範圍內，引用若照字面寫出來，會被本模組自己報成問題
_A, _C = "AGENTS" + ".md", "CLAUDE" + ".md"


def _agents(n: int, extra: str = "") -> str:
    rules = "\n".join(f"{i}. **規則{i}**：內容。" for i in range(1, n + 1))
    return (f"# AGENTS.md\n\n## 不可違反的規則\n\n規則編號被程式碼與文件引用（「{_A} 規則 N」「#N」「第 N 條」）。\n\n"
            f"{rules}\n{extra}\n## 命名與格式慣例\n\n1. 這不是規則清單。\n2. 也不是。\n")


def selftest() -> list[str]:
    import tempfile
    fails: list[str] = []

    def check(label, fn):
        try:
            msg = fn()
        except Exception as e:   # 紅燈要是 FAIL，不是崩潰
            msg = f"拋出例外 {type(e).__name__}：{e}"
        if msg:
            fails.append(f"{label}：{msg}")

    def t_count():
        bad = []
        if rule_count(_agents(8)) != (8, None):
            bad.append(f"8 條 → {rule_count(_agents(8))}")
        if rule_count(_agents(9)) != (9, None):
            bad.append("9 條（下一節的編號清單不算）")
        for label, text in (("沒有該節", "# x\n\n1. a\n"), ("節內沒有清單", "## 不可違反的規則\n\n沒有\n## 下一節\n"),
                            ("編號跳號", "## 不可違反的規則\n\n1. a\n3. c\n"), ("不從 1 開始", "## 不可違反的規則\n\n2. a\n3. b\n")):
            n, why = rule_count(text)
            if n is not None or not why:
                bad.append(f"{label} 應回報原因（得到 {n}、{why}）")
        return "；".join(bad) or None
    check("rule_count：取自「不可違反的規則」一節、編號須 1..N 連續", t_count)

    def t_forms():
        text = "\n".join([f"a（{_A} 規則 3）", f"b {_A} 規則7", f"c `{_A}` #2", f"d {_A} 第 1 條", f"e {_A} 第4條",
                          f"f {_A} rule 5", f"g {_A}：規則 6", f"h {_A} 規則 3、7", f"i {_A} #2、#8", f"j {_A} rules 1 and 2"])
        got = [(r.line, r.file, r.numbers) for r in references(text)]
        want = [(1, _A, [3]), (2, _A, [7]), (3, _A, [2]), (4, _A, [1]), (5, _A, [4]), (6, _A, [5]), (7, _A, [6]),
                (8, _A, [3, 7]), (9, _A, [2, 8]), (10, _A, [1, 2])]
        return None if got == want else f"得到 {got}"
    check("references：規則 N／規則N／#N／第 N 條／第N條／rule N、冒號、反引號、列舉都認得", t_forms)

    def t_lists():   # code review：列舉、範圍與大寫也要每個編號都檢查
        cases = {f"{_A} 第 1、9 條": [1, 9], f"{_A} 規則 1–9": [1, 9], f"{_A} 規則 1-9": [1, 9], f"{_A} 規則 1 與 9": [1, 9],
                 f"{_A} 規則 1和9": [1, 9], f"{_A} 規則 2 及 9": [2, 9], f"{_A} rules 1, 2, and 9": [1, 2, 9],
                 f"{_A} rule #9": [9], f"{_A} Rule 3": [3], f"{_A} Rules 1 and 2": [1, 2]}
        bad = {t: [r.numbers for r in references(t)] for t, want in cases.items() if [r.numbers for r in references(t)] != [want]}
        return f"{bad}" if bad else None
    check("references：列舉（、／與／和／及／and）、範圍（1–9）、rule #N、大寫 Rule", t_lists)

    def t_boundary():
        texts = [f"MY_{_A} 規則 9", f"x-{_A} 規則 9", f"{_A} 規則 ９", f"{_A} 第 ３ 條"]
        hit = [t for t in texts if references(t)]
        return f"不是引用卻被認成引用（檔名前面要是邊界、只認 ASCII 數字）：{hit}" if hit else None
    check("references：檔名前面要是邊界；全形數字不算", t_boundary)

    def t_claude():
        got = text_problems(f"x（{_C} 規則 1）\ny {_C} #2", 8)
        if [ln for ln, _ in got] != [1, 2] or not all("規範的唯一來源是 AGENTS.md" in m for _, m in got):
            return f"指向 {_C} 的引用 → 問題，訊息寫明唯一來源（得到 {got}）"
        return None
    check(f"指向 {_C} 的引用 → 問題", t_claude)

    def t_range():
        got = text_problems(f"a {_A} 規則 9\nb {_A} #0\nc {_A} 規則 3、12\nd {_A} 規則 8", 8)
        if [ln for ln, _ in got] != [1, 2, 3] or not all(n in m for n, (_, m) in zip(("沒有 9", "沒有 0", "沒有 12"), got)):
            return f"超出 1–8 的編號 → 問題，每處一項（得到 {got}）"
        return None
    check("超出範圍的編號 → 問題", t_range)

    def t_not_refs():
        texts = [_agents(8),                                                    # AGENTS.md 自己說明引用格式的那句
                 f'agent_rule_files: [".cursorrules", "{_A}", "SKILL.md", "{_C}", ".cursor/rules/**/*.mdc"]',
                 f"掃描 `.cursorrules`、`{_A}`、`{_C}`、`.cursor/rules/**/*.mdc`",
                 f"# 所有 Markdown（含 {_C}、{_A}、SKILL.md）",
                 f'for p, want in (("{_C}", True), (".cursor/rules/x/y.mdc", True)):',
                 f"見 {_A}「文件語言」、#178"]                                   # issue 編號，不緊接在檔名後
        hit = [t[:40] for t in texts if references(t)]
        return f"不是規則引用卻被認成引用：{hit}" if hit else None
    check("規則檔清單的檔名、AGENTS.md 的格式說明、issue 編號 → 不是引用", t_not_refs)

    def git_tree(d: pathlib.Path, files: dict[str, str], untracked: dict[str, str] = None):
        subprocess.run(["git", "init", "-q", str(d)], check=True)
        for name, body in {**files, **(untracked or {})}.items():
            (d / name).parent.mkdir(parents=True, exist_ok=True)
            (d / name).write_text(body, encoding="utf-8")
        subprocess.run(["git", "-C", str(d), "add", "--", *files], check=True)

    def t_tree():
        bad = []
        with tempfile.TemporaryDirectory() as t:
            D = pathlib.Path(t)
            git_tree(D, {"AGENTS.md": _agents(8), ".gitignore": "ignored.md\n", "a.py": f"# {_A} 規則 9\n",
                         "ok.md": f"見 {_A} 規則 8", "bin.dat": "x", "reports/r.md": f"{_A} 規則 99"},   # reports/ 即使被追蹤也不掃
                     untracked={"new.md": f"{_C} 規則 1", "ignored.md": f"{_A} 規則 99"})
            (D / "bin.dat").write_bytes(b"\xff\xfe\x00 " + _A.encode() + "規則 99".encode())
            got = problems(D)
            if len(got) != 2 or not any(p.startswith("a.py:1") for p in got) or not any(p.startswith("new.md:1") for p in got):
                bad.append(f"應只報 a.py（超出範圍）與 new.md（尚未 git add 的新檔），不報 reports/、.gitignore 排除的檔、二進位檔（得到 {got}）")
            (D / "AGENTS.md").write_text(_agents(9), encoding="utf-8")   # 多加一條規則：原本超出範圍的引用就合法
            got = problems(D)
            if any(p.startswith("a.py") for p in got):
                bad.append(f"AGENTS.md 有 9 條時，規則 9 合法（得到 {got}）")
            (D / "AGENTS.md").write_text("# 沒有規則清單\n", encoding="utf-8")
            if not any("AGENTS.md" in p and "不可違反的規則" in p for p in problems(D)):
                bad.append("AGENTS.md 讀不出規則清單 → 問題")
            (D / "AGENTS.md").unlink()
            if not problems(D):
                bad.append("AGENTS.md 缺席 → 問題")
        with tempfile.TemporaryDirectory() as t:   # CI 在工作區 checkout 出 _trusted/ 巢狀 repo：ls-files --others 會列出目錄
            D = pathlib.Path(t)
            git_tree(D, {"AGENTS.md": _agents(8), "big5.txt": "x", "nul.bin": "x"})
            git_tree(D / "_trusted", {"AGENTS.md": _agents(8)})
            (D / "big5.txt").write_bytes("見 ".encode() + _A.encode() + "規則 1".encode("big5"))   # 非 UTF-8 的文字檔
            (D / "nul.bin").write_bytes(b"\x00\x01" + _A.encode() + "規則 99".encode())        # 含 NUL 的二進位檔
            got = problems(D)
            if len(got) != 1 or not got[0].startswith("big5.txt") or "UTF-8" not in got[0]:
                bad.append(f"巢狀 repo 目錄略過、二進位檔略過、非 UTF-8 文字檔回報問題（不默默略過）（得到 {got}）")
            if os.name == "posix" and os.geteuid() != 0:   # root 讀得到 0o000 的檔，測不出來
                (D / "big5.txt").write_text("x", encoding="utf-8")
                (D / "big5.txt").chmod(0)
                try:
                    got = problems(D)
                finally:
                    (D / "big5.txt").chmod(0o644)
                if len(got) != 1 or not got[0].startswith("big5.txt") or "讀不到" not in got[0]:
                    bad.append(f"讀不到的檔（PermissionError）→ 問題，不讓 validate 崩潰（得到 {got}）")
        with tempfile.TemporaryDirectory() as t:
            (pathlib.Path(t) / "AGENTS.md").write_text(_agents(8), encoding="utf-8")
            if not problems(pathlib.Path(t)):
                bad.append("不是 git 樹（列不出檔案）→ 問題，不是 0 個問題")
        return "；".join(bad) or None
    check("problems：git 追蹤＋未 add 的新檔、排除 reports/ 與二進位、規則數取自 AGENTS.md", t_tree)
    return fails


if __name__ == "__main__":
    if sys.argv[1:2] == ["selftest"]:
        _fails = selftest()
        for f in _fails:
            print(f"FAIL {f}")
        print("selftest 通過" if not _fails else f"selftest 失敗 {len(_fails)} 項")
        sys.exit(1 if _fails else 0)
    print(__doc__.strip(), file=sys.stderr)
    sys.exit(4)
