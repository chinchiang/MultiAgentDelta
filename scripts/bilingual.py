#!/usr/bin/env python3
"""VibeSec 雙語集合的檢查（AGENTS.md「文件語言」、#178）：集合內的 Markdown 必須中英雙語，集合外只寫正體中文。

由 scripts/validate.py 呼叫：
  set_paths(root)          root 底下屬於雙語集合的 Markdown，以及缺席的集合項目與譯本（缺席 → validate 報 ERR，不是略過）
  problems(text)           集合內一份文件的問題：切換連結、兩個錨點、中英兩段各層級標題數量相同
  translation_problems(source, translation)
                           只寫正體中文的來源與它的英文譯本（TRANSLATIONS）：兩者各層級標題數量相同

  python3 scripts/bilingual.py selftest
"""
from __future__ import annotations
import pathlib, re, sys

# 雙語集合：檔案逐一列出；目錄以目錄為準（之後新增的檔案自動屬於集合）。與 AGENTS.md「文件語言」的列舉同步
SET_FILES = ("GLOSSARY.md",)
# 譯本 → 來源：來源只寫正體中文（AGENTS.md 每回合載入 agent 的 context，不放兩種語言），英文另放譯本；
# 譯本即使位在集合目錄內也不屬於雙語集合，改以標題結構與來源相同來確認兩者同步
TRANSLATIONS = {"docs/agents/rules.en.md": "AGENTS.md"}
SET_DIRS = ("docs/agents/", "docs/adr/", "docs/research/")
SWITCH = "[正體中文（臺灣）](#zh-tw) | [English](#english)"
ZH, EN = '<a id="zh-tw"></a>', '<a id="english"></a>'


def set_paths(root: pathlib.Path) -> tuple[list[pathlib.Path], list[str]]:
    """root 底下屬於雙語集合的 Markdown（目錄含子目錄、不含譯本），以及缺席的集合項目、譯本與其來源（檔案或目錄不存在）。"""
    root = pathlib.Path(root)
    found = [root / f for f in SET_FILES if (root / f).is_file()]
    found += [p for d in SET_DIRS if (root / d).is_dir() for p in (root / d).glob("**/*.md") if p.is_file()]
    found = [p for p in found if p.relative_to(root).as_posix() not in TRANSLATIONS]
    missing = [f for f in SET_FILES if not (root / f).is_file()] + [d for d in SET_DIRS if not (root / d).is_dir()]
    missing += [f for pair in TRANSLATIONS.items() for f in pair if not (root / f).is_file()]
    return sorted(set(found)), missing


def _prose(lines: list[str]):
    """(行號, 行) 但略過程式碼區塊（``` 或 ~~~，三個以上，收尾須同字元且不短於開頭）與 HTML 註解（<!-- … -->）。"""
    fence, comment = None, False
    for i, ln in enumerate(lines):
        s = ln.strip()
        if fence:
            if re.fullmatch(re.escape(fence[0]) + "{%d,}" % len(fence), s):
                fence = None
            continue
        if comment:
            comment = "-->" not in s
            continue
        if m := re.match(r"(`{3,}|~{3,})", s):
            fence = m.group(1); continue
        if s.startswith("<!--"):
            comment = "-->" not in s; continue
        yield i, ln


def _headings(lines: list[str]) -> dict[int, int]:
    """各層級標題的數量（# 數 → 個數）；程式碼區塊與 HTML 註解裡的 # 不算。"""
    counts: dict[int, int] = {}
    for _, ln in _prose(lines):
        if m := re.match(r"(#{1,6}) \S", ln):
            counts[len(m.group(1))] = counts.get(len(m.group(1)), 0) + 1
    return counts


def problems(text: str) -> list[str]:
    """集合內一份文件的問題（空清單 = 合格）。錨點須各自單獨成行、各出現一次，中文在前。"""
    lines = text.lstrip("\ufeff").splitlines()
    out = []
    if not lines or lines[0].strip() != SWITCH:
        out.append(f"檔首缺語言切換連結（第一行須為 {SWITCH}）")
    prose = list(_prose(lines))   # 程式碼區塊裡舉例的錨點不算
    zh, en = [i for i, ln in prose if ln.strip() == ZH], [i for i, ln in prose if ln.strip() == EN]
    for anchor, at in ((ZH, zh), (EN, en)):
        if len(at) != 1:
            out.append(f"{anchor} 應單獨成行出現一次（得到 {len(at)} 次）")
    if len(zh) == 1 and len(en) == 1:
        if zh[0] > en[0]:
            out.append("正體中文段須在英文段之前")
        else:
            a, b = _headings(lines[zh[0]:en[0]]), _headings(lines[en[0]:])
            if a != b:
                fmt = lambda c: "、".join(f"{'#' * k} {v} 個" for k, v in sorted(c.items())) or "無"
                out.append(f"中英兩段的標題結構不同（正體中文：{fmt(a)}；英文：{fmt(b)}）")
    return out


def translation_problems(source: str, translation: str) -> list[str]:
    """只寫正體中文的來源與英文譯本的問題（空清單 = 合格）：各層級標題數量須相同；兩者都不得帶雙語集合的錨點。"""
    out = []
    a, b = (_headings(t.lstrip("\ufeff").splitlines()) for t in (source, translation))
    if a != b:
        fmt = lambda c: "、".join(f"{'#' * k} {v} 個" for k, v in sorted(c.items())) or "無"
        out.append(f"譯本與來源的標題結構不同（來源：{fmt(a)}；譯本：{fmt(b)}），譯本須在同一個 PR 更新")
    for label, text in (("來源", source), ("譯本", translation)):
        if any(ln.strip() in (ZH, EN) for _, ln in _prose(text.splitlines())):
            out.append(f"{label}帶有雙語集合的錨點：來源只寫正體中文、譯本只寫英文")
    return out


def selftest() -> list[str]:
    fails: list[str] = []
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        R = pathlib.Path(d)
        for rel in ("GLOSSARY.md", "docs/agents/rules.en.md", "docs/agents/a.md", "docs/agents/sub/b.md", "docs/adr/0003-new.md", "docs/adr/notes.txt",
                    "docs/research/r.md", "README.md", "docs/05-x.md", "docs/agents.md", ".claude/agents/c.md"):
            (R / rel).parent.mkdir(parents=True, exist_ok=True); (R / rel).write_text("x", encoding="utf-8")
        found, missing = set_paths(R)
        got = sorted(p.relative_to(R).as_posix() for p in found)
        want = ["GLOSSARY.md", "docs/adr/0003-new.md", "docs/agents/a.md", "docs/agents/sub/b.md", "docs/research/r.md"]
        if got != want:
            fails.append(f"set_paths：集合內的 Markdown（含子目錄、不含集合外與非 .md）應為 {want}（得到 {got}）")
        if missing != ["AGENTS.md"]:
            fails.append(f"set_paths：譯本在、來源缺席時應回報來源（得到 {missing}）")
        if set_paths(R / "none")[1] != list(SET_FILES) + list(SET_DIRS) + [f for p in TRANSLATIONS.items() for f in p]:
            fails.append("set_paths：root 不存在 → 集合項目全部缺席")
    doc = lambda zh="## 甲\n\n內容\n\n### 乙\n", en="## A\n\ntext\n\n### B\n", head=SWITCH: (
        f"{head}\n\n{ZH}\n\n# 標題\n\n{zh}\n---\n\n{EN}\n\n# Title\n\n{en}")
    for label, text, want in [
        ("格式正確", doc(), 0),
        ("程式碼區塊裡的 # 不算標題", doc(zh="## 甲\n\n```bash\n# 註解\n```\n\n### 乙\n"), 0),
        ("~~~ 與四個反引號的程式碼區塊", doc(zh="## 甲\n\n~~~\n# 註解\n~~~\n\n````md\n```\n## 假\n```\n````\n\n### 乙\n"), 0),
        ("HTML 註解裡的 # 不算", doc(zh="## 甲\n\n<!--\n## 草稿\n-->\n\n### 乙\n"), 0),
        ("程式碼區塊裡舉例的錨點不算", doc(zh=f"## 甲\n\n```\n{EN}\n```\n\n### 乙\n"), 0),
        ("BOM", "\ufeff" + doc(), 0),
        ("CRLF", doc().replace("\n", "\r\n"), 0),
        ("缺切換連結", doc(head="# 沒有切換連結"), 1),
        ("缺英文錨點", doc().replace(EN, ""), 1),
        ("缺中文錨點", doc().replace(ZH, ""), 1),
        ("英文錨點在中文錨點之前", f"{SWITCH}\n\n{EN}\n\n# Title\n\n---\n\n{ZH}\n\n# 標題\n", 1),
        ("錨點順序顛倒、兩段都沒有標題", f"{SWITCH}\n\n{EN}\n\ntext\n\n{ZH}\n\n文字\n", 1),
        ("英文段少一節", doc(en="## A\n\ntext\n"), 1),
        ("同數量但層級不同", doc(en="## A\n\n## B\n"), 1),
        ("只有中文", "# 標題\n\n只有中文\n", 3),
    ]:
        got = problems(text)
        if len(got) != want:
            fails.append(f"problems「{label}」應回報 {want} 項（得到 {got}）")
    src = "# 標題\n\n## 甲\n\n```bash\n# 註解\n```\n\n### 乙\n"
    for label, (s, tr), want in [
        ("譯本與來源標題結構相同", (src, "Intro line.\n\n# Title\n\n## A\n\n### B\n"), 0),
        ("譯本少一節", (src, "# Title\n\n## A\n"), 1),
        ("同數量但層級不同", (src, "# Title\n\n## A\n\n## B\n"), 1),
        ("來源帶錨點", (f"{ZH}\n\n{src}", "# Title\n\n## A\n\n### B\n"), 1),
        ("譯本程式碼區塊裡舉例的錨點不算", (src, f"# Title\n\n## A\n\n```\n{EN}\n```\n\n### B\n"), 0),
    ]:
        got = translation_problems(s, tr)
        if len(got) != want:
            fails.append(f"translation_problems「{label}」應回報 {want} 項（得到 {got}）")
    return fails


if __name__ == "__main__":
    if sys.argv[1:2] == ["selftest"]:
        _fails = selftest()
        for f in _fails:
            print(f"FAIL {f}")
        print("selftest 通過" if not _fails else f"selftest 失敗 {len(_fails)} 項")
        sys.exit(1 if _fails else 0)
    print(__doc__.strip()); sys.exit(4)
