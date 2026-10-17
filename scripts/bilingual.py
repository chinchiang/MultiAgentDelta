#!/usr/bin/env python3
"""VibeSec 雙語集合的檢查（CLAUDE.md 命名與格式慣例、#178）：集合內的 Markdown 必須中英雙語，集合外只寫正體中文。

由 scripts/validate.py 呼叫：
  in_set(rel)              rel（repo 相對路徑）是否屬於雙語集合
  problems(text)           集合內一份文件的問題：切換連結、兩個錨點、中英兩段各層級標題數量相同

  python3 scripts/bilingual.py selftest
"""
from __future__ import annotations
import re, sys

# 雙語集合：檔案逐一列出；目錄以目錄為準（之後新增的檔案自動屬於集合）
SET_FILES = ("CLAUDE.md", "GLOSSARY.md")
SET_DIRS = ("docs/agents/", "docs/adr/", "docs/research/")
SWITCH = "[正體中文（臺灣）](#zh-tw) | [English](#english)"
ZH, EN = '<a id="zh-tw"></a>', '<a id="english"></a>'


def in_set(rel: str) -> bool:
    return rel.endswith(".md") and (rel in SET_FILES or rel.startswith(SET_DIRS))


def _headings(section: str) -> dict[int, int]:
    """各層級標題的數量（# 數 → 個數）；程式碼區塊（``` 圍住）裡的 # 不算。"""
    counts: dict[int, int] = {}
    fenced = False
    for ln in section.splitlines():
        if ln.lstrip().startswith("```"):
            fenced = not fenced
        elif not fenced and (m := re.match(r"(#{1,6}) \S", ln)):
            counts[len(m.group(1))] = counts.get(len(m.group(1)), 0) + 1
    return counts


def problems(text: str) -> list[str]:
    """集合內一份文件的問題（空清單 = 合格）。錨點須各自單獨成行、各出現一次，中文在前。"""
    lines = text.splitlines()
    out = []
    if not lines or lines[0].strip() != SWITCH:
        out.append(f"檔首缺語言切換連結（第一行須為 {SWITCH}）")
    zh, en = [i for i, ln in enumerate(lines) if ln.strip() == ZH], [i for i, ln in enumerate(lines) if ln.strip() == EN]
    for anchor, at in ((ZH, zh), (EN, en)):
        if len(at) != 1:
            out.append(f"{anchor} 應單獨成行出現一次（得到 {len(at)} 次）")
    if len(zh) == 1 and len(en) == 1:
        if zh[0] > en[0]:
            out.append("正體中文段須在英文段之前")
        else:
            a, b = _headings("\n".join(lines[zh[0]:en[0]])), _headings("\n".join(lines[en[0]:]))
            if a != b:
                fmt = lambda c: "、".join(f"{'#' * k} {v} 個" for k, v in sorted(c.items())) or "無"
                out.append(f"中英兩段的標題結構不同（正體中文：{fmt(a)}；英文：{fmt(b)}）")
    return out


def selftest() -> list[str]:
    fails: list[str] = []
    for rel, want in [("CLAUDE.md", True), ("GLOSSARY.md", True), ("docs/agents/workflow.md", True),
                      ("docs/adr/0003-new.md", True), ("docs/research/x.md", True), ("docs/agents/sub/y.md", True),
                      ("README.md", False), ("docs/05-g4-access-control-agent-review.md", False),
                      ("docs/agents.md", False), ("x/CLAUDE.md", False), (".claude/agents/vibesec-appsec.md", False),
                      ("docs/adr/notes.txt", False)]:
        if in_set(rel) != want:
            fails.append(f"in_set({rel!r}) 應為 {want}")
    doc = lambda zh="## 甲\n\n內容\n\n### 乙\n", en="## A\n\ntext\n\n### B\n", head=SWITCH: (
        f"{head}\n\n{ZH}\n\n# 標題\n\n{zh}\n---\n\n{EN}\n\n# Title\n\n{en}")
    for label, text, want in [
        ("格式正確", doc(), 0),
        ("程式碼區塊裡的 # 不算標題", doc(zh="## 甲\n\n```bash\n# 註解\n```\n\n### 乙\n"), 0),
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
    return fails


if __name__ == "__main__":
    if sys.argv[1:2] == ["selftest"]:
        _fails = selftest()
        for f in _fails:
            print(f"FAIL {f}")
        print("selftest 通過" if not _fails else f"selftest 失敗 {len(_fails)} 項")
        sys.exit(1 if _fails else 0)
    print(__doc__.strip()); sys.exit(4)
