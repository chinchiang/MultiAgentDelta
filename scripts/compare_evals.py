#!/usr/bin/env python3
"""兩份 run_evals.py --json 輸出的逐案比對（#224）：分支與 main 在同一台機器、同一組參數下各跑一次，逐案必須相同。

本機缺 semgrep 等工具時 --baseline 一定報退步，TP／TN 數字也隨工具組合而變；判準是「逐案與 main 相同」，不是絕對數字。
逐欄完全比對、不正規化（案例列沒有時間欄位）；兩邊的案例 ID 集合也必須相同。

  python3 scripts/compare_evals.py <main.json> <branch.json>
    0 逐案相同   1 有差異（印出案例 ID、不同欄位、兩邊的列）
    2 無法比對（檔案缺席、無法解析、缺 cases、cases 為空、案例缺 id 或 ID 重複；incomplete ≠ pass）
    兩邊的 summary（ALL 與各閘門）一律印出。

  python3 scripts/compare_evals.py selftest
"""
from __future__ import annotations
import json, pathlib, sys


class InputError(Exception):
    """輸入無法比對（缺席、無法解析、格式不符）：exit 2，不得當成沒有差異。"""


def load(path: pathlib.Path | str) -> tuple[dict[str, dict], dict]:
    """讀一份 run_evals --json 輸出 → ({案例 ID: 案例列}, summary)。summary 缺席或不是物件 → {}（只用來顯示）。
    缺席、無法解析、缺 cases、cases 為空（run_evals 沒對到任何案例時照樣寫出 JSON）、案例缺 id 或 ID 重複 → InputError。"""
    try:
        doc = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise InputError(f"{path}：缺席或無法解析（{type(e).__name__}）") from e
    cases = doc.get("cases") if isinstance(doc, dict) else None
    if not isinstance(cases, list):
        raise InputError(f"{path}：缺 cases 清單（不是 run_evals --json 的輸出）")
    if not cases:
        raise InputError(f"{path}：cases 為空（沒有任何案例，無法確認逐案相同）")
    rows: dict[str, dict] = {}
    for c in cases:
        cid = c.get("id") if isinstance(c, dict) else None
        if not isinstance(cid, str) or not cid:
            raise InputError(f"{path}：有案例缺 id")
        if cid in rows:
            raise InputError(f"{path}：案例 ID 重複：{cid}")
        rows[cid] = c
    summary = doc.get("summary")
    return rows, summary if isinstance(summary, dict) else {}


def differences(main: dict[str, dict], branch: dict[str, dict]) -> list[str]:
    """逐案比對（main、branch 是 load 的案例列）：只在一邊的案例、列不同的案例，各一項；空清單 = 逐案相同。"""
    show = lambda r: json.dumps(r, ensure_ascii=False, sort_keys=True)
    out = [f"只在 main：{cid}" for cid in sorted(set(main) - set(branch))]
    out += [f"只在分支：{cid}" for cid in sorted(set(branch) - set(main))]
    for cid in sorted(set(main) & set(branch)):
        a, b = main[cid], branch[cid]
        if a != b:
            fields = sorted(k for k in set(a) | set(b) if a.get(k, KeyError) != b.get(k, KeyError))
            out.append(f"{cid}（不同欄位：{'、'.join(fields)}）：\n  main  {show(a)}\n  分支  {show(b)}")
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr); return 4
    try:
        (main_rows, main_sum), (branch_rows, branch_sum) = load(argv[0]), load(argv[1])
    except InputError as e:
        print(f"無法比對：{e}", file=sys.stderr); return 2
    diffs = differences(main_rows, branch_rows)
    for d in diffs:
        print(d)
    for who, s in (("main", main_sum), ("分支", branch_sum)):
        print(f"{who} summary：" + ("（缺席）" if not s else ""))
        for k in sorted(s):   # ALL 依字母序排在 G0–G6 之前
            print(f"  {k}：{json.dumps(s[k], ensure_ascii=False)}")
    print(f"{len(main_rows)}／{len(branch_rows)} 個案例；" + (f"{len(diffs)} 項差異" if diffs else "逐案相同"))
    return 1 if diffs else 0


def selftest() -> list[str]:
    import contextlib, io, tempfile
    fails: list[str] = []
    row = lambda cid, outcome="TP", **kw: {"id": cid, "gate": "G2", "rule_id": "vibesec.g2.hardcoded-secret",
                                           "outcome": outcome, "reason": None, "hits": [], **kw}
    doc = lambda *rows: {"split": "all", "summary": {"ALL": {"TP": sum(r["outcome"] == "TP" for r in rows)}},
                         "cases": list(rows)}
    rows_of = lambda d: {c["id"]: c for c in d["cases"]}
    base = doc(row("a"), row("b", "TN"))
    for label, other, want in [
        ("逐案相同（順序不同也算相同）", doc(row("b", "TN"), row("a")), 0),
        ("判定不同", doc(row("a", "FN"), row("b", "TN")), 1),
        ("其他欄位不同（不正規化）", doc(row("a", reason="x"), row("b", "TN")), 1),
        ("分支多一個欄位", doc(row("a", extra=None), row("b", "TN")), 1),
        ("分支少一個案例", doc(row("a")), 1),
        ("分支多一個案例", doc(row("a"), row("b", "TN"), row("c")), 1),
    ]:
        try:
            got = differences(rows_of(base), rows_of(other))
        except Exception as e:
            fails.append(f"differences「{label}」不得拋例外（{type(e).__name__}：{e}）"); continue
        if bool(got) != bool(want):
            fails.append(f"differences「{label}」應{'有' if want else '沒有'}差異（得到 {got}）")
    got = differences(rows_of(base), rows_of(doc(row("a", "FN", reason="x"), row("b", "TN"))))
    if len(got) != 1 or not got[0].startswith("a（不同欄位：outcome、reason）") or "FN" not in got[0]:
        fails.append(f"差異應寫出案例 ID、不同欄位與兩邊的列（得到 {got}）")
    # 命令列：0／1／2；無法比對 → 2，不是 0；參數不足 → 4（同其他腳本的用法錯誤）
    with tempfile.TemporaryDirectory() as d:
        D = pathlib.Path(d)

        def put(name, v):
            (D / name).write_text(v if isinstance(v, str) else json.dumps(v), encoding="utf-8")
            return D / name

        def run(*args):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try:
                    rc = main([str(a) for a in args])
                except Exception as e:
                    rc = f"例外 {type(e).__name__}"
            return rc, out.getvalue()

        base_f = put("base.json", base)
        for label, b, want in [
            ("逐案相同", put("same.json", doc(row("b", "TN"), row("a"))), 0),
            ("有差異", put("diff.json", doc(row("a", "FN"), row("b", "TN"))), 1),
            ("summary 不是物件", put("badsum.json", {**doc(row("b", "TN"), row("a")), "summary": ["x"]}), 0),
            ("檔案缺席", D / "none.json", 2), ("無法解析", put("bad.json", "{"), 2),
            ("頂層是陣列", put("list.json", []), 2), ("缺 cases", put("nocases.json", {"summary": {}}), 2),
            ("cases 不是清單", put("notlist.json", {"cases": {}}), 2),
            ("cases 為空", put("empty.json", {"summary": {}, "cases": []}), 2),
            ("案例不是物件", put("notdict.json", {"cases": ["a"]}), 2),
            ("案例缺 id", put("noid.json", {"cases": [{"outcome": "TP"}]}), 2),
            ("案例 ID 重複", put("dup.json", doc(row("a"), row("a"))), 2),
        ]:
            rc, _ = run(base_f, b)
            if rc != want:
                fails.append(f"命令列「{label}」應 exit {want}（得到 {rc}）")
        if run(put("e1.json", {"cases": []}), put("e2.json", {"cases": []}))[0] != 2:
            fails.append("兩邊 cases 都為空 → 無法比對（exit 2），不是逐案相同")
        rc, out = run(base_f, put("gates.json", {**doc(row("b", "TN"), row("a")),
                                                 "summary": {"G2": {"TP": 1}, "ALL": {"TP": 1}}}))
        if rc != 0 or "  ALL：" not in out or "  G2：" not in out or out.index("  ALL：") > out.index("  G2："):
            fails.append(f"summary 要印出 ALL 與各閘門（ALL 在前）（得到 {out!r}）")
        if run(base_f)[0] != 4:
            fails.append("參數不足應 exit 4（用法錯誤）")
    return fails


if __name__ == "__main__":
    if sys.argv[1:2] == ["selftest"]:
        _fails = selftest()
        for f in _fails:
            print(f"FAIL {f}")
        print("selftest 通過" if not _fails else f"selftest 失敗 {len(_fails)} 項")
        sys.exit(1 if _fails else 0)
    sys.exit(main(sys.argv[1:]))
