#!/usr/bin/env python3
"""兩份 run_evals.py --json 輸出的逐案比對（#224）：分支與 main 在同一台機器、同一組參數下各跑一次，逐案必須相同。

本機缺 semgrep 等工具時 --baseline 一定報退步，TP／TN 數字也隨工具組合而變；判準是「逐案與 main 相同」，不是絕對數字。
逐欄完全比對、不正規化（案例列沒有時間欄位）；兩邊的案例 ID 集合也必須相同。

  python3 scripts/compare_evals.py <main.json> <branch.json>
    0 逐案相同   1 有差異（印出案例 ID、兩邊的列與 summary）   2 無法比對（檔案缺席、無法解析、缺 cases；incomplete ≠ pass）

  python3 scripts/compare_evals.py selftest
"""
from __future__ import annotations
import json, pathlib, sys


class InputError(Exception):
    """輸入無法比對（缺席、無法解析、格式不符）：exit 2，不得當成沒有差異。"""


def load(path: pathlib.Path | str) -> dict[str, dict]:
    """讀一份 run_evals --json 輸出 → {案例 ID: 案例列}。缺席、無法解析、缺 cases、案例缺 id 或 ID 重複 → InputError。"""
    try:
        doc = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise InputError(f"{path}：缺席或無法解析（{type(e).__name__}）") from e
    cases = doc.get("cases") if isinstance(doc, dict) else None
    if not isinstance(cases, list):
        raise InputError(f"{path}：缺 cases 清單（不是 run_evals --json 的輸出）")
    rows: dict[str, dict] = {}
    for c in cases:
        cid = c.get("id") if isinstance(c, dict) else None
        if not isinstance(cid, str) or not cid:
            raise InputError(f"{path}：有案例缺 id")
        if cid in rows:
            raise InputError(f"{path}：案例 ID 重複：{cid}")
        rows[cid] = c
    return rows


def differences(main: dict[str, dict], branch: dict[str, dict]) -> list[str]:
    """逐案比對（main、branch 是 load 的結果）：只在一邊的案例、列不同的案例，各一行；空清單 = 逐案相同。"""
    show = lambda r: json.dumps(r, ensure_ascii=False, sort_keys=True)
    out = [f"只在 main：{cid}" for cid in sorted(set(main) - set(branch))]
    out += [f"只在分支：{cid}" for cid in sorted(set(branch) - set(main))]
    out += [f"{cid}：\n  main  {show(main[cid])}\n  分支  {show(branch[cid])}"
            for cid in sorted(set(main) & set(branch)) if main[cid] != branch[cid]]
    return out


def _summary(path: str) -> str:
    try:
        return json.dumps((json.loads(pathlib.Path(path).read_text(encoding="utf-8")).get("summary") or {}).get("ALL"),
                          ensure_ascii=False)
    except (OSError, ValueError, AttributeError):
        return "（無法讀取）"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr); return 2
    try:
        main_rows, branch_rows = load(argv[0]), load(argv[1])
    except InputError as e:
        print(f"無法比對：{e}", file=sys.stderr); return 2
    diffs = differences(main_rows, branch_rows)
    for d in diffs:
        print(d)
    print(f"main  summary：{_summary(argv[0])}")
    print(f"分支  summary：{_summary(argv[1])}")
    print(f"{len(main_rows)}／{len(branch_rows)} 個案例；" + (f"{len(diffs)} 項差異" if diffs else "逐案相同"))
    return 1 if diffs else 0


def selftest() -> list[str]:
    import contextlib, io, tempfile
    fails: list[str] = []
    row = lambda cid, outcome="TP", **kw: {"id": cid, "gate": "G2", "rule_id": "vibesec.g2.hardcoded-secret", "outcome": outcome,
                                           "reason": None, "hits": [], **kw}
    doc = lambda *rows: {"split": "all", "summary": {"TP": sum(r["outcome"] == "TP" for r in rows)}, "cases": list(rows)}
    base = doc(row("a"), row("b", "TN"))
    _rows = lambda d: {c["id"]: c for c in d["cases"]}
    for label, other, want in [
        ("逐案相同（順序不同也算相同）", doc(row("b", "TN"), row("a")), 0),
        ("判定不同", doc(row("a", "FN"), row("b", "TN")), 1),
        ("其他欄位不同（不正規化）", doc(row("a", reason="x"), row("b", "TN")), 1),
        ("分支少一個案例", doc(row("a")), 1),
        ("分支多一個案例", doc(row("a"), row("b", "TN"), row("c")), 1),
    ]:
        try:
            got = differences(_rows(base), _rows(other))
        except Exception as e:
            fails.append(f"differences「{label}」不得拋例外（{type(e).__name__}：{e}）"); continue
        if bool(got) != bool(want):
            fails.append(f"differences「{label}」應{'有' if want else '沒有'}差異（得到 {got}）")
    got = differences(_rows(base), _rows(doc(row("a", "FN"), row("b", "TN"))))
    if not any("a" in g and "FN" in g for g in got):
        fails.append(f"差異應寫出案例 ID 與兩邊的列（得到 {got}）")
    # 命令列：0／1／2；無法比對（缺席、無法解析、缺 cases、案例缺 id、ID 重複）→ 2，不是 0
    with tempfile.TemporaryDirectory() as d:
        D = pathlib.Path(d)
        def put(name, v):
            (D / name).write_text(v if isinstance(v, str) else json.dumps(v), encoding="utf-8")
            return D / name
        same, diff = put("same.json", doc(row("b", "TN"), row("a"))), put("diff.json", doc(row("a", "FN"), row("b", "TN")))
        base_f = put("base.json", base)
        for label, b, want in [
            ("逐案相同", same, 0), ("有差異", diff, 1), ("檔案缺席", D / "none.json", 2),
            ("無法解析", put("bad.json", "{"), 2), ("缺 cases", put("nocases.json", {"summary": {}}), 2),
            ("cases 不是清單", put("notlist.json", {"cases": {}}), 2),
            ("案例缺 id", put("noid.json", {"cases": [{"outcome": "TP"}]}), 2),
            ("案例 ID 重複", put("dup.json", doc(row("a"), row("a"))), 2),
        ]:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                try:
                    rc = main([str(base_f), str(b)])
                except Exception as e:
                    rc = f"例外 {type(e).__name__}"
            if rc != want:
                fails.append(f"命令列「{label}」應 exit {want}（得到 {rc}）")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            if main([str(base_f)]) != 2:
                fails.append("參數不足應 exit 2")
    return fails


if __name__ == "__main__":
    if sys.argv[1:2] == ["selftest"]:
        _fails = selftest()
        for f in _fails:
            print(f"FAIL {f}")
        print("selftest 通過" if not _fails else f"selftest 失敗 {len(_fails)} 項")
        sys.exit(1 if _fails else 0)
    sys.exit(main(sys.argv[1:]))
