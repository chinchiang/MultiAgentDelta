#!/usr/bin/env python3
"""VibeSec CVE 參考目錄（config/catalogs/cve-references.yaml）的核對：CLAUDE.md 規則 3「CVE 只能查目錄」。

由 scripts/validate.py 呼叫：
  catalog_problems(cves)                  目錄每筆的欄位是否完整、格式是否正確（GHSA ID、日期、KEV 分欄）
  reference_problems(cves, files, root)   文件與設定引用的 CVE 是否都在目錄

  python3 scripts/cve_catalog.py selftest
"""
from __future__ import annotations
import pathlib, re, sys

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
GHSA_RE = re.compile(r"GHSA(-[23456789cfghjmpqrvwx]{4}){3}")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
CATALOG = "config/catalogs/cve-references.yaml"


def catalog_problems(cves: dict) -> list[str]:
    """目錄每筆須可查證：GHSA ID、發布日、受影響套件、標題；KEV 分欄（kev 為布林，true 時才有 kev_date_added）。"""
    out = []
    for cid, m in (cves or {}).items():
        m = m if isinstance(m, dict) else {}
        why = [w for w, bad in [
            ("ID 格式", not CVE_RE.fullmatch(str(cid))),
            ("ghsa", not GHSA_RE.fullmatch(str(m.get("ghsa") or ""))),
            ("published", not DATE_RE.fullmatch(str(m.get("published") or ""))),
            ("affected", not m.get("affected")),
            ("summary", not m.get("summary")),
            ("kev（須為 true／false）", not isinstance(m.get("kev"), bool)),
            ("kev_date_added（kev: true 時必填、false 時不得填）",
             bool(m.get("kev")) != bool(DATE_RE.fullmatch(str(m.get("kev_date_added") or ""))))] if bad]
        if why:
            out.append(f"cve-references.yaml {cid}：欄位不合法（{'、'.join(why)}）")
    return out


def reference_problems(cves: dict, files, root: pathlib.Path) -> list[str]:
    """files 中出現、但不在目錄的 CVE → 「<相對路徑>:<行>: <CVE> 不在目錄」。目錄檔本身略過；讀不到的檔略過。"""
    out = []
    for f in files:
        rel = pathlib.Path(f).resolve().relative_to(root.resolve())
        if rel.as_posix() == CATALOG:
            continue
        try:
            lines = pathlib.Path(f).read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for i, line in enumerate(lines, 1):
            for m in CVE_RE.finditer(line):
                if m.group(0) not in (cves or {}):
                    out.append(f"{rel}:{i}: {m.group(0)} 不在 {CATALOG}（CLAUDE.md 規則 3：查證後再加入）")
    return out


def selftest() -> list[str]:
    import tempfile
    fails: list[str] = []
    # 虛構 ID 在執行期組出：本檔不在 validate.py 的 CVE 掃描範圍，但避免被其他工具誤認為真實引用
    fake, real = "CVE-" + "2099-0001", "CVE-" + "2099-0002"
    good = {"ghsa": "GHSA-jfh8-c2jp-5v3q", "published": "2021-12-10", "affected": ["maven:x:y"], "summary": "s"}
    cases = [
        ("完整（不在 KEV）", {real: {**good, "kev": False}}, 0),
        ("完整（在 KEV）", {real: {**good, "kev": True, "kev_date_added": "2021-12-10"}}, 0),
        ("ID 格式錯", {"CVE-21-1": {**good, "kev": False}}, 1),
        ("GHSA 格式錯", {real: {**good, "ghsa": "GHSA-xxxx", "kev": False}}, 1),
        ("缺 published", {real: {**{k: v for k, v in good.items() if k != "published"}, "kev": False}}, 1),
        ("缺 affected", {real: {**good, "affected": [], "kev": False}}, 1),
        ("kev 不是布林", {real: {**good, "kev": "yes"}}, 1),
        ("kev: true 缺收錄日", {real: {**good, "kev": True}}, 1),
        ("kev: false 卻填收錄日", {real: {**good, "kev": False, "kev_date_added": "2021-12-10"}}, 1),
        ("值不是物件", {real: None}, 1),
    ]
    for label, cves, want in cases:
        got = catalog_problems(cves)
        if len(got) != want:
            fails.append(f"catalog_problems「{label}」應回報 {want} 筆（得到 {got}）")
    with tempfile.TemporaryDirectory() as d:
        root = pathlib.Path(d)
        (root / "config/catalogs").mkdir(parents=True)
        (root / CATALOG).write_text(f"cves:\n  {fake}: {{}}\n", encoding="utf-8")   # 目錄檔本身不掃
        (root / "a.md").write_text(f"見 {real}。\n另見 {fake} 與 {real}\n", encoding="utf-8")
        (root / "b.yml").write_text(f"# CVE-2099-XXXXX 是佔位字串，不是 ID\nx: 1\n", encoding="utf-8")
        got = reference_problems({real: {}}, [root / CATALOG, root / "a.md", root / "b.yml"], root)
        if got != [f"a.md:2: {fake} 不在 {CATALOG}（CLAUDE.md 規則 3：查證後再加入）"]:
            fails.append(f"reference_problems：只回報不在目錄的 CVE 並附行號，佔位字串與目錄檔本身不算（得到 {got}）")
    # 本 repo 的實際目錄：每筆欄位完整
    try:
        import yaml
        cves = (yaml.safe_load((pathlib.Path(__file__).resolve().parent.parent / CATALOG).read_text(encoding="utf-8")) or {}).get("cves")
        if not cves or catalog_problems(cves):
            fails.append(f"本 repo 的 {CATALOG} 應存在且每筆欄位完整：{catalog_problems(cves or {})}")
    except (ImportError, OSError) as e:
        fails.append(f"無法讀取本 repo 的 {CATALOG}：{type(e).__name__}")
    return fails


if __name__ == "__main__":
    if sys.argv[1:2] == ["selftest"]:
        _fails = selftest()
        for f in _fails:
            print(f"FAIL {f}")
        print("selftest 通過" if not _fails else f"selftest 失敗 {len(_fails)} 項")
        sys.exit(1 if _fails else 0)
    print(__doc__.strip()); sys.exit(4)
