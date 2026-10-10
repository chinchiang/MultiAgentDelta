#!/usr/bin/env python3
"""VibeSec 審查包：把受測程式碼附進送給非 Claude Code provider 的審查包（docs/09 §6）。

Claude Code 的 reviewer sub-agent 能自己讀 repo，scripts/review_provider.py 呼叫的外部模型不行：審查包裡沒有程式碼，
它就只能憑摘要回答，引用不了 file:line。這支工具把 commit 的原文（含行號）附進審查包：

  python3 scripts/review_packet.py build --base reports/raw/G4/review/packet.json --target <repo> \\
      [--commit HEAD] [--diff-base <sha>] [--threat-model docs/threat-model.yaml] [--max-bytes 900000] --out <packet.json>
  python3 scripts/review_packet.py selftest

範圍（docs/09 §6：送 diff 周邊 ±40 行與被引用的檔案，不送整個 repo；G4 架構審查送威脅模型）：
  - 不給 --diff-base（full）：威脅模型全文，加上威脅模型以 path:line 引用、且受 git 追蹤的檔案全文。
  - 給 --diff-base（diff）：威脅模型全文，加上 diff_base..commit 每個變更 hunk 前後 40 行。
內容一律取自 commit（git show），不讀工作目錄。

不可違反（CLAUDE.md 規則 7）：
  - 送出前以 gitleaks（本 repo 的 config/gitleaks.toml）掃描要附上的內容，命中的字串一律換成前 4 後 4 加 sha256 指紋。
    gitleaks 缺席或失敗 → 無法確認祕密已遮罩，不產生審查包（exit 2）。審查包的資料分級沿用 --base（必須宣告，否則不產生），不在這裡判定；--base 內容一併掃描遮罩。
  - 超過 --max-bytes → 不產生（exit 2），不默默截斷：截斷後的審查包會讓模型以為看到了全部。
離開碼：0 產生；2 無法產生（缺 gitleaks、掃描失敗、超過上限、找不到 commit 或威脅模型）；4 參數錯誤。
"""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, re, shutil, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONTEXT = 40
REF = re.compile(r"([A-Za-z0-9_./-]+\.[A-Za-z0-9]+):\d+")
DATA_CLASSES = ("public", "internal", "confidential", "pii")
BASE_SCAN_NAME = ".vibesec-packet-base.json"   # 掃描用的暫存檔名（不會出現在 git 追蹤的路徑）
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", re.M)


class PacketError(RuntimeError):
    pass


def _git_bytes(target: pathlib.Path, *args: str) -> bytes:
    r = subprocess.run(["git", "-C", str(target), *args], capture_output=True)
    if r.returncode != 0:
        raise PacketError(f"git {' '.join(args[:2])} 失敗：{r.stderr.decode(errors='replace').strip()[-200:]}")
    return r.stdout


def _git(target: pathlib.Path, *args: str) -> str:
    return _git_bytes(target, *args).decode("utf-8", "replace")


def _names(target: pathlib.Path, *args: str) -> list[str]:
    """-z 輸出的路徑清單：含空白、非 ASCII（core.quotePath 會加引號跳脫）的檔名也原樣取回。"""
    return [n for n in _git_bytes(target, *args, "-z").decode("utf-8", "surrogateescape").split("\0") if n]


def _show(target: pathlib.Path, commit: str, path: str) -> str | None:
    """commit 中檔案的文字內容；不是 UTF-8 文字（二進位檔）→ None，由呼叫端列入略過清單，不讓整個審查包失敗。"""
    data = _git_bytes(target, "show", f"{commit}:{path}")
    if b"\0" in data[:8192]:
        return None
    try:
        return data.decode("utf-8").replace("\r\n", "\n")
    except UnicodeDecodeError:
        return None


def numbered(text: str, ranges: list[tuple[int, int]] | None = None) -> str:
    """每行前綴行號；ranges 有值時只留這些行（以 … 標出略過的區段）。"""
    lines = text.split("\n")
    keep = [(1, len(lines))] if not ranges else ranges
    out, last = [], 0
    for a, b in keep:
        a, b = max(1, a), min(len(lines), b)
        if a > last + 1:
            out.append("  ...| （略過）")
        out += [f"{i:5d}| {lines[i - 1]}" for i in range(a, b + 1)]
        last = b
    if last < len(lines) and ranges:
        out.append("  ...| （略過）")
    return "\n".join(out)


def referenced_files(threat_model: str, tracked: list[str]) -> list[str]:
    """威脅模型以 path:line 引用的檔案（引用可省略目錄，例如 api.py:12），只取受 git 追蹤者。"""
    refs = set(REF.findall(threat_model))
    return sorted({t for r in refs for t in tracked if t == r or t.endswith("/" + r)})


def changed_ranges(target: pathlib.Path, base: str, commit: str) -> dict[str, list[tuple[int, int]]]:
    """diff_base..commit 每個新增／修改檔案的變更行，前後各擴 CONTEXT 行並合併。"""
    names = _names(target, "diff", "--name-only", "--diff-filter=AMR", f"{base}..{commit}")
    out: dict[str, list[tuple[int, int]]] = {}
    for name in names:
        diff = _git(target, "diff", "-U0", f"{base}..{commit}", "--", name)
        spans = []
        for m in HUNK.finditer(diff):
            start, count = int(m.group(1)), int(m.group(2) or 1)
            end = start + max(count, 1) - 1
            spans.append((start - CONTEXT, end + CONTEXT))
        merged: list[tuple[int, int]] = []
        for a, b in sorted(spans):
            if merged and a <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], b))
            else:
                merged.append((a, b))
        if merged:
            out[name] = merged
    return out


def gitleaks_binary() -> str:
    """操作者以 VIBESEC_GITLEAKS 指定 gitleaks，否則取 PATH 上的。只接受解析得到的可執行檔，回傳絕對路徑。"""
    wanted = os.environ.get("VIBESEC_GITLEAKS")
    found = shutil.which(wanted) if wanted else shutil.which("gitleaks")
    if not found:
        where = f"VIBESEC_GITLEAKS={wanted!r} 不是可執行檔" if wanted else "PATH 上找不到 gitleaks"
        raise PacketError(f"{where}：無法確認祕密已遮罩，不產生審查包")
    return str(pathlib.Path(found).resolve())


def gitleaks_scan(texts: dict[str, str]) -> list[str]:
    """回傳命中的祕密字串。gitleaks 缺席或失敗 → PacketError（不產生審查包）。"""
    binary = gitleaks_binary()
    with tempfile.TemporaryDirectory(prefix="vibesec-packet-") as d:
        src = pathlib.Path(d) / "src"
        for name, text in texts.items():
            p = src / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        report = pathlib.Path(d) / "report.json"
        r = subprocess.run([binary, "dir", str(src), "--config", str(ROOT / "config/gitleaks.toml"), "--no-banner",
                            "--report-format", "json", "--report-path", str(report), "--exit-code", "0",
                            "--log-level", "error"], capture_output=True, text=True, timeout=300)
        if r.returncode != 0 or not report.is_file():
            raise PacketError(f"gitleaks 掃描失敗（exit {r.returncode}）：不產生審查包")
        return sorted({h["Secret"] for h in json.loads(report.read_text() or "[]") if h.get("Secret")})


def mask(text: str, secrets: list[str]) -> str:
    for s in sorted(secrets, key=len, reverse=True):
        text = text.replace(s, f"{s[:4]}…{s[-4:]}[masked sha256:{hashlib.sha256(s.encode()).hexdigest()[:12]}]")
    return text


def mask_obj(value, secrets: list[str]):
    """--base 的巢狀內容（發現摘要、證據摘錄）逐一遮罩字串。"""
    if isinstance(value, str):
        return mask(value, secrets)
    if isinstance(value, list):
        return [mask_obj(v, secrets) for v in value]
    if isinstance(value, dict):
        return {mask_obj(k, secrets): mask_obj(v, secrets) for k, v in value.items()}
    return value


def build(base: dict, target: pathlib.Path, commit: str = "HEAD", diff_base: str | None = None,
          threat_model: str = "docs/threat-model.yaml", max_bytes: int = 900_000, scan=gitleaks_scan) -> dict:
    if base.get("data_class") not in DATA_CLASSES:   # review_provider 依此取較嚴格的分級；沒宣告就無法保證不外傳
        raise PacketError(f"--base 必須宣告 data_class（{'／'.join(DATA_CLASSES)}），目前是 {base.get('data_class')!r}")
    sha = _git(target, "rev-parse", f"{commit}^{{commit}}").strip()
    tracked = _names(target, "ls-tree", "-r", "--name-only", sha)
    if threat_model not in tracked:
        raise PacketError(f"{sha[:12]} 沒有威脅模型 {threat_model}")
    tm = _show(target, sha, threat_model)
    if tm is None:
        raise PacketError(f"威脅模型 {threat_model} 不是 UTF-8 文字")
    if diff_base:
        base_sha = _git(target, "rev-parse", f"{diff_base}^{{commit}}").strip()
        ranges = changed_ranges(target, base_sha, sha)
        raw = {name: _show(target, sha, name) for name in ranges}
        scope, note = "diff", f"diff_base {base_sha[:12]}..{sha[:12]} 每個變更 hunk 前後 {CONTEXT} 行"
    else:
        ranges = {}
        raw = {name: _show(target, sha, name) for name in referenced_files(tm, tracked)}
        scope, note = "full", "威脅模型以 path:line 引用的檔案全文"
    skipped = sorted(name for name, text in raw.items() if text is None)   # 二進位檔：模型讀不了，照實列出
    raw = {name: text for name, text in raw.items() if text is not None}
    # --base 也要掃：發現摘要與證據摘錄可能直接引用含祕密的程式行
    secrets = scan({threat_model: tm, BASE_SCAN_NAME: json.dumps(base, ensure_ascii=False, indent=1), **raw})
    files = {name: numbered(mask(text, secrets), ranges.get(name)) for name, text in raw.items()}
    pkt = mask_obj(dict(base), secrets)
    pkt["target"] = {**(base.get("target") or {}), "commit": sha, "scope": scope,
                     "note": "唯讀審查被測專案；只能依本審查包判斷。source_files 是 commit 的原文，每行前綴為行號，引用時用 path:line。"}
    if diff_base:
        pkt["target"]["diff_base"] = base_sha
    pkt["threat_model_full"] = numbered(mask(tm, secrets))
    pkt["source_files"] = files
    pkt["source_files_note"] = (f"{note}（docs/09 §6）。只附上列檔案，不送整個 repo。"
                                f"gitleaks 命中 {len(secrets)} 個字串，已遮罩為前 4 後 4 加 sha256 指紋。"
                                + (f"略過 {len(skipped)} 個非文字檔（未附上，模型沒看到）：{'、'.join(skipped)}。" if skipped else ""))
    size = len(json.dumps(pkt, ensure_ascii=False).encode())
    if size > max_bytes:
        raise PacketError(f"審查包 {size} bytes 超過上限 {max_bytes}：不截斷、不產生（改用 --diff-base 或提高上限）")
    for s in secrets:   # 遮罩後不得殘留原文
        if s in json.dumps(pkt, ensure_ascii=False):
            raise PacketError("遮罩後仍殘留命中字串：不產生審查包")
    return pkt


# ------------------------------------------------------------------ selftest
def selftest() -> list[str]:
    fails: list[str] = []
    git = lambda d, *a: subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *a], cwd=d,
                                       capture_output=True, check=True, text=True)
    planted = "sk-" + "Z9" * 20
    with tempfile.TemporaryDirectory() as d:
        repo = pathlib.Path(d)
        git(repo, "init", "-q")
        (repo / "docs").mkdir(); (repo / "app").mkdir()
        (repo / "docs/threat-model.yaml").write_text("threats:\n  - ref: app/api.py:2\n  - ref: util.py:1\n  - ref: logo.png:1\n  - ref: app/my notes.py:1\n")
        (repo / "app/api.py").write_text("\n".join(f"line{i}" for i in range(1, 121)) + "\n")
        (repo / "app/util.py").write_text(f"KEY = '{planted}'\n")
        (repo / "app/unref.py").write_text("print('not referenced')\n")
        (repo / "app/my notes.py").write_text("x = 1\n"); (repo / "app/logo.png").write_bytes(b"\x89PNG\0\0\xff")
        git(repo, "add", "-A"); git(repo, "commit", "-qm", "base")
        first = git(repo, "rev-parse", "HEAD").stdout.strip()
        lines = (repo / "app/api.py").read_text().split("\n"); lines[99] = "changed100"
        (repo / "app/api.py").write_text("\n".join(lines))
        git(repo, "commit", "-qam", "change")
        fake = lambda texts: [planted] if any(planted in t for t in texts.values()) else []
        base = {"data_class": "internal", "target": {"repo": "x"}, "output": "…"}
        pkt = build(base, repo, scan=fake)
        if "app/my notes.py" not in _names(repo, "ls-tree", "-r", "--name-only", "HEAD"):
            fails.append("含空白的檔名要原樣列出（以前 .split() 會拆成兩個不存在的路徑）")
        if "app/logo.png" in pkt["source_files"] or "app/logo.png" not in pkt["source_files_note"]:
            fails.append("二進位檔不附上，但要在 source_files_note 列出（不讓整個審查包失敗）")
        if set(pkt["source_files"]) != {"app/api.py", "app/util.py"}:
            fails.append(f"full：只附威脅模型引用的檔案（含省略目錄的引用）：{sorted(pkt['source_files'])}")
        if planted in json.dumps(pkt) or "[masked sha256:" not in pkt["source_files"]["app/util.py"]:
            fails.append("命中的祕密必須遮罩")
        if "    2| line2" not in pkt["source_files"]["app/api.py"] or pkt["target"]["scope"] != "full":
            fails.append("full：附行號全文")
        if pkt["data_class"] != "internal" or pkt["output"] != "…":
            fails.append("其餘欄位沿用 --base")
        pkt = build(base, repo, diff_base=first, scan=fake)
        api = pkt["source_files"].get("app/api.py", "")
        if set(pkt["source_files"]) != {"app/api.py"} or "  100| changed100" not in api or "   60| line60" not in api \
                or "   59| line59" in api or "（略過）" not in api or pkt["target"]["scope"] != "diff":
            fails.append(f"diff：只附變更 hunk 前後 {CONTEXT} 行")
        try:
            build(base, repo, max_bytes=100, scan=fake); fails.append("超過上限必須拒絕，不截斷")
        except PacketError:
            pass
        leaky = {**base, "finding": {"evidence": f"app/util.py:1 KEY = '{planted}'"}}   # 發現摘錄直接引用祕密
        pkt = build(leaky, repo, scan=fake)
        if planted in json.dumps(pkt) or "[masked sha256:" not in pkt["finding"]["evidence"]:
            fails.append("--base 內容（發現與證據摘錄）也必須掃描遮罩")
        for bad_class in (None, "secret"):
            try:
                build({**base, "data_class": bad_class}, repo, scan=fake); fails.append(f"--base data_class={bad_class!r} 必須拒絕")
            except PacketError:
                pass
        def broken(texts): raise PacketError("gitleaks 掃描失敗")
        try:
            build(base, repo, scan=broken); fails.append("掃描失敗必須拒絕產生")
        except PacketError:
            pass
        try:
            build(base, repo, threat_model="docs/missing.yaml", scan=fake); fails.append("缺威脅模型必須拒絕")
        except PacketError:
            pass
        old = os.environ.pop("VIBESEC_GITLEAKS", None); path = os.environ.get("PATH", "")
        os.environ["PATH"] = ""
        try:
            gitleaks_scan({"a": "b"}); fails.append("缺 gitleaks 必須拒絕產生")
        except PacketError:
            pass
        not_exec = pathlib.Path(d) / "not-executable"
        not_exec.write_text("#!/bin/sh\nexit 0\n")
        not_exec.chmod(0o644)
        try:
            for bogus in (str(not_exec), str(pathlib.Path(d) / "missing")):
                os.environ["VIBESEC_GITLEAKS"] = bogus
                try:
                    gitleaks_binary(); fails.append(f"VIBESEC_GITLEAKS 指向非可執行檔必須拒絕：{bogus}")
                except PacketError:
                    pass
        finally:
            os.environ.pop("VIBESEC_GITLEAKS", None)
            os.environ["PATH"] = path
            if old is not None:
                os.environ["VIBESEC_GITLEAKS"] = old
    return fails


def main(argv: list[str]) -> int:
    if argv[:1] == ["selftest"]:
        fails = selftest()
        for f in fails:
            print(f"FAIL {f}")
        print("selftest " + ("通過" if not fails else f"失敗 {len(fails)} 項"))
        return 1 if fails else 0
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("cmd", choices=["build"])
    ap.add_argument("--base", required=True, help="harness 產出的審查包（不含程式碼）")
    ap.add_argument("--target", required=True, help="被測專案的 git repo 根目錄")
    ap.add_argument("--commit", default="HEAD")
    ap.add_argument("--diff-base", help="給定時只附 diff_base..commit 的變更 hunk 前後 40 行")
    ap.add_argument("--threat-model", default="docs/threat-model.yaml")
    ap.add_argument("--max-bytes", type=int, default=900_000)
    ap.add_argument("--out", required=True)
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        return 4
    try:
        base = json.loads(pathlib.Path(a.base).read_text(encoding="utf-8"))
        pkt = build(base, pathlib.Path(a.target), a.commit, a.diff_base, a.threat_model, a.max_bytes)
    except (PacketError, OSError, json.JSONDecodeError, subprocess.TimeoutExpired) as e:
        print(f"無法產生審查包：{e}", file=sys.stderr)
        return 2
    pathlib.Path(a.out).write_text(json.dumps(pkt, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"審查包 {a.out}：{pkt['target']['scope']}，{len(pkt['source_files'])} 個檔案，"
          f"{len(json.dumps(pkt, ensure_ascii=False).encode())} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
