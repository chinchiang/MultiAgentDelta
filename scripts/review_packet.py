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
  - 送出前以 gitleaks（本 repo 的 config/gitleaks-packet.toml：與 config/gitleaks.toml 同一套規則，但沒有任何 allowlist）
    掃描要附上的內容，命中的字串一律換成遮罩加 sha256 指紋
    （至少遮住 8 個字元：16 字元以上留前 4 後 4，較短的少留或全遮）。被測程式碼的 `gitleaks:allow` 註解不採信
    （--ignore-gitleaks-allow）：那是被測專案自己寫的，不能決定祕密要不要送出去。
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
# 遮罩專用設定：G2 的 config/gitleaks.toml 有全域 allowlist（lock 檔路徑、sample／canary 等 stopwords、${VAR} 樣式）
# 與規則層 allowlist（example、synthetic…），套在遮罩上，外部專案這類位置或字樣的真祕密就不遮、明文送雲端（規則 7）
MASK_CONFIG = ROOT / "config/gitleaks-packet.toml"
G2_CONFIG = ROOT / "config/gitleaks.toml"
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


def gitleaks_scan(texts: dict[str, str], config: pathlib.Path = MASK_CONFIG) -> list[str]:
    """回傳命中的祕密字串。gitleaks 缺席或失敗 → PacketError（不產生審查包）。"""
    binary = gitleaks_binary()
    with tempfile.TemporaryDirectory(prefix="vibesec-packet-") as d:
        src = pathlib.Path(d) / "src"
        # 以中性檔名（序號＋原副檔名）寫出：gitleaks 內建預設設定（useDefault）自帶的全域路徑 allowlist
        # （package-lock.json、go.sum…）無法在設定檔移除，原路徑照寫，那些檔裡的祕密就不遮。遮罩只需要命中字串、不需要路徑。
        src.mkdir(parents=True)
        for i, (name, text) in enumerate(texts.items()):
            (src / f"{i:04d}{pathlib.PurePosixPath(name).suffix}").write_text(text, encoding="utf-8")
        report = pathlib.Path(d) / "report.json"
        # --ignore-gitleaks-allow：受測程式碼寫 `# gitleaks:allow` 就能讓金鑰不被遮罩、明文送雲端（同 g2_secrets 掃外部目標）
        r = subprocess.run([binary, "dir", str(src), "--config", str(config), "--no-banner",
                            "--report-format", "json", "--report-path", str(report), "--exit-code", "0",
                            "--ignore-gitleaks-allow", "--log-level", "error"], capture_output=True, text=True, timeout=300)
        if r.returncode != 0 or not report.is_file():
            raise PacketError(f"gitleaks 掃描失敗（exit {r.returncode}）：不產生審查包")
        return sorted({h["Secret"] for h in json.loads(report.read_text() or "[]") if h.get("Secret")})


def mask(text: str, hits: list[str]) -> str:
    """命中字串換成遮罩加 sha256 指紋。至少遮住 8 個字元：以前一律留前 4 後 4，8 字元的密碼等於全文照抄。"""
    for s in sorted(hits, key=len, reverse=True):
        k = min(4, max(0, (len(s) - 8) // 2))
        shown = f"{s[:k]}…{s[-k:]}" if k else "…"
        text = text.replace(s, f"{shown}[masked sha256:{hashlib.sha256(s.encode()).hexdigest()[:12]}]")
    return text


def mask_obj(value, hits: list[str]):
    """--base 的巢狀內容（發現摘要、證據摘錄）逐一遮罩字串。"""
    if isinstance(value, str):
        return mask(value, hits)
    if isinstance(value, list):
        return [mask_obj(v, hits) for v in value]
    if isinstance(value, dict):
        return {mask_obj(k, hits): mask_obj(v, hits) for k, v in value.items()}
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
    hits = scan({threat_model: tm, BASE_SCAN_NAME: json.dumps(base, ensure_ascii=False, indent=1), **raw})
    files = {name: numbered(mask(text, hits), ranges.get(name)) for name, text in raw.items()}
    pkt = mask_obj(dict(base), hits)
    pkt["target"] = {**(base.get("target") or {}), "commit": sha, "scope": scope,
                     "note": "唯讀審查被測專案；只能依本審查包判斷。source_files 是 commit 的原文，每行前綴為行號，引用時用 path:line。"}
    if diff_base:
        pkt["target"]["diff_base"] = base_sha
    pkt["threat_model_full"] = numbered(mask(tm, hits))
    pkt["source_files"] = files
    pkt["source_files_note"] = (f"{note}（docs/09 §6）。只附上列檔案，不送整個 repo。"
                                f"gitleaks 命中 {len(hits)} 個字串，已遮罩並附 sha256 指紋。"
                                + (f"略過 {len(skipped)} 個非文字檔（未附上，模型沒看到）：{'、'.join(skipped)}。" if skipped else ""))
    size = len(json.dumps(pkt, ensure_ascii=False).encode())
    if size > max_bytes:
        raise PacketError(f"審查包 {size} bytes 超過上限 {max_bytes}：不截斷、不產生（改用 --diff-base 或提高上限）")
    for s in hits:   # 遮罩後不得殘留原文
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
        # 遮罩至少遮住 8 個字元：以前一律留前 4 後 4，8 字元的祕密原樣保留、9–11 字元只遮 1–3 個
        # 失敗訊息只報字元數，不印遮罩結果：遮罩失敗時其中就含祕密（規則 7；CodeQL py/clear-text-logging-sensitive-data）
        for sample in ("hunter22", "abcdefghi", "abcdefghijk1", "sk-" + "Q7" * 20):
            masked = mask(f"pw={sample}", [sample])
            n_shown = len(masked[3:].split("[masked sha256:")[0].replace("…", ""))
            n_total = len(sample)
            if sample in masked or n_shown > n_total - 8:
                fails.append(f"{n_total} 字元的祕密遮罩後露出 {n_shown} 字元（至少要遮住 8 個）")
        if not mask("k=" + "sk-" + "Q7" * 20, ["sk-" + "Q7" * 20]).startswith("k=sk-Q…Q7Q7[masked sha256:"):
            fails.append("16 字元以上的祕密維持前 4 後 4 加指紋")
        # gitleaks:allow 不採信：假 gitleaks 模擬真實行為（有 allow 註解時不回報，除非帶 --ignore-gitleaks-allow）
        allowed = "sk-" + "A1" * 20
        (repo / "app/util.py").write_text(f"KEY = '{allowed}'  # gitleaks:allow\n")
        git(repo, "commit", "-qam", "allow-comment")
        fake_bin = pathlib.Path(d) / "fake-gitleaks"
        fake_bin.write_text("#!/bin/sh\n"
                            "report=; prev=; allow=0\n"
                            "for a in \"$@\"; do [ \"$prev\" = --report-path ] && report=$a; "
                            "[ \"$a\" = --ignore-gitleaks-allow ] && allow=1; prev=$a; done\n"
                            f"if [ $allow = 1 ]; then echo '[{{\"Secret\": \"{allowed}\"}}]' > \"$report\"; "
                            "else echo '[]' > \"$report\"; fi\n")
        fake_bin.chmod(0o755)
        old = os.environ.get("VIBESEC_GITLEAKS")
        os.environ["VIBESEC_GITLEAKS"] = str(fake_bin)
        try:
            pkt = build(base, repo)
            if allowed in json.dumps(pkt) or "[masked sha256:" not in pkt["source_files"].get("app/util.py", ""):
                fails.append("被測程式碼的 gitleaks:allow 註解不得讓祕密免遮罩（gitleaks 須帶 --ignore-gitleaks-allow）")
        finally:
            os.environ.pop("VIBESEC_GITLEAKS", None)
            if old is not None:
                os.environ["VIBESEC_GITLEAKS"] = old
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
        # 遮罩用的 gitleaks 呼叫：設定是 gitleaks-packet.toml（不是 G2 的 gitleaks.toml），暫存檔以中性檔名寫出
        # （原路徑會被內建預設的路徑 allowlist 排除，例如 package-lock.json）。假 gitleaks 記下參數與掃描目錄的檔名。
        log = pathlib.Path(d) / "fake-gitleaks.log"
        spy = pathlib.Path(d) / "spy-gitleaks"
        spy.write_text("#!/bin/sh\n"
                       "report=; prev=; src=; cfg=\n"
                       "for a in \"$@\"; do [ \"$prev\" = --report-path ] && report=$a; [ \"$prev\" = --config ] && cfg=$a; "
                       "[ \"$prev\" = dir ] && src=$a; prev=$a; done\n"
                       f"echo \"config=$cfg\" > '{log}'; (cd \"$src\" && find . -type f) >> '{log}'\n"
                       "echo '[]' > \"$report\"\n")
        spy.chmod(0o755)
        old = os.environ.get("VIBESEC_GITLEAKS")
        os.environ["VIBESEC_GITLEAKS"] = str(spy)
        try:
            gitleaks_scan({"web/package-lock.json": "x", "docs/a.md": "y", BASE_SCAN_NAME: "{}"})
            seen = log.read_text().split("\n")
            if seen[0] != f"config={MASK_CONFIG}":
                fails.append(f"遮罩須用 {MASK_CONFIG.name}，不得用 G2 有 allowlist 的設定（得到 {seen[0]}）")
            names = sorted(n for n in seen[1:] if n)
            if names != ["./0000.json", "./0001.md", "./0002.json"]:
                fails.append(f"暫存檔應以序號＋副檔名命名，不保留原路徑（得到 {names}）")
        finally:
            os.environ.pop("VIBESEC_GITLEAKS", None)
            if old is not None:
                os.environ["VIBESEC_GITLEAKS"] = old

    # 遮罩設定：沒有任何 allowlist，偵測規則與 G2 的 config/gitleaks.toml 一致（改規則時兩檔要一起改）
    import tomllib
    mask_cfg = tomllib.loads(MASK_CONFIG.read_text(encoding="utf-8"))
    g2_cfg = tomllib.loads(G2_CONFIG.read_text(encoding="utf-8"))
    if {"allowlist", "allowlists"} & set(mask_cfg) or any("allowlist" in r or "allowlists" in r for r in mask_cfg.get("rules", [])):
        fails.append(f"{MASK_CONFIG.name} 不得有全域或規則層 allowlist")
    strip = lambda r: {k: v for k, v in r.items() if k not in ("allowlist", "allowlists")}
    if mask_cfg.get("rules") != [strip(r) for r in g2_cfg.get("rules", [])] or mask_cfg.get("extend") != g2_cfg.get("extend"):
        fails.append(f"{MASK_CONFIG.name} 的規則與 [extend] 須與 {G2_CONFIG.name} 一致（去掉 allowlist 後）")

    # 真 gitleaks（VIBESEC_GITLEAKS 或 PATH 上有才跑）：G2 allowlist 會放過的位置與字樣，遮罩時都要命中
    try:
        gitleaks_binary()
    except PacketError:
        print("（略過真 gitleaks 遮罩測試：找不到 gitleaks；設定與呼叫方式已由上方離線測試驗證）", file=sys.stderr)
    else:
        key = "sk-" + "Q7wLm2Xr9Tz4Kb8Np3Vd6Hs1Jf5Gc0Ya"
        pw = "Xk9mQ2vL7pR4tW8zN3bF6hJ1"
        for name, text, secret in [
            ("uv.lock", f"OPENAI_API_KEY = '{key}'\n", key),                       # G2 全域 paths
            ("web/package-lock.json", f'{{"token": "{key}"}}\n', key),            # gitleaks 內建預設的路徑 allowlist
            ("app/a.py", f"api_key = 'sample{key[3:]}'\n", "sample" + key[3:]),   # G2 全域 stopwords
            ("app/d.py", f"password = 'canary{pw}'\n", "canary" + pw),
            ("app/g.py", f"JWT_SECRET = 'example{pw}'\n", "example" + pw),        # G2 規則層 allowlist
        ]:
            try:
                got = gitleaks_scan({name: text})
            except PacketError as e:
                fails.append(f"真 gitleaks 掃描失敗（{name}）：{e}")
                continue
            if secret not in got:   # 只報檔名：失敗訊息不印祕密（規則 7）
                fails.append(f"G2 allowlist 會放過的祕密（{name}）遮罩時必須命中")
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
