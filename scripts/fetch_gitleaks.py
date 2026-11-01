#!/usr/bin/env python3
"""VibeSec：照 nightly workflow 釘選的版本與 SHA-256 取得本機 gitleaks，驗證後快取（#241）。

workflow 文件第 7 步要求推送前跑本機 gitleaks，版本與 SHA-256 必須和 nightly 的 GITLEAKS_VERSION、GITLEAKS_SHA256 相同。

用法：
  VIBESEC_GITLEAKS="$(python3 -I scripts/fetch_gitleaks.py)"   # stdout 只印 binary 的絕對路徑；其他訊息在 stderr
  python3 scripts/fetch_gitleaks.py selftest
退出碼：0 成功；2 無法取得（incomplete ≠ pass）。
"""
from __future__ import annotations
import hashlib, os, pathlib, re, stat, sys, tarfile, tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
NIGHTLY = ROOT / ".github/workflows/nightly-full.yml"
# 與 nightly 相同的 release 資產；pinned() 核對 nightly 的下載網址也是這個範本，nightly 換資產時退出碼 2（不默默不一致）
URL = "https://github.com/gitleaks/gitleaks/releases/download/v{v}/gitleaks_{v}_linux_x64.tar.gz"
MAX_BYTES = 64 * 1024 * 1024   # 下載上限（8.28.0 的 tarball 約 7 MB）：異常回應不得塞爆磁碟


class FetchProblem(Exception):
    """無法取得經驗證的 gitleaks：退出碼 2，不留下未驗證的檔案。"""


def pinned(workflow_text: str) -> tuple[str, str]:
    """nightly workflow 的 (GITLEAKS_VERSION, GITLEAKS_SHA256)。workflow 內每一處釘選都必須相同，否則 FetchProblem
    （不默默挑其中一份）；缺席或格式不對同樣 FetchProblem。"""
    versions = set(re.findall(r'^\s*GITLEAKS_VERSION:\s*"?([^"\s#]+)"?', workflow_text, re.M))
    hashes = set(re.findall(r'^\s*GITLEAKS_SHA256:\s*"?([^"\s#]+)"?', workflow_text, re.M))
    urls = set(re.findall(r'"?(https://github\.com/gitleaks/gitleaks/releases/download/[^"\s]+)"?', workflow_text))
    want_url = URL.format(v="${GITLEAKS_VERSION}")
    if urls != {want_url}:
        raise FetchProblem(f"nightly 的 gitleaks 下載網址和本腳本不同（nightly：{sorted(urls)}；本腳本：{want_url}）")
    if len(versions) != 1 or len(hashes) != 1:
        raise FetchProblem(f"nightly workflow 的 gitleaks 釘選值不是唯一一組（版本 {sorted(versions)}、雜湊 {len(hashes)} 種）")
    (version,), (sha,) = versions, hashes
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise FetchProblem(f"GITLEAKS_VERSION 格式不對：{version!r}")
    if not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise FetchProblem("GITLEAKS_SHA256 不是 64 個小寫 hex")
    return version, sha


def https_download(url: str, dest: pathlib.Path, *, opener=None, max_bytes: int = MAX_BYTES) -> None:
    """以 HTTPS 下載到 dest，超過 max_bytes 即停（OSError）。GitHub release 會轉址到 objects.githubusercontent.com，
    轉址後仍須是 HTTPS。opener 只給 selftest 注入。"""
    if not url.startswith("https://"):
        raise OSError(f"只接受 HTTPS：{url}")
    if opener is None:
        import urllib.request
        opener = urllib.request.urlopen
    with opener(url, timeout=60) as r:
        if not r.geturl().startswith("https://"):
            raise OSError(f"轉址到非 HTTPS：{r.geturl()}")
        size = 0
        with open(dest, "wb") as f:
            while chunk := r.read(1 << 16):
                size += len(chunk)
                if size > max_bytes:
                    raise OSError(f"下載超過 {max_bytes} bytes，視為異常回應")
                f.write(chunk)


def _sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def _private_dir(path: pathlib.Path) -> pathlib.Path:
    """建立（只有擁有者可存取）或確認 path：必須是自己擁有的目錄、group／other 不可寫，否則 FetchProblem
    （別人可寫的快取目錄可能被預先放進任意 binary 與「正確」的驗證紀錄）。"""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o022:
        raise FetchProblem(f"快取目錄 {path} 不是自己擁有、或 group／other 可寫，不採信")
    return path


def ensure(version: str, sha256: str, *, cache_root: pathlib.Path, download) -> pathlib.Path:
    """<cache_root>/gitleaks-<版本>/gitleaks 的絕對路徑。
    快取命中：快取目錄是自己擁有且 group／other 不可寫、binary 可執行、驗證紀錄寫的 tarball 雜湊＝sha256，
    而且**重新計算的 binary 雜湊＝紀錄裡的 binary 雜湊**（紀錄本身是公開值，不能只看它）。否則先刪過期的 binary，
    以 download(url, dest) 下載到快取目錄內的暫存檔，tarball 的 SHA-256 相符才打開，只取名為 gitleaks 的一般檔案
    （不接受符號連結、子目錄或路徑穿越）。任何失敗 → FetchProblem，不留暫存檔、也不留未驗證的 binary。"""
    root = _private_dir(pathlib.Path(cache_root))
    target = _private_dir(root / f"gitleaks-{version}")
    binary, marker = target / "gitleaks", target / "tarball.sha256"
    try:
        recorded = marker.read_text(encoding="utf-8").split()
    except OSError:
        recorded = []
    if len(recorded) == 2 and recorded[0] == sha256 and binary.is_file() and not binary.is_symlink() \
            and os.access(binary, os.X_OK) and _sha256(binary) == recorded[1]:
        return binary.resolve()
    for stale in (binary, marker):   # 過期或被改過的 binary 不沿用：先刪，下載失敗時也不會留著被誤用
        stale.unlink(missing_ok=True)
    fd, name = tempfile.mkstemp(dir=target, prefix=".download-", suffix=".tar.gz")
    os.close(fd)
    fd, part_name = tempfile.mkstemp(dir=target, prefix=".gitleaks-", suffix=".part")
    os.close(fd)
    tmp, part = pathlib.Path(name), pathlib.Path(part_name)
    try:
        try:
            download(URL.format(v=version), tmp)
        except OSError as e:
            raise FetchProblem(f"下載失敗：{e}") from e
        if _sha256(tmp) != sha256:
            raise FetchProblem("下載的 tarball 和 nightly 釘選的 SHA-256 不符，不解壓縮")
        try:
            with tarfile.open(tmp, "r:gz") as tf:
                member = next((m for m in tf.getmembers() if m.name == "gitleaks"), None)
                if member is None or not member.isreg():
                    raise FetchProblem("tarball 裡沒有名為 gitleaks 的一般檔案")
                data = tf.extractfile(member).read()
        except tarfile.TarError as e:
            raise FetchProblem(f"tarball 無法解析：{type(e).__name__}") from e
        part.write_bytes(data)
        part.chmod(0o700)
        part.replace(binary)
        marker.write_text(f"{sha256} {hashlib.sha256(data).hexdigest()}\n", encoding="utf-8")
        return binary.resolve()
    finally:
        tmp.unlink(missing_ok=True)
        part.unlink(missing_ok=True)


def selftest() -> list[str]:
    fails: list[str] = []

    def check(name, fn):
        """fn 回傳 None 表示通過；回傳字串或拋例外表示失敗。"""
        try:
            why = fn()
        except Exception as e:
            why = f"{type(e).__name__}：{e}"
        if why:
            fails.append(f"{name}：{why}")

    def raises(fn) -> str | None:
        try:
            fn()
        except FetchProblem as e:
            return str(e) or "（無訊息）"
        return None

    SHA = "ab" * 32   # 64 個 hex；只當測試資料，不是任何 binary 的真實雜湊
    NIGHTLY_URL = ('            "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/'
                   'gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"\n')
    job = lambda v, s, url=NIGHTLY_URL: (f'      - name: x\n        env:\n          GITLEAKS_VERSION: "{v}"\n'
                                         f'          GITLEAKS_SHA256: {s}\n        run: |\n          curl -o x \\\n{url}')

    def t_pinned():
        if pinned(job("8.28.0", SHA) + job("8.28.0", SHA)) != ("8.28.0", SHA):
            return "兩個 job 釘選相同 → 回傳 (版本, 雜湊)"
        for label, text in [("缺版本", f"          GITLEAKS_SHA256: {SHA}\n"),
                            ("缺雜湊", '          GITLEAKS_VERSION: "8.28.0"\n'),
                            ("兩個 job 版本不同", job("8.28.0", SHA) + job("8.29.0", SHA)),
                            ("兩個 job 雜湊不同", job("8.28.0", SHA) + job("8.28.0", "cd" * 32)),
                            ("版本格式不對", job("latest", SHA)),
                            ("雜湊格式不對", job("8.28.0", "abc")),
                            ("nightly 換了下載資產", job("8.28.0", SHA, NIGHTLY_URL.replace("linux_x64", "linux_arm64"))),
                            ("nightly 沒有下載網址", job("8.28.0", SHA, ""))]:
            if not raises(lambda text=text: pinned(text)):
                return f"{label} → FetchProblem（不可默默挑一份或退回預設）"
    check("pinned：從 nightly workflow 讀出唯一一組釘選值", t_pinned)

    # ---- ensure：下載函式與快取根目錄都注入；fixture tarball 在暫存目錄現建，不連網
    import io

    def tarball(members) -> bytes:
        """members：(名稱, 內容 bytes 或 None＝符號連結) 的清單。"""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for name, data in members:
                info = tarfile.TarInfo(name)
                if data is None:
                    info.type, info.linkname = tarfile.SYMTYPE, "/bin/sh"
                    tf.addfile(info)
                else:
                    info.size, info.mode = len(data), 0o644
                    tf.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    GOOD = tarball([("README.md", b"x"), ("gitleaks", b"#!/bin/sh\necho 8.28.0\n")])
    GOOD_SHA = hashlib.sha256(GOOD).hexdigest()

    def downloader(data, calls):
        def download(url, dest):
            calls.append(url)
            if isinstance(data, Exception):
                raise data
            pathlib.Path(dest).write_bytes(data)
        return download

    def leftovers(root):   # 快取根目錄裡除了 binary 與驗證紀錄以外的檔案（暫存檔不得留下）
        return sorted(str(q.relative_to(root)) for q in pathlib.Path(root).rglob("*") if q.is_file()
                      and q.name not in ("gitleaks", "tarball.sha256"))

    def t_ensure_cache():
        with tempfile.TemporaryDirectory() as d:
            calls = []
            b1 = ensure("8.28.0", GOOD_SHA, cache_root=pathlib.Path(d), download=downloader(GOOD, calls))
            if calls != [URL.format(v="8.28.0")] or not b1.is_absolute() or b1.read_bytes() != b"#!/bin/sh\necho 8.28.0\n" \
                    or not b1.stat().st_mode & 0o111 or "8.28.0" not in str(b1):
                return f"第一次 → 下載 nightly 同一個資產、驗證後解出可執行的 binary（得到 {calls}、{b1}）"
            b2 = ensure("8.28.0", GOOD_SHA, cache_root=pathlib.Path(d), download=downloader(GOOD, calls))
            if b2 != b1 or len(calls) != 1 or leftovers(d):
                return f"第二次 → 快取命中、不再下載、不留暫存檔（得到 {len(calls)} 次下載、{leftovers(d)}）"
    check("ensure：下載、驗證、快取命中", t_ensure_cache)

    def t_ensure_reject():
        for label, data, sha in [("雜湊不符", GOOD, "cd" * 32),
                                 ("tarball 裡沒有 gitleaks", tarball([("README.md", b"x")]), None),
                                 ("gitleaks 是符號連結", tarball([("gitleaks", None)]), None),
                                 ("gitleaks 在子目錄（路徑穿越）", tarball([("../gitleaks", b"x")]), None),
                                 ("下載失敗", OSError("connection reset"), GOOD_SHA)]:
            with tempfile.TemporaryDirectory() as d:
                want_sha = sha or (hashlib.sha256(data).hexdigest() if isinstance(data, bytes) else GOOD_SHA)
                why = raises(lambda: ensure("8.28.0", want_sha, cache_root=pathlib.Path(d), download=downloader(data, [])))
                binaries = [str(q) for q in pathlib.Path(d).rglob("gitleaks")]
                if not why or binaries or leftovers(d):
                    return f"{label} → FetchProblem，不留 binary 與暫存檔（得到 {why}、{binaries}、{leftovers(d)}）"

    check("ensure：雜湊不符、缺 binary、不安全的成員、下載失敗都拒絕且不留檔", t_ensure_reject)

    def t_ensure_stale_cache():   # 快取裡的 binary 是別的雜湊驗證過的 → 重新下載，不沿用
        with tempfile.TemporaryDirectory() as d:
            ensure("8.28.0", GOOD_SHA, cache_root=pathlib.Path(d), download=downloader(GOOD, []))
            other = tarball([("gitleaks", b"#!/bin/sh\necho other\n")])
            calls = []
            b = ensure("8.28.0", hashlib.sha256(other).hexdigest(), cache_root=pathlib.Path(d), download=downloader(other, calls))
            if len(calls) != 1 or b.read_bytes() != b"#!/bin/sh\necho other\n":
                return f"驗證紀錄和釘選雜湊不同 → 重新下載並換成新 binary（得到 {len(calls)} 次下載）"
        with tempfile.TemporaryDirectory() as d:   # 重新下載失敗時，別的雜湊驗證過的舊 binary 也不能留著被誤用
            ensure("8.28.0", GOOD_SHA, cache_root=pathlib.Path(d), download=downloader(GOOD, []))
            why = raises(lambda: ensure("8.28.0", "cd" * 32, cache_root=pathlib.Path(d), download=downloader(OSError("down"), [])))
            if not why or list(pathlib.Path(d).rglob("gitleaks")):
                return f"重新下載失敗 → FetchProblem，舊 binary 已刪除（得到 {why}、{list(pathlib.Path(d).rglob('gitleaks'))}）"
    check("ensure：快取的驗證紀錄和釘選雜湊不同時重新下載", t_ensure_stale_cache)

    def t_ensure_tampered():   # 驗證紀錄是公開值：快取命中要重新核對 binary 本身，被換掉就重新下載
        with tempfile.TemporaryDirectory() as d:
            b = ensure("8.28.0", GOOD_SHA, cache_root=pathlib.Path(d), download=downloader(GOOD, []))
            b.write_bytes(b"#!/bin/sh\necho evil\n")
            calls = []
            b2 = ensure("8.28.0", GOOD_SHA, cache_root=pathlib.Path(d), download=downloader(GOOD, calls))
            if len(calls) != 1 or b2.read_bytes() != b"#!/bin/sh\necho 8.28.0\n":
                return f"binary 被換掉（紀錄沒變）→ 不沿用、重新下載（得到 {len(calls)} 次下載、{b2.read_bytes()!r}）"
    check("ensure：快取命中時重新核對 binary 本身", t_ensure_tampered)

    def t_ensure_unsafe_dir():   # 別人可寫或不屬於自己的快取目錄不採信（可能被預先放進任意 binary）
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            ensure("8.28.0", GOOD_SHA, cache_root=root, download=downloader(GOOD, []))
            target = root / "gitleaks-8.28.0"
            if target.stat().st_mode & 0o077:
                return f"新建的快取目錄只有擁有者能存取（得到 {oct(target.stat().st_mode & 0o777)}）"
            target.chmod(0o777)
            if not raises(lambda: ensure("8.28.0", GOOD_SHA, cache_root=root, download=downloader(GOOD, []))):
                return "快取目錄 group／other 可寫 → FetchProblem"
            target.chmod(0o700); root.chmod(0o777)
            if not raises(lambda: ensure("8.28.0", GOOD_SHA, cache_root=root, download=downloader(GOOD, []))):
                return "快取根目錄 group／other 可寫 → FetchProblem"
            root.chmod(0o700)
    check("ensure：拒絕別人可寫的快取目錄", t_ensure_unsafe_dir)

    def t_download_limit():   # 下載有大小上限、轉址後須是 HTTPS（比照 fetch_kev 的 MAX_BYTES）
        class Resp(io.BytesIO):
            def __init__(self, data, url): super().__init__(data); self._url = url
            def geturl(self): return self._url
            def __enter__(self): return self
            def __exit__(self, *a): self.close()
        with tempfile.TemporaryDirectory() as d:
            dest = pathlib.Path(d, "x")
            for label, data, final, limit, ok in [("正常", b"abc", "https://objects.example/x", 10, True),
                                                   ("超過上限", b"x" * 11, "https://objects.example/x", 10, False),
                                                   ("轉址到 HTTP", b"abc", "http://objects.example/x", 10, False)]:
                try:
                    https_download("https://github.com/x", dest, opener=lambda url, timeout: Resp(data, final), max_bytes=limit)
                    got = True
                except OSError:
                    got = False
                if got != ok:
                    return f"{label} → {'成功' if ok else 'OSError'}（得到 {'成功' if got else 'OSError'}）"
            try:
                https_download("http://github.com/x", dest, opener=lambda url, timeout: Resp(b"", url)); return "非 HTTPS 網址 → OSError"
            except OSError:
                pass
    check("https_download：大小上限與 HTTPS", t_download_limit)

    # ---- main：stdout 只印 binary 路徑，其餘在 stderr；無法取得 → 退出碼 2
    import contextlib

    def run_main(*, workflow_text, platform=("linux", "x86_64"), data=GOOD, missing_workflow=False):
        with tempfile.TemporaryDirectory() as d:
            wf = pathlib.Path(d, "nightly.yml")
            if not missing_workflow:
                wf.write_text(workflow_text, encoding="utf-8")
            out, err, calls = io.StringIO(), io.StringIO(), []
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = main([], workflow=wf, environ={"XDG_CACHE_HOME": str(pathlib.Path(d, "cache")), "HOME": d},
                          platform=platform, download=downloader(data, calls))
            return rc, out.getvalue(), err.getvalue(), calls, d

    def t_main_ok():
        rc, out, err, calls, d = run_main(workflow_text=job("8.28.0", GOOD_SHA))
        want = str(pathlib.Path(d, "cache", "vibesec", "gitleaks-8.28.0", "gitleaks").resolve())
        if rc != 0 or out != want + "\n" or len(calls) != 1:
            return f"成功 → 退出碼 0、stdout 只有 $XDG_CACHE_HOME/vibesec/gitleaks-<版本>/gitleaks 的路徑（得到 {rc}、{out!r}、{err!r}）"
    check("main：成功時 stdout 只印 binary 路徑", t_main_ok)

    def t_main_problems():
        for label, kw in [("nightly workflow 讀不到", {"workflow_text": "", "missing_workflow": True}),
                          ("釘選值不唯一", {"workflow_text": job("8.28.0", GOOD_SHA) + job("8.29.0", GOOD_SHA)}),
                          ("雜湊不符", {"workflow_text": job("8.28.0", "cd" * 32)}),
                          ("不支援的平台", {"workflow_text": job("8.28.0", GOOD_SHA), "platform": ("darwin", "arm64")})]:
            rc, out, err, calls, d = run_main(**kw)
            if rc != 2 or out or not err.strip():
                return f"{label} → 退出碼 2、stdout 空白、stderr 寫明原因（得到 {rc}、{out!r}、{err!r}）"
            if label == "不支援的平台" and calls:
                return f"不支援的平台 → 不下載（得到 {calls}）"
    check("main：無法取得時退出碼 2、stdout 空白", t_main_problems)

    def t_main_home_fallback():
        with tempfile.TemporaryDirectory() as d:
            wf = pathlib.Path(d, "nightly.yml"); wf.write_text(job("8.28.0", GOOD_SHA), encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                rc = main([], workflow=wf, environ={"HOME": d}, platform=("linux", "x86_64"), download=downloader(GOOD, []))
            want = str(pathlib.Path(d, ".cache", "vibesec", "gitleaks-8.28.0", "gitleaks").resolve())
            if rc != 0 or out.getvalue().strip() != want:
                return f"沒有 XDG_CACHE_HOME → ~/.cache/vibesec/（得到 {rc}、{out.getvalue()!r}）"
    check("main：沒有 XDG_CACHE_HOME 時用 ~/.cache", t_main_home_fallback)
    return fails


def main(argv=None, *, workflow=NIGHTLY, environ=None, platform=None, download=None) -> int:
    """workflow、environ、platform、download 只給 selftest 注入；命令列沒有其他參數。"""
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["selftest"]:
        fails = selftest()
        print("\n".join(f"FAIL {x}" for x in fails) or "fetch_gitleaks selftest ok")
        return 1 if fails else 0
    environ = os.environ if environ is None else environ
    system, machine = platform or (sys.platform, os.uname().machine if hasattr(os, "uname") else "")
    try:
        if not (system.startswith("linux") and machine in ("x86_64", "amd64")):
            raise FetchProblem(f"只支援 linux x64（nightly 用的同一個 release 資產）；這台是 {system}／{machine}")
        try:
            text = pathlib.Path(workflow).read_text(encoding="utf-8")
        except OSError as e:
            raise FetchProblem(f"讀不到 nightly workflow：{e}") from e
        version, sha = pinned(text)
        base = environ.get("XDG_CACHE_HOME") or str(pathlib.Path(environ.get("HOME") or pathlib.Path.home(), ".cache"))
        binary = ensure(version, sha, cache_root=pathlib.Path(base) / "vibesec", download=download or https_download)
    except FetchProblem as e:
        print(f"無法取得經驗證的 gitleaks（incomplete ≠ pass）：{e}", file=sys.stderr)
        return 2
    print(f"gitleaks {version}：{binary}", file=sys.stderr)
    print(binary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
