"""測試共用的替身與輔助。 / Shared test doubles and helpers.

傳輸層的替身放在 tests/，不放生產程式（#260 的決定）：生產側只有評測也會用到的 FakeRegistry（scripts/g1_registry.py）。
run_cli 與 run_screen 是驅動快篩 main 的輔助函式（不是替身），多個測試檔共用：run_cli 取得 SARIF、閘門結果與以嚴格 UTF-8
編碼的標準輸出（含無法編碼的字元會當場崩潰，與真的終端機一致）；run_screen 是只要（退出碼、閘門結果、登錄庫）的簡版。
"""
import json
import urllib.error


class RoutedTransport:
    """依網址腳本化的傳輸層：值是 dict／list（轉成 JSON）、bytes（原樣）或例外（丟出）；沒有腳本的網址 → URLError。
    calls 依序記錄每次嘗試的網址（重試也各記一次）。"""

    def __init__(self, routes):
        self.routes = dict(routes)
        self.calls = []

    def get(self, url, timeout):
        self.calls.append(url)
        if url not in self.routes:
            raise urllib.error.URLError(f"沒有腳本：{url}")
        item = self.routes[url]
        if isinstance(item, BaseException):
            raise item
        return item if isinstance(item, bytes) else json.dumps(item).encode()


def http_error(code):
    return urllib.error.HTTPError("https://x.invalid/", code, "msg", {}, None)


class FakeTargetTransport:
    """受測服務傳輸層的記憶體路由替身：記錄已送達的請求清單，未腳本化的路徑 fail-closed 回傳 TransportError。

    routes 支援以 `(method, url_or_path)` 或 `url_or_path` 為索引；值可為 `(status, body)`、
    `(status, body, headers)`（body 可為 bytes 或自動轉 JSON 的物件）、`HttpResponse`、`TransportError` 或 `callable(req)`。
    """

    def __init__(self, routes=None):
        self.routes = dict(routes or {})
        self.calls = []

    @staticmethod
    def _load_target_guard():
        import pathlib
        import sys
        scripts_dir = str(pathlib.Path(__file__).resolve().parents[1] / "scripts")
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)
        import target_guard
        return target_guard

    @staticmethod
    def _candidates(req):
        import urllib.parse
        u = urllib.parse.urlsplit(req.url)
        canonical = urllib.parse.urlunsplit((u.scheme.lower(), u.netloc.lower(), u.path, u.query, u.fragment))
        path = u.path or "/"
        rel = f"{path}?{u.query}" if u.query else path
        return (
            (req.method, req.url),
            (req.method, canonical),
            (req.method, rel),
            (req.method, path),
            req.url,
            canonical,
            rel,
            path,
        )

    @staticmethod
    def _bound_response(tg, status, raw_body, headers, max_bytes, elapsed_ms=0, truncated=False):
        is_truncated = bool(truncated) or (len(raw_body) > max_bytes)
        return tg.HttpResponse(
            status=status,
            body=raw_body[:max_bytes],
            headers=headers,
            truncated=is_truncated,
            elapsed_ms=elapsed_ms,
        )

    def send(self, req):
        tg = self._load_target_guard()
        self.calls.append(req)
        for cand in self._candidates(req):
            if cand in self.routes:
                spec = self.routes[cand]
                break
        else:
            return tg.TransportError(url=req.url, reason=f"未腳本化的測試路由：{req.method} {req.url}")
        if callable(spec):
            spec = spec(req)
        if isinstance(spec, tg.TransportError):
            return spec
        if isinstance(spec, tg.HttpResponse):
            return self._bound_response(tg, spec.status, spec.body, spec.headers, req.max_bytes, spec.elapsed_ms, spec.truncated)
        if isinstance(spec, tuple) and len(spec) in (2, 3):
            raw_body = spec[1] if isinstance(spec[1], bytes) else json.dumps(spec[1]).encode("utf-8")
            hdrs = spec[2] if len(spec) == 3 else {}
            return self._bound_response(tg, int(spec[0]), raw_body, hdrs, req.max_bytes)
        raise TypeError(f"不支援的 FakeTargetTransport 路由規格：{spec!r}")


class FakeGit:
    """記憶體內的 Git（#265）：staged 是檔名列表（或測試給的失敗物件）、tracked 是追蹤檔列表（None＝不是 git 工作樹）、
    files 是 {(ref, 路徑): 內容}。沒有腳本的 show 回 None（與真的 git「檔案不存在」同形）。
    shown 依序記錄每次 show 的 (ref, 路徑)，測試用來確認路徑是相對目標專案的。"""

    def __init__(self, staged=(), tracked=None, files=None):
        self._staged, self._tracked, self._files = staged, tracked, dict(files or {})
        self.shown = []

    def staged(self):
        return self._staged if not isinstance(self._staged, (list, tuple)) else list(self._staged)

    def tracked_files(self):
        return None if self._tracked is None else list(self._tracked)

    def show(self, ref, path):
        self.shown.append((ref, path))
        return self._files.get((ref, path))


class CliRun:
    """run_cli 的結果：退出碼、閘門結果、SARIF（皆已用嚴格 UTF-8 讀回並解析；沒有輸出時為 {}）、標準輸出的文字、登錄庫，
    以及 main 丟出的例外（沒有則為 None；測試斷言它是 None，崩潰才會是可讀的失敗而不是 ERROR）。"""

    def __init__(self, code, gate, sarif, stdout, registry, error=None):
        self.code, self.gate, self.sarif, self.stdout, self.registry, self.error = code, gate, sarif, stdout, registry, error


def run_cli(D, *argv, git=None, registry=None, sarif=False):
    """以假登錄庫跑快篩的 main。標準輸出是嚴格 UTF-8 的位元組串流（含無法編碼的字元會當場崩潰，與真的終端機一致），
    閘門結果與 SARIF 也以嚴格 UTF-8 讀回；git=None 時用生產的 SubprocessGit。"""
    # 惰性匯入：這個檔也被不需要快篩的測試匯入（傳輸層測試），匯入時不能要求 scripts/ 已經在 sys.path 上
    import contextlib
    import dataclasses
    import io
    import g1_registry as gr
    import g1_slopcheck as sc
    gate = D.parent / f"{D.name}-gate.json"
    sarif_path = D.parent / f"{D.name}-out.sarif"
    reg = registry or gr.FakeRegistry()
    raw = io.BytesIO()
    stdout = io.TextIOWrapper(raw, encoding="utf-8", errors="strict", write_through=True)
    extra = ["--sarif", str(sarif_path)] if sarif else []
    def env_factory(root):
        env, problem = sc.default_env(root, sc.ROOT, registry=reg)      # 政策、設定與生產一樣；登錄庫是替身
        return (dataclasses.replace(env, git=git) if env is not None and git is not None else env), problem

    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
        error = None
        try:
            code = sc.main(["g1_slopcheck.py", "--target", str(D), *argv, "--gate", str(gate), *extra], env_factory=env_factory)
        except Exception as e:      # noqa: BLE001  記下例外，讓崩潰在測試裡是可讀的失敗（assert run.error is None），不是 ERROR
            code, error = None, e

    def load(p):
        data = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
        if p.exists():
            p.unlink()
        return data
    return CliRun(code, load(gate), load(sarif_path), raw.getvalue().decode("utf-8"), reg, error)


def run_screen(D, *argv, git=None, registry=None):
    """run_cli 的簡版：回傳（退出碼、閘門結果、登錄庫）。"""
    r = run_cli(D, *argv, git=git, registry=registry)
    if r.error is not None:
        raise r.error
    return r.code, r.gate, r.registry
