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
    import io
    from unittest import mock
    import g1_registry as gr
    import g1_slopcheck as sc
    gate = D.parent / f"{D.name}-gate.json"
    sarif_path = D.parent / f"{D.name}-out.sarif"
    reg = registry or gr.FakeRegistry()
    raw = io.BytesIO()
    stdout = io.TextIOWrapper(raw, encoding="utf-8", errors="strict", write_through=True)
    extra = ["--sarif", str(sarif_path)] if sarif else []
    with mock.patch.object(sc, "GIT", git), mock.patch.object(sc, "REGISTRY", reg), \
            contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
        error = None
        try:
            code = sc.main(["g1_slopcheck.py", "--target", str(D), *argv, "--gate", str(gate), *extra])
        except Exception as e:      # noqa: BLE001  記下例外，讓崩潰在測試裡是可讀的失敗（assert run.error is None），不是 ERROR
            code, error = None, e
        finally:
            sc.TARGET = sc.ROOT

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
