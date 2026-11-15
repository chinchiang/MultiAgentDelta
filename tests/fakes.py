"""測試共用的替身。 / Shared test doubles.

傳輸層的替身放在 tests/，不放生產程式（#260 的決定）：生產側只有評測也會用到的 FakeRegistry（scripts/g1_registry.py）。
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
