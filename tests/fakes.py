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
