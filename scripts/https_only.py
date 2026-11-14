#!/usr/bin/env python3
"""HTTPS 傳輸層：只走 HTTPS 的 GET JSON，暫時性錯誤重試（#263，#260 的 S2）。

只用標準函式庫、沒有全域狀態。介面只有一個進入點：
  get_json(url, *, timeout, retries, backoff, transport, sleep=time.sleep) -> 解析後的 JSON
重試與錯誤分類在 get_json；傳輸層（transport）只負責「一次嘗試」：get(url, timeout) -> 回應本文（bytes），失敗丟出
urllib／OSError 例外。生產轉接器是 UrllibHttpsOnly；測試用腳本化的替身放在 tests/。

行為（從 g1_slopcheck.http_json 原樣搬來）：暫時性錯誤（連線中斷、傳輸截斷、逾時、429、5xx、本文不是完整的 JSON）
重試 retries 次，每次失敗後等 backoff × 第幾次；其餘 HTTP 錯誤（如 404）立即拋出；重試用完仍失敗就拋出最後一個錯誤，
由呼叫端記未完成（AGENTS.md 規則 2：拿不到證據就是 incomplete，不是通過）。
"""
from __future__ import annotations
import http.client, json, os, ssl, time, urllib.error, urllib.request


def tls_context() -> ssl.SSLContext:
    """驗證憑證與主機名的 TLS 設定；SSL_CERT_FILE 指向自訂的信任憑證（例如企業 proxy）。"""
    return ssl.create_default_context(cafile=os.environ.get("SSL_CERT_FILE") or None)


def _https_only_opener():
    """只裝 HTTPS（驗證憑證與主機名）、https proxy 與 UnknownHandler：file://、http:// 等一律 URLError。"""
    opener = urllib.request.OpenerDirector()
    https_proxy = {k: v for k, v in urllib.request.getproxies().items() if k == "https"}
    for h in (urllib.request.ProxyHandler(https_proxy),
              urllib.request.HTTPSHandler(context=tls_context()),
              urllib.request.UnknownHandler(),
              urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor()):
        opener.add_handler(h)
    return opener


class UrllibHttpsOnly:
    """生產轉接器：以只裝 HTTPS 的 urllib opener 發出一次 GET。user_agent 由呼叫端指定（G1 用 vibesec-g1/0.1）。
    opener_factory 只給這個轉接器自己的測試用（驗證每次嘗試都新建 Request）。"""

    def __init__(self, *, user_agent: str, opener_factory=_https_only_opener):
        self.user_agent = user_agent
        self._opener_factory = opener_factory

    def get(self, url: str, timeout: float) -> bytes:
        # 每次嘗試都建新的 Request：ProxyHandler 會改寫傳入的 Request（set_proxy），重用同一個物件時，
        # 經 http:// proxy 的第二、三次嘗試會變成 type=http 並以「unknown url type: http」失敗——暫時性錯誤其實沒被重試
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        with self._opener_factory().open(req, timeout=timeout) as r:
            return r.read()


def get_json(url: str, *, timeout: float, retries: int, backoff: float, transport, sleep=time.sleep):
    """GET JSON。暫時性錯誤（連線中斷、傳輸截斷、逾時、429、5xx）重試 retries 次；其餘 HTTP 錯誤（如 404）立即拋出。
    重試仍失敗就拋出，由呼叫端記 incomplete。sleep 只給測試注入（驗證退避時間）。"""
    for attempt in range(retries + 1):
        try:
            return json.loads(transport.get(url, timeout).decode())
        except urllib.error.HTTPError as e:
            if (e.code != 429 and e.code < 500) or attempt == retries:
                raise
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError):
            if attempt == retries:
                raise
        sleep(backoff * (attempt + 1))
