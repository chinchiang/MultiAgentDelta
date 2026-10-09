"""授權目標 HTTP 用戶端：所有請求與重新導向都必須留在同一來源。"""
import json
import urllib.error
import urllib.parse
import urllib.request


def origin(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        raise ValueError("目標必須是沒有內嵌憑證的 HTTP(S) URL")
    return parts.scheme, parts.hostname.lower(), parts.port or (443 if parts.scheme == "https" else 80)


class ScopedRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed):
        self.allowed = allowed

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if origin(newurl) != self.allowed:
            raise urllib.error.URLError("拒絕跨來源或降級重新導向：超出授權目標")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class TargetClient:
    def __init__(self, target):
        self.target = target.rstrip("/")
        self.allowed = origin(target)
        self.opener = urllib.request.build_opener(ScopedRedirect(self.allowed))

    def open(self, request, timeout=15):
        if origin(request.full_url) != self.allowed:
            raise urllib.error.URLError("拒絕授權目標以外的請求")
        return self.opener.open(request, timeout=timeout)

    def request(self, path, method="GET", token=None, data=None, headers=None, timeout=15):
        url = urllib.parse.urljoin(self.target + "/", path) if urllib.parse.urlsplit(path).scheme or path.startswith("//") else self.target + path
        h = {"User-Agent": "vibesec-g5-probes", **(headers or {})}
        if token:
            h["Authorization"] = f"Bearer {token}"
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            h["Content-Type"] = "application/json"
        try:
            with self.open(urllib.request.Request(url, data=body, headers=h, method=method), timeout) as response:
                return response.status, response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except (OSError, ValueError) as e:
            return None, str(e)
