#!/usr/bin/env python3
"""VibeSec 目標授權檢查：G5／G6 探針送出前，確認目標在 config/targets.yaml 的允許範圍內（AGENTS.md 規則 8）。

  python3 scripts/target_guard.py check <url>   # 0 允許；1 拒絕；2 設定缺席或無法解析（incomplete ≠ pass）
  python3 scripts/target_guard.py same-origin <url> <base>   # 0 同源；1 非同源或無法解析
  python3 scripts/target_guard.py selftest

  from target_guard import check, same_origin
  allowed, reason = check(url, root)            # 設定缺席或壞掉 → GuardConfigError
  ok, reason = same_origin(url, base)           # 探針送出前：最終 URL 必須與已授權的 base 同源

規則（細節見 config/targets.yaml）：只收 http/https；帶帳密的 URL 拒絕；雲端 metadata 位址拒絕；
denied_host_suffixes 優先；allowed_hosts／allowed_host_suffixes 允許；其餘預設拒絕。
只比對主機名，不做 DNS 解析：允許清單只能放受控的網域（staging DNS 由擁有者控制）。

same_origin：check 只授權 base；目標回應裡的 URL（OIDC discovery 的 jwks_uri、openapi 的 paths 鍵）由目標控制，
直接拿去送請求等於讓目標指揮 runner 打任意主機（還可能帶 Authorization）。送出前以 scheme、主機、埠完全相同判定，
帶帳密、非 http/https、空白／控制字元、非 ASCII 主機（IDN 同形字）、反斜線、主機含 % 一律拒絕。
"""
from __future__ import annotations
import collections.abc, dataclasses, http.client, ipaddress, json, pathlib, re, ssl, sys, time, types, typing, urllib.error, urllib.parse, urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import https_only  # noqa: E402

DEFAULT_ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFIG = "config/targets.yaml"
METADATA_HOSTS = {"metadata.google.internal", "metadata", "instance-data", "instance-data.ec2.internal"}
METADATA_NETS = [ipaddress.ip_network("169.254.0.0/16"), ipaddress.ip_network("fd00:ec2::/32")]
DEFAULT_MAX_BYTES: typing.Final[int] = 1 << 20
_SEAL: typing.Final = object()
_SCHEME_RE: typing.Final = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_TRANSPORT_EXCEPTIONS = (
    urllib.error.URLError,
    http.client.HTTPException,
    ssl.SSLError,
    TimeoutError,
    OSError,
    ValueError,
)


class GuardConfigError(Exception):
    pass


class Origin(typing.NamedTuple):
    scheme: str
    host: str
    port: int


@dataclasses.dataclass(frozen=True)
class TargetDenied:
    reason: str
    config_problem: bool = False


class Headers(collections.abc.Mapping[str, str]):
    """大小寫不敏感的唯讀 HTTP 回應標頭對照表。"""

    __slots__ = ("_entries",)

    def __init__(self, raw: typing.Mapping[str, str] | typing.Iterable[tuple[str, str]] | None = None) -> None:
        entries: dict[str, tuple[str, str]] = {}
        if raw is not None:
            items = raw.items() if isinstance(raw, collections.abc.Mapping) else raw
            for name, val in items:
                s_name = str(name)
                entries[s_name.lower()] = (s_name, str(val))
        self._entries = entries

    def __getitem__(self, name: str) -> str:
        return self._entries[name.lower()][1]

    def __iter__(self) -> typing.Iterator[str]:
        for orig_name, _ in self._entries.values():
            yield orig_name

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name.lower() in self._entries


@dataclasses.dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes = b""
    headers: Headers = dataclasses.field(default_factory=Headers)
    truncated: bool = False
    elapsed_ms: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.headers, Headers):
            object.__setattr__(self, "headers", Headers(self.headers))

    def header(self, name: str, default: str | None = None) -> str | None:
        return self.headers.get(name, default)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self) -> object | None:
        """解析完整回應本文為 JSON；若回應已截斷或非合法 JSON 則回傳 None。"""
        if self.truncated:
            return None
        try:
            return json.loads(self.text)
        except ValueError:
            return None


@dataclasses.dataclass(frozen=True)
class OffOrigin:
    url: str
    reason: str


@dataclasses.dataclass(frozen=True)
class TransportError:
    url: str
    reason: str
    elapsed_ms: int = 0


TargetOutcome: typing.TypeAlias = HttpResponse | OffOrigin | TransportError


@dataclasses.dataclass(frozen=True)
class TransportRequest:
    method: str
    url: str
    headers: typing.Mapping[str, str]
    body: bytes | None
    timeout: float
    max_bytes: int


class TargetTransport(typing.Protocol):
    def send(self, req: TransportRequest) -> HttpResponse | TransportError: ...


def _target_opener() -> urllib.request.OpenerDirector:
    """只裝空代理（忽略環境變數 proxy）與 HTTP／HTTPS（驗證 TLS），不裝 HTTPRedirectHandler 與本機檔案處理器。"""
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(context=https_only.tls_context()),
        urllib.request.UnknownHandler(),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
    ):
        opener.add_handler(handler)
    return opener


def _validate_wire_request(req: TransportRequest) -> None:
    if not req.method or not req.method.isascii() or any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7f for c in req.method):
        raise ValueError("HTTP 方法含非法字元")
    if not req.url.isascii() or any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7f for c in req.url):
        raise ValueError("請求 URL 含非 ASCII 或控制字元")
    for h_name, h_val in req.headers.items():
        if not h_name or not h_name.isascii() or any(c.isspace() or c == ":" or ord(c) < 0x20 or ord(c) == 0x7f for c in h_name):
            raise ValueError(f"標頭名稱不合法：{h_name!r}")
        if "\r" in h_val or "\n" in h_val or "\x00" in h_val:
            raise ValueError(f"標頭值含控制字元：{h_name}")
        h_val.encode("latin-1")


def _transport_failure(url: str, exc: BaseException, started: float) -> TransportError:
    elapsed = int((time.monotonic() - started) * 1000)
    return TransportError(url=url, reason=f"請求失敗（{type(exc).__name__}：{exc}）", elapsed_ms=elapsed)


class UrllibTransport:
    """生產受測服務單跳 HTTP 轉接器：不走環境代理、不跟隨 3xx 重新導向、4xx／5xx 原樣轉為 HttpResponse、限長讀取。"""

    def send(self, req: TransportRequest) -> HttpResponse | TransportError:
        t0 = time.monotonic()
        try:
            _validate_wire_request(req)
            u_req = urllib.request.Request(req.url, data=req.body, headers=dict(req.headers), method=req.method)
            with _target_opener().open(u_req, timeout=req.timeout) as resp:
                raw = resp.read(req.max_bytes + 1)
                status = resp.status
                hdrs = Headers(resp.headers.items())
        except urllib.error.HTTPError as e:
            try:
                raw = e.read(req.max_bytes + 1) if e.fp is not None else b""
                hdrs = Headers(e.headers.items()) if e.headers is not None else Headers()
                status = e.code
            except _TRANSPORT_EXCEPTIONS as read_err:
                return _transport_failure(req.url, read_err, t0)
            finally:
                try:
                    e.close()
                except Exception:
                    pass
        except _TRANSPORT_EXCEPTIONS as e:
            return _transport_failure(req.url, e, t0)
        elapsed = int((time.monotonic() - t0) * 1000)
        truncated = len(raw) > req.max_bytes
        return HttpResponse(
            status=status,
            body=raw[: req.max_bytes],
            headers=hdrs,
            truncated=truncated,
            elapsed_ms=elapsed,
        )


def _load(root: pathlib.Path) -> dict:
    p = root / CONFIG
    try:
        import yaml
    except ImportError as e:
        raise GuardConfigError("PyYAML 缺席，無法讀取目標允許清單") from e
    try:
        d = yaml.safe_load(p.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise GuardConfigError(f"{CONFIG} 不存在") from e
    except Exception as e:
        raise GuardConfigError(f"{CONFIG} 無法解析（{type(e).__name__}）") from e
    if not isinstance(d, dict):
        raise GuardConfigError(f"{CONFIG} 格式錯誤（應為 mapping）")
    out = {}
    for k in ("allowed_hosts", "allowed_host_suffixes", "denied_host_suffixes"):
        v = d.get(k) or []
        if not isinstance(v, list) or not all(isinstance(x, str) and x.strip() for x in v):
            raise GuardConfigError(f"{CONFIG} 的 {k} 必須是非空字串清單")
        out[k] = [_norm(x) for x in v]
    return out


def _norm(host: str) -> str:
    h = host.strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h.rstrip(".")


def _match(host: str, pattern: str) -> bool:
    if pattern.startswith("."):
        return host.endswith(pattern)
    return host == pattern


def check(url: str, root: pathlib.Path | str | None = None) -> tuple[bool, str]:
    cfg = _load(pathlib.Path(root) if root else DEFAULT_ROOT)
    try:
        u = urllib.parse.urlsplit((url or "").strip())
        host = u.hostname
        port = u.port  # 非法埠號會丟 ValueError
        if port == 0:
            raise ValueError("Port out of range 1-65535")
    except ValueError as e:
        return False, f"URL 無法解析（{e}）"
    if u.scheme not in ("http", "https"):
        return False, f"只允許 http/https，收到 {u.scheme or '（無）'!r}"
    if "@" in u.netloc:
        return False, "URL 帶帳密（user@host），可能混淆實際目標"
    if not host:
        return False, "URL 沒有主機名"
    host = _norm(host)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if host in METADATA_HOSTS or (ip is not None and any(ip in n for n in METADATA_NETS)):
        return False, f"{host} 是雲端 metadata 位址"
    for pat in cfg["denied_host_suffixes"]:
        if _match(host, pat):
            return False, f"{host} 符合 denied_host_suffixes 的 {pat}（正式環境）"
    if host in cfg["allowed_hosts"]:
        return True, f"{host} 在 allowed_hosts"
    for pat in cfg["allowed_host_suffixes"]:
        if _match(host, pat):
            return True, f"{host} 符合 allowed_host_suffixes 的 {pat}"
    return False, f"{host} 不在 {CONFIG} 的允許清單（預設拒絕）"


def _origin(url: str) -> tuple[str, str, int]:
    """回傳 (scheme, host, port)；任何可疑寫法丟 ValueError（寧可拒絕，不猜瀏覽器／urllib 會怎麼解讀）。"""
    if not isinstance(url, str) or not url:
        raise ValueError("URL 為空")
    if any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7f for c in url):
        raise ValueError("URL 含空白或控制字元")
    if "\\" in url:
        raise ValueError("URL 含反斜線")
    u = urllib.parse.urlsplit(url)
    scheme = u.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"只允許 http/https，收到 {u.scheme or '（無）'!r}")
    if "@" in u.netloc:
        raise ValueError("URL 帶帳密（user@host）")
    if not u.netloc.isascii() or "%" in u.netloc:
        raise ValueError("主機含非 ASCII 或百分比編碼（IDN／編碼混淆）")
    host = u.hostname
    if not host:
        raise ValueError("URL 沒有主機名")
    port = u.port  # 非法埠號丟 ValueError
    if port == 0:
        raise ValueError("非法埠號 0")
    return scheme, host.lower(), (443 if scheme == "https" else 80) if port is None else port


def parse_origin(url: str | None) -> Origin | None:
    """解析為不可變的 Origin(scheme, host, port)；任何非 http/https 或可疑寫法皆回傳 None。"""
    if not isinstance(url, str):
        return None
    try:
        scheme, host, port = _origin(url)
    except ValueError:
        return None
    return Origin(scheme, host, port)


def same_origin(url: str, base: str) -> tuple[bool, str]:
    """url 與 base 的 scheme、主機、埠完全相同才 True；不做 DNS 解析、不正規化尾點（嚴格比對）。"""
    try:
        want = _origin(base)
    except ValueError as e:
        return False, f"授權目標 URL 無法解析（{e}）"
    try:
        got = _origin(url)
    except ValueError as e:
        return False, f"{url!r} 無法判定來源（{e}）"
    if got != want:
        return False, f"{got[0]}://{got[1]}:{got[2]} 與授權來源 {want[0]}://{want[1]}:{want[2]} 不同"
    return True, "同源"


def _resolve_url(base_url: str, path: str) -> str:
    if not isinstance(path, str):
        return ""
    if _SCHEME_RE.match(path):
        return path
    if path.startswith("/") and not path.startswith("//"):
        return base_url + path
    return path


@typing.final
class AuthorizedTarget:
    """已通過 config/targets.yaml 與來源解析的受測服務傳輸能力；僅能由 authorize_target() 鑄造。"""

    __slots__ = ("_seal", "_base_url", "_origin", "_transport", "_user_agent")

    def __init__(
        self,
        _seal: object = None,
        *,
        base_url: str = "",
        origin: Origin | None = None,
        transport: TargetTransport | None = None,
        user_agent: str = "vibesec-probe",
    ) -> None:
        if _seal is not _SEAL or origin is None:
            raise TypeError("AuthorizedTarget 只能透過 authorize_target() 建立，不得直接實例化")
        self._seal = _seal
        self._base_url = base_url
        self._origin = origin
        self._transport = transport
        self._user_agent = user_agent

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("AuthorizedTarget 為封緘類別，不得繼承")

    @property
    def base_url(self) -> str:
        return self._base_url

    @property
    def origin(self) -> Origin:
        return self._origin

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        body: bytes | None = None,
        json_body: object = None,
        headers: typing.Mapping[str, str] | None = None,
        bearer_token: str | None = None,
        timeout: float = 15.0,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> TargetOutcome:
        if getattr(self, "_seal", None) is not _SEAL or self._transport is None:
            raise TypeError("未經 authorize_target() 封緘的 AuthorizedTarget 實例不得發送請求")
        if body is not None and json_body is not None:
            raise ValueError("body 與 json_body 不可同時指定")
        if max_bytes <= 0:
            raise ValueError("max_bytes 必須為正整數")
        url = _resolve_url(self._base_url, path)
        same, why = same_origin(url, self._base_url)
        if not same:
            return OffOrigin(url=url, reason=why)
        req_headers: dict[str, str] = {"User-Agent": self._user_agent}
        if json_body is not None:
            payload: bytes | None = json.dumps(json_body).encode("utf-8")
            req_headers["Content-Type"] = "application/json"
        else:
            payload = body
        if headers:
            for h_name, h_val in headers.items():
                req_headers[str(h_name)] = str(h_val)
        if bearer_token:
            req_headers["Authorization"] = f"Bearer {bearer_token}"
        t_req = TransportRequest(
            method=method.upper(),
            url=url,
            headers=types.MappingProxyType(req_headers),
            body=payload,
            timeout=timeout,
            max_bytes=max_bytes,
        )
        t0 = time.monotonic()
        outcome = self._transport.send(t_req)
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        if outcome.elapsed_ms == 0 and elapsed_ms > 0:
            return dataclasses.replace(outcome, elapsed_ms=elapsed_ms)
        return outcome


def authorize_target(
    url: str | None,
    *,
    root: pathlib.Path | str | None = None,
    transport: TargetTransport | None = None,
    user_agent: str = "vibesec-probe",
) -> AuthorizedTarget | TargetDenied:
    """唯一鑄造 AuthorizedTarget 的授權入口；未授權、設定損壞或含 query／fragment 一律回傳 TargetDenied（零網路請求）。"""
    base_url = (url if isinstance(url, str) else "").strip().rstrip("/")
    try:
        ok, why = check(base_url, root)
    except GuardConfigError as e:
        return TargetDenied(reason=f"目標允許清單無法讀取：{e}", config_problem=True)
    if not ok:
        return TargetDenied(reason=why, config_problem=False)
    if "?" in base_url or "#" in base_url:
        return TargetDenied(reason="基準 URL 不得包含 query 或 fragment", config_problem=False)
    try:
        scheme, host, port = _origin(base_url)
    except ValueError as e:
        return TargetDenied(reason=f"授權目標 URL 無法解析（{e}）", config_problem=False)
    return AuthorizedTarget(
        _SEAL,
        base_url=base_url,
        origin=Origin(scheme, host, port),
        transport=transport if transport is not None else UrllibTransport(),
        user_agent=user_agent,
    )


def _same_origin_selftest() -> list[str]:
    fails: list[str] = []
    base = "http://127.0.0.1:8000"
    cases = [
        ("http://127.0.0.1:8000/.well-known/jwks.json", True, "同源絕對 URL"),
        ("HTTP://127.0.0.1:8000/x", True, "scheme 大小寫"),
        (base + "/__vibesec_nonexistent__/%ff", True, "路徑中的百分比編碼"),
        (base + "//evil.example.com/x", True, "base + '//host' 仍是同源路徑"),
        ("http://127.0.0.1:8001/jwks.json", False, "不同埠"),
        ("https://127.0.0.1:8000/", False, "不同 scheme"),
        ("http://127.0.0.1/", False, "預設埠 80 ≠ 8000"),
        ("http://evil.example.com/jwks.json", False, "不同主機"),
        ("http://localhost:8000/", False, "別名主機（不做 DNS 解析）"),
        ("http://127.0.0.1.:8000/", False, "尾點（嚴格比對）"),
        (base + "@evil.example.com/x", False, "base + '@host' 路徑注入成帳密"),
        ("http://127.0.0.1:8000@evil.example.com/", False, "帳密混淆"),
        ("http://u:p@127.0.0.1:8000/", False, "帶帳密（主機相同）"),
        ("file:///etc/passwd", False, "file scheme"),
        ("//127.0.0.1:8000/x", False, "無 scheme 的 network-path"),
        ("/jwks.json", False, "相對路徑不是絕對 URL"),
        ("http://127.0.0.1:8000 /x", False, "空白"),
        ("http://127.0.0.1:8000\t/x", False, "控制字元"),
        ("http://127.0.0.1:8000\\@evil.example.com/", False, "反斜線"),
        ("http://ｅvil.example.com/", False, "IDN 全形字"),
        ("http://127.0.0.1%3a8000/", False, "主機百分比編碼"),
        ("http://127.0.0.1:0/", False, "非法埠號 0"),
        ("http://127.0.0.1:99999/", False, "非法埠號"),
        ("", False, "空字串"),
    ]
    for url, want, label in cases:
        got, why = same_origin(url, base)
        if got is not want:
            fails.append(f"same_origin {label}：{url!r} 預期 {'同源' if want else '拒絕'}，實際 {'同源' if got else '拒絕'}（{why}）")
    if same_origin("https://api.staging.example.com/a", "https://api.staging.example.com")[0] is not True:
        fails.append("same_origin：https 預設埠 443 應與省略埠相同")
    if same_origin("https://api.staging.example.com:443/a", "https://API.staging.example.com/")[0] is not True:
        fails.append("same_origin：明寫 :443 與主機大小寫應視為同源")
    if same_origin(base, "ftp://127.0.0.1")[0]:
        fails.append("same_origin：base 本身非 http/https 時必須拒絕")
    return fails


def selftest() -> list[str]:
    import tempfile
    fails: list[str] = []

    def expect(root, url, want, label):
        got, why = check(url, root)
        if got is not want:
            fails.append(f"{label}：{url} 預期 {'允許' if want else '拒絕'}，實際 {'允許' if got else '拒絕'}（{why}）")

    with tempfile.TemporaryDirectory() as d:
        root = pathlib.Path(d)
        (root / "config").mkdir()
        (root / CONFIG).write_text(
            "allowed_hosts: [localhost, 127.0.0.1, '::1']\n"
            "allowed_host_suffixes: [.staging.example.com, exact.example.net]\n"
            "denied_host_suffixes: [prod.staging.example.com, .example.org]\n", encoding="utf-8")
        expect(root, "http://127.0.0.1:8000", True, "靶場")
        expect(root, "http://LOCALHOST.:8000/chat", True, "大寫與尾點")
        expect(root, "http://[::1]:8000", True, "IPv6 loopback")
        expect(root, "https://api.staging.example.com", True, "允許後綴（子網域）")
        expect(root, "https://exact.example.net/x", True, "允許主機（完全相同）")
        expect(root, "https://sub.exact.example.net", False, "非點開頭的後綴只比對完全相同")
        expect(root, "https://evilstaging.example.com", False, "後綴必須在網域邊界")
        expect(root, "https://prod.staging.example.com", False, "deny 優先於允許後綴")
        expect(root, "https://www.example.org", False, "deny 後綴")
        expect(root, "https://example.com", False, "預設拒絕")
        expect(root, "http://127.0.0.1@evil.example.com/", False, "帶帳密")
        expect(root, "http://user:pw@127.0.0.1/", False, "帶帳密（看似靶場）")
        expect(root, "ftp://127.0.0.1/", False, "非 http/https")
        expect(root, "127.0.0.1:8000", False, "缺 scheme")
        expect(root, "http://169.254.169.254/latest", False, "metadata IP")
        expect(root, "http://metadata.google.internal/", False, "metadata 主機名")
        expect(root, "http://127.0.0.1:0/", False, "非法埠號 0")
        expect(root, "http://127.0.0.1:99999/", False, "非法埠號")
        expect(root, "", False, "空字串")
        (root / CONFIG).write_text("allowed_hosts: 127.0.0.1\n", encoding="utf-8")
        try:
            check("http://127.0.0.1", root); fails.append("allowed_hosts 不是清單應丟 GuardConfigError")
        except GuardConfigError:
            pass
        (root / CONFIG).unlink()
        try:
            check("http://127.0.0.1", root); fails.append("設定缺席應丟 GuardConfigError")
        except GuardConfigError:
            pass
    try:
        ok, why = check("http://127.0.0.1:8000")
        if not ok: fails.append(f"repo 的 {CONFIG} 必須允許本機靶場：{why}")
        ok, _ = check("https://example.com")
        if ok: fails.append(f"repo 的 {CONFIG} 不得允許 example.com")
    except GuardConfigError as e:
        fails.append(f"repo 的 {CONFIG}：{e}")
    return fails + _same_origin_selftest()


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["selftest"]:
        fails = selftest()
        for f in fails: print(f"FAIL {f}")
        print("selftest " + ("通過" if not fails else f"失敗 {len(fails)} 項"))
        return 1 if fails else 0
    if len(argv) == 3 and argv[0] == "same-origin":
        ok, why = same_origin(argv[1], argv[2])
        print(("同源：" if ok else "拒絕：") + why)
        return 0 if ok else 1
    if len(argv) == 2 and argv[0] == "check":
        try:
            ok, why = check(argv[1])
        except GuardConfigError as e:
            print(f"incomplete：{e}", file=sys.stderr)
            return 2
        print(("允許：" if ok else "拒絕：") + why)
        return 0 if ok else 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
