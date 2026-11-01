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
import ipaddress, pathlib, sys, urllib.parse

DEFAULT_ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFIG = "config/targets.yaml"
METADATA_HOSTS = {"metadata.google.internal", "metadata", "instance-data", "instance-data.ec2.internal"}
METADATA_NETS = [ipaddress.ip_network("169.254.0.0/16"), ipaddress.ip_network("fd00:ec2::/32")]


class GuardConfigError(Exception):
    pass


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
        _ = u.port  # 非法埠號會丟 ValueError
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
    return scheme, host.lower(), port or (443 if scheme == "https" else 80)


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
