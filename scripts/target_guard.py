#!/usr/bin/env python3
"""VibeSec 目標授權檢查：G5／G6 探針送出前，確認目標在 config/targets.yaml 的允許範圍內（CLAUDE.md 規則 8）。

  python3 scripts/target_guard.py check <url>   # 0 允許；1 拒絕；2 設定缺席或無法解析（incomplete ≠ pass）
  python3 scripts/target_guard.py selftest

  from target_guard import check
  allowed, reason = check(url, root)            # 設定缺席或壞掉 → GuardConfigError

規則（細節見 config/targets.yaml）：只收 http/https；帶帳密的 URL 拒絕；雲端 metadata 位址拒絕；
denied_host_suffixes 優先；allowed_hosts／allowed_host_suffixes 允許；其餘預設拒絕。
只比對主機名，不做 DNS 解析：允許清單只能放受控的網域（staging DNS 由擁有者控制）。
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
    return fails


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["selftest"]:
        fails = selftest()
        for f in fails: print(f"FAIL {f}")
        print("selftest " + ("通過" if not fails else f"失敗 {len(fails)} 項"))
        return 1 if fails else 0
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
