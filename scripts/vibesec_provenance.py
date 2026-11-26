#!/usr/bin/env python3
"""VibeSec 審查包的來源標記（provenance mark，#329、ADR 0004）：證明審查包出自 review_packet（遮罩過）或
prepare_comparison（合成評測案例），而且產生之後沒被改過。review_provider 只送出標記有效的審查包。

公開入口（interface）：
  load_pepper(environ=None, home=None, create=False) -> bytes
      指紋金鑰：環境變數 VIBESEC_FINGERPRINT_KEY（空字串視同沒有）；否則 ~/.config/vibesec/fingerprint-key
      （家目錄：home 參數 → environ 的 HOME → Path.home()，注入的 environ 也決定讀哪個家目錄）。
      create=True 時沒有就建立（隨機 32 bytes 的 hex，權限 0600；只有 review_packet 這樣用）。
      短於 32 bytes、權限比 0600 寬、讀不到或建不出來 → PepperUnavailable（訊息不含金鑰）。
  seal(packet, kind, key) -> dict
      回傳加上 provenance = {kind, key_id, hmac} 的副本。kind 必須是 KINDS 之一。
  verify(packet, key) -> str | None
      None＝標記有效；否則回傳原因（缺少標記、格式不正確、kind 不認得、另一把金鑰、內容在標記後被改過）。
  strip(packet) -> dict
      回傳不含 provenance 的副本（送給模型前用）。

HMAC-SHA256 涵蓋整份審查包（provenance 除外），序列化固定為鍵排序、ensure_ascii=False、分隔符號 (",", ":")。
限制：金鑰在本機，讀得到金鑰的人或 agent 可以自己算出標記，所以擋不了刻意偽造；目標是防止意外與被誘導
（手組審查包、填錯分級、跳過遮罩）。只用標準函式庫。
  python3 scripts/vibesec_provenance.py selftest
"""
from __future__ import annotations
import hashlib, hmac, json, os, pathlib, secrets, sys, tempfile

PEPPER_ENV = "VIBESEC_FINGERPRINT_KEY"
PEPPER_FILE = pathlib.PurePosixPath(".config/vibesec/fingerprint-key")   # 相對於家目錄
PEPPER_MIN = 32   # bytes：太短的金鑰可以連同短祕密一起暴力反推，HMAC 就失去意義
KINDS = ("review-packet", "eval-fixture")
FIELD = "provenance"


class PepperUnavailable(Exception):
    """拿不到可用的指紋金鑰；訊息不含金鑰。"""


def load_pepper(environ=None, home: pathlib.Path | None = None, create: bool = False) -> bytes:
    env = os.environ if environ is None else environ
    if env.get(PEPPER_ENV):
        if len(env[PEPPER_ENV].encode()) < PEPPER_MIN:
            raise PepperUnavailable(f"{PEPPER_ENV} 太短（至少 {PEPPER_MIN} bytes）")
        return env[PEPPER_ENV].encode()
    base = pathlib.Path(home) if home is not None else (pathlib.Path(env["HOME"]) if env.get("HOME") else pathlib.Path.home())
    path = base / PEPPER_FILE
    try:
        if not path.exists():
            if not create:
                raise PepperUnavailable(f"沒有指紋金鑰（{PEPPER_ENV} 未設定，~/{PEPPER_FILE} 不存在）")
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:   # 同時有另一個程序剛建好：讀它的
                fd = None
            if fd is not None:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(secrets.token_hex(32))
        if os.name == "posix" and path.stat().st_mode & 0o077:   # 只在建立時給 0600 不夠：既有檔被放寬就拒絕
            raise PepperUnavailable(f"指紋金鑰檔 ~/{PEPPER_FILE} 的權限太寬（群組或其他人可存取）：chmod 600 後再執行")
        data = path.read_bytes().strip()
    except OSError as e:
        raise PepperUnavailable(f"指紋金鑰讀不到也建不出來（{PEPPER_ENV} 未設定；~/{PEPPER_FILE}：{type(e).__name__}）") from None
    if len(data) < PEPPER_MIN:
        raise PepperUnavailable(f"指紋金鑰檔 ~/{PEPPER_FILE} 太短或是空的（至少 {PEPPER_MIN} bytes）")
    return data


def _canonical(packet: dict) -> bytes:
    body = {k: v for k, v in packet.items() if k != FIELD}
    return json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def pepper_tag(key: bytes) -> str:
    """金鑰 SHA-256 的前 8 hex：分辨「另一把金鑰」與「內容被改過」，無法反推金鑰。"""
    return hashlib.sha256(key).hexdigest()[:8]


def _mac(packet: dict, kind: str, key: bytes) -> str:
    return hmac.new(key, kind.encode() + b"\0" + _canonical(packet), hashlib.sha256).hexdigest()


def seal(packet: dict, kind: str, key: bytes) -> dict:
    if kind not in KINDS:
        raise ValueError(f"kind 必須是 {'／'.join(KINDS)} 之一：{kind!r}")
    out = strip(packet)
    out[FIELD] = {"kind": kind, "key_id": pepper_tag(key), "hmac": _mac(out, kind, key)}
    return out


def verify(packet, key: bytes) -> str | None:
    if not isinstance(packet, dict):
        return "審查包不是 JSON 物件"
    p = packet.get(FIELD)
    if p is None:
        return "缺少來源標記（不是由 review_packet 或 prepare_comparison 產生）"
    if not isinstance(p, dict) or set(p) != {"kind", "key_id", "hmac"} or not all(isinstance(v, str) for v in p.values()):
        return "來源標記格式不正確"
    if p["kind"] not in KINDS:
        return f"來源標記的 kind 不認得：{p['kind']!r}"
    if p["key_id"] != pepper_tag(key):
        return f"來源標記由另一把金鑰產生（key_id {p['key_id']}，本機 {pepper_tag(key)}）"
    try:
        want = _mac(packet, p["kind"], key)
    except (ValueError, TypeError):   # 例如不成對的 surrogate、不能序列化的值：無法驗證就不送（fail-closed）
        return "審查包含無法序列化的內容，無法驗證來源標記"
    if not hmac.compare_digest(p["hmac"], want):
        return "內容在標記後被改過（HMAC 不符）"
    return None


def strip(packet: dict) -> dict:
    return {k: v for k, v in packet.items() if k != FIELD}


# ------------------------------------------------------------------ selftest
def selftest() -> list[str]:
    fails: list[str] = []

    def check(label, fn):   # 紅燈要是 FAIL，不是崩潰
        try:
            msg = fn()
        except Exception as e:
            msg = f"拋出例外 {type(e).__name__}：{e}"
        if msg:
            fails.append(f"{label}：{msg}")

    K, K2 = b"k" * 40, b"j" * 40
    pkt = {"data_class": "internal", "finding": {"id": "VS-20260101-00000000", "evidence": "x = 1"}, "output": ["a", "b"]}

    def t_roundtrip():
        s = seal(pkt, "review-packet", K)
        p = s.get(FIELD) or {}
        if set(p) != {"kind", "key_id", "hmac"} or p["kind"] != "review-packet" or len(p["hmac"]) != 64 or len(p["key_id"]) != 8:
            return f"provenance 應為 {{kind, pepper_tag(8 hex), hmac(64 hex)}}（得到 {p}）"
        if FIELD in pkt:
            return "seal 不得修改傳入的審查包"
        if verify(s, K) is not None:
            return f"剛封好的審查包應驗證通過（得到 {verify(s, K)!r}）"
        if strip(s) != pkt or FIELD not in s:
            return "strip 回傳不含 provenance 的副本、不修改原本的"
        if verify(seal(pkt, "eval-fixture", K), K) is not None:
            return "eval-fixture 也是認得的 kind"
    check("seal／verify／strip：封好即可驗證，strip 拿掉標記", t_roundtrip)

    def t_reasons():
        s = seal(pkt, "review-packet", K)
        cases = [
            ("缺少標記", pkt, "缺少來源標記"),
            ("不是 dict", ["x"], "審查包不是 JSON 物件"),
            ("格式不正確", {**s, FIELD: {"kind": "review-packet"}}, "來源標記格式不正確"),
            ("kind 不認得", seal(pkt, "review-packet", K) | {FIELD: {**s[FIELD], "kind": "hand-made"}}, "kind 不認得"),
            ("另一把金鑰", seal(pkt, "review-packet", K2), "另一把金鑰"),
            ("分級被改", {**s, "data_class": "public"}, "內容在標記後被改過"),
            ("內容被改", {**s, "finding": {**s["finding"], "evidence": "x = 2"}}, "內容在標記後被改過"),
            ("多一個欄位", {**s, "extra": 1}, "內容在標記後被改過"),
            ("無法序列化", {**s, "finding": {"evidence": "\ud800"}}, "無法序列化"),
        ]
        bad = []
        for label, p, want in cases:
            got = verify(p, K)
            if not got or want not in got:
                bad.append(f"{label}：應含「{want}」（得到 {got!r}）")
        return "；".join(bad) or None
    check("verify：各種不合格的原因分得清楚", t_reasons)

    def t_canonical():   # 鍵的順序與縮排不影響標記：審查包寫檔時用 indent，讀回來仍要驗得過
        s = seal(pkt, "review-packet", K)
        reread = json.loads(json.dumps(dict(reversed(list(s.items()))), ensure_ascii=False, indent=2))
        return None if verify(reread, K) is None else "重新排序、縮排後讀回的審查包應驗證通過"
    check("序列化固定：鍵順序與縮排不影響驗證", t_canonical)

    def t_kind():
        try:
            seal(pkt, "hand-made", K)
            return "seal 不接受 KINDS 以外的 kind"
        except ValueError:
            return None
    check("seal：kind 必須是 KINDS 之一", t_kind)

    def t_key():
        with tempfile.TemporaryDirectory() as h:
            H = pathlib.Path(h)
            long = "z" * 40
            if load_pepper({PEPPER_ENV: long}, H) != long.encode():
                return "有 VIBESEC_FINGERPRINT_KEY 時用它"
            for env in ({PEPPER_ENV: "short"},):
                try:
                    load_pepper(env, H); return f"VIBESEC_FINGERPRINT_KEY 短於 {PEPPER_MIN} bytes 要拒絕"
                except PepperUnavailable:
                    pass
            try:
                load_pepper({}, H); return "create=False 且沒有金鑰檔 → PepperUnavailable，不建立"
            except PepperUnavailable:
                pass
            if (H / ".config").exists():
                return "create=False 不得建立任何檔案"
            k1 = load_pepper({}, H, create=True)
            f = H / PEPPER_FILE
            if not f.is_file() or f.stat().st_mode & 0o777 != 0o600 or len(k1) < PEPPER_MIN:
                return "create=True 時建立 0600 的金鑰檔（至少 32 bytes）"
            if load_pepper({}, H) != k1 or load_pepper({PEPPER_ENV: ""}, H) != k1:
                return "之後讀同一個金鑰檔；空的環境變數視同沒有"
            if load_pepper({"HOME": str(H)}) != k1:
                return "沒給 home 時取 environ 的 HOME（注入的 environ 決定讀哪個家目錄）"
            if os.name == "posix":
                f.chmod(0o644)
                try:
                    load_pepper({}, H); return "金鑰檔群組或其他人可讀時要拒絕"
                except PepperUnavailable:
                    pass
                f.chmod(0o600)
            f.write_bytes(b"short"); f.chmod(0o600)
            try:
                load_pepper({}, H); return f"金鑰檔短於 {PEPPER_MIN} bytes 要拒絕"
            except PepperUnavailable:
                pass
            B = H / "blocked"; B.mkdir(); (B / ".config").write_text("x")
            try:
                load_pepper({}, B, create=True); return "讀不到也建不出來時要拒絕"
            except PepperUnavailable:
                pass
    check("load_pepper：環境變數、0600 金鑰檔、只有 create=True 才建立", t_key)
    return fails


if __name__ == "__main__":
    if sys.argv[1:2] == ["selftest"]:
        fails = selftest()
        for f in fails:
            print(f"FAIL {f}")
        print("vibesec_provenance selftest " + ("ok" if not fails else f"失敗 {len(fails)} 項"))
        sys.exit(1 if fails else 0)
    print(__doc__.strip(), file=sys.stderr)
    sys.exit(4)
