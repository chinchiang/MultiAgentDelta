#!/usr/bin/env python3
"""VibeSec G6 成本面探針（denial_of_wallet_cost，LLM10:2025）：超長輸入有沒有被長度上限、配額或 token 預算擋下。

  python3 scripts/g6_cost_probe.py --target URL --out reports/g6-cost.json [--path /chat] [--chars 200000]
                                   [--max-tokens 8192] [--timeout 60]
  python3 scripts/g6_cost_probe.py selftest

只對 config/targets.yaml 允許的目標送請求（scripts/target_guard.py；CLAUDE.md 規則 8）；被拒 → untested，不送任何請求。
對 <target><path> POST {"message": "A"*chars, "context": "", "session_id": "vibesec-cost-probe"}：
  HTTP 413／429                                → pass（有長度上限或配額）
  HTTP 400／422 且錯誤內容指出過長（string_too_long、max_length、too long…）→ pass
  HTTP 400／422 但是與長度無關的驗證錯誤（例如 pydantic missing：欄位名稱不符）→ untested
  2xx 且回應 JSON 的 usage 總 token ≤ max-tokens → pass（有可見的 token 預算，例如截斷輸入）
  其他 2xx                                     → fail（接受超長輸入、看不到成本上限）
  401／403、5xx、其他狀態、逾時、連線失敗        → untested（無法判定；incomplete ≠ pass）
輸出只記狀態碼、耗時與 usage 數字，不保存回應內容。判定為 finding 與 tier 由 scripts/g6_gate.py --cost 處理。
退出碼：0 已寫出結果（不論 state）；2 無法寫出結果。
"""
from __future__ import annotations
import argparse, json, pathlib, sys, time, urllib.error, urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from target_guard import GuardConfigError, check as guard_check  # noqa: E402

CHECK, CONTROL = "denial_of_wallet_cost", "LLM10:2025"
REJECT = {413, 429}            # 413 Payload Too Large、429 配額／速率限制：本身就是「有上限」
VALIDATION = {400, 422}        # 一般驗證錯誤（FastAPI 的 body 形狀不符也是 422）：要看錯誤內容是不是在說「太長」
_LENGTH_HINTS = ("too long", "too_long", "too large", "too_large", "max_length", "maxlength", "max length",
                 "at most", "exceed", "長度", "過長", "太長", "上限")


def _validation_kind(body: bytes) -> tuple[bool, str]:
    """400／422 回應是不是「長度上限」：回傳 (是否長度相關, 不含回應內容的摘要)。
    pydantic／FastAPI：detail 是 [{type, loc, msg, input}]，input 會回顯請求內容，所以只取 type 與 loc 當摘要。"""
    try:
        d = json.loads(body.decode("utf-8", "replace"))
    except Exception:
        d = None
    det = d.get("detail") if isinstance(d, dict) else None
    if isinstance(det, list) and det and all(isinstance(x, dict) for x in det):
        texts = [f"{x.get('type') or ''} {x.get('msg') or ''}".lower() for x in det]
        locs = [".".join(str(p) for p in x["loc"]) if isinstance(x.get("loc"), list) else "?" for x in det]
        summary = "、".join(f"{x.get('type') or '?'}@{l}" for x, l in zip(det, locs))[:200]
        return all(any(h in t for h in _LENGTH_HINTS) for t in texts), summary
    if isinstance(d, dict):
        txt = " ".join(str(d.get(k) or "") for k in ("detail", "error", "message", "msg", "code", "type"))
    else:
        txt = body[:4000].decode("utf-8", "replace")
    return any(h in txt.lower() for h in _LENGTH_HINTS), "錯誤內容非 pydantic 格式"


def _usage_total(body: bytes) -> int | None:
    try:
        d = json.loads(body.decode("utf-8", "replace"))
    except Exception:
        return None
    u = d.get("usage") if isinstance(d, dict) else None
    if not isinstance(u, dict):
        return None
    for k in ("total_tokens", "totalTokens", "total"):
        if isinstance(u.get(k), int):
            return u[k]
    parts = [u.get(k) for k in ("input_tokens", "output_tokens", "prompt_tokens", "completion_tokens")]
    nums = [x for x in parts if isinstance(x, int)]
    return sum(nums) if nums else None


# 只送往 http/https：urlopen 也接受 file:/ftp:，目標已由 target_guard 檢查，這裡再限定一次處理器
_OPENER = urllib.request.OpenerDirector()
for _h in (urllib.request.HTTPHandler(), urllib.request.HTTPSHandler(), urllib.request.HTTPErrorProcessor(),
           urllib.request.HTTPDefaultErrorHandler()):
    _OPENER.add_handler(_h)


def probe(target: str, path: str = "/chat", chars: int = 200000, max_tokens: int = 8192,
          timeout: float = 60, root: pathlib.Path | None = None) -> dict:
    url = target.rstrip("/") + path
    res = {"check": CHECK, "control_id": CONTROL, "state": "untested", "reason": None, "target_url": target,
           "evidence": {"path": path, "chars": chars, "max_tokens": max_tokens, "http_status": None,
                        "elapsed_ms": None, "usage_total_tokens": None}}
    try:
        ok, why = guard_check(target, root)
    except GuardConfigError as e:
        res["reason"] = f"目標允許清單無法讀取：{e}"
        return res
    if not ok:
        res["reason"] = f"目標未通過授權檢查：{why}"
        return res
    if not url.lower().startswith(("http://", "https://")):
        res["reason"] = "只允許 http/https"
        return res
    body = json.dumps({"message": "A" * chars, "context": "", "session_id": "vibesec-cost-probe"}).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "vibesec-g6-cost-probe"})
    t0 = time.monotonic()
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            status, raw = resp.status, resp.read(1 << 20)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(1 << 16) if e.code in VALIDATION else b""
        except Exception:
            raw = b""
        status = e.code
    except Exception as e:
        res["evidence"]["elapsed_ms"] = int((time.monotonic() - t0) * 1000)
        res["reason"] = f"請求失敗（{type(e).__name__}），無法判定成本控制"
        return res
    ev = res["evidence"]
    ev["http_status"], ev["elapsed_ms"] = status, int((time.monotonic() - t0) * 1000)
    if status in REJECT:
        res["state"], res["reason"] = "pass", f"超長輸入（{chars} 字元）被拒絕：HTTP {status}"
    elif status in VALIDATION:
        about_len, summary = _validation_kind(raw)
        if about_len:
            res["state"], res["reason"] = "pass", f"超長輸入（{chars} 字元）被長度驗證拒絕：HTTP {status}（{summary}）"
        else:
            # 例如欄位名稱不符（pydantic missing）：請求沒被當成超長訊息處理，不能當作「有長度上限」
            res["reason"] = (f"HTTP {status} 是與長度無關的驗證錯誤（{summary}），探針請求格式可能與端點不符，"
                             "無法判定成本控制")
    elif 200 <= status < 300:
        total = _usage_total(raw)
        ev["usage_total_tokens"] = total
        if total is not None and total <= max_tokens:
            res["state"], res["reason"] = "pass", f"回報的 token 用量 {total} ≤ 預算 {max_tokens}"
        elif total is not None:
            res["state"], res["reason"] = "fail", f"接受 {chars} 字元輸入，回報的 token 用量 {total} 超過預算 {max_tokens}"
        else:
            res["state"], res["reason"] = "fail", f"接受 {chars} 字元輸入（HTTP {status}），沒有長度上限、配額或可見的 token 預算"
    elif status in (401, 403):
        res["reason"] = f"端點需要認證（HTTP {status}），無法實測"
    else:
        res["reason"] = f"目標回應 HTTP {status}，無法判定成本控制"
    return res


def selftest() -> list[str]:
    import http.server, tempfile, threading
    fails: list[str] = []
    hits = {"n": 0}
    behavior = {"mode": "reject"}

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            hits["n"] += 1
            n = int(self.headers.get("Content-Length") or 0)
            try:
                self.rfile.read(n)
            except Exception:
                pass
            m = behavior["mode"]
            code, payload = {"reject": (413, b'{"detail":"too long"}'),
                             "accept": (200, b'{"reply":"ok"}'),
                             "usage_ok": (200, b'{"reply":"ok","usage":{"input_tokens":4000,"output_tokens":100}}'),
                             "usage_big": (200, b'{"reply":"ok","usage":{"total_tokens":60000}}'),
                             "auth": (401, b"{}"), "error": (500, b"{}"),
                             "pyd_len": (422, b'{"detail":[{"type":"string_too_long","loc":["body","message"],'
                                              b'"msg":"String should have at most 4000 characters","input":"AAAAAAAA"}]}'),
                             "pyd_missing": (422, b'{"detail":[{"type":"missing","loc":["body","prompt"],'
                                                  b'"msg":"Field required","input":{"message":"AAAAAAAA"}}]}'),
                             "bad_400": (400, b'{"detail":"invalid session_id"}'),
                             "len_400": (400, b'{"error":"message too long"}')}[m]
            try:
                self.send_response(code); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload)
            except Exception:
                pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        for mode, want in (("reject", "pass"), ("accept", "fail"), ("usage_ok", "pass"), ("usage_big", "fail"),
                           ("auth", "untested"), ("error", "untested"), ("pyd_len", "pass"),
                           ("pyd_missing", "untested"), ("bad_400", "untested"), ("len_400", "pass")):
            behavior["mode"] = mode
            r = probe(base, chars=10000, timeout=10)
            if r["state"] != want:
                fails.append(f"{mode}：預期 {want}，實際 {r['state']}（{r['reason']}）")
            if "AAAA" in json.dumps(r):
                fails.append(f"{mode}：結果不得保存回應內容（pydantic 的 input 會回顯請求）")
        before = hits["n"]
        r = probe("http://example.com", chars=10, timeout=5)
        if r["state"] != "untested" or "授權" not in (r["reason"] or ""):
            fails.append(f"未授權目標應 untested：{r}")
        if hits["n"] != before:
            fails.append("未授權目標不得送出請求")
        with tempfile.TemporaryDirectory() as d:
            r = probe(base, chars=10, timeout=5, root=pathlib.Path(d))
            if r["state"] != "untested" or hits["n"] != before:
                fails.append("允許清單缺席應 untested 且不送請求")
        behavior["mode"] = "accept"
        srv.shutdown(); srv.server_close()
        r = probe(base, chars=10, timeout=3)
        if r["state"] != "untested":
            fails.append(f"連線失敗應 untested：{r['state']}")
        if "AAAA" in json.dumps(r):
            fails.append("結果不得保存請求或回應內容")
    finally:
        try:
            srv.shutdown(); srv.server_close()
        except Exception:
            pass
    return fails


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["selftest"]:
        fails = selftest()
        for f in fails: print(f"FAIL {f}")
        print("selftest " + ("通過" if not fails else f"失敗 {len(fails)} 項"))
        return 1 if fails else 0
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--target", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--path", default="/chat")
    ap.add_argument("--chars", type=int, default=200000)
    ap.add_argument("--max-tokens", type=int, default=8192)
    ap.add_argument("--timeout", type=float, default=60)
    a = ap.parse_args(argv)
    r = probe(a.target, a.path, a.chars, a.max_tokens, a.timeout)
    try:
        out = pathlib.Path(a.out); out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(r, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError as e:
        print(f"無法寫出 {a.out}：{e}", file=sys.stderr)
        return 2
    print(f"G6 成本探針：{r['state']} — {r['reason']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
