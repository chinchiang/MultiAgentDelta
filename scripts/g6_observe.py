#!/usr/bin/env python3
"""VibeSec G6 觀測層：對授權目標送出宣告的 G6 探針，記錄結構化工具事件與用量 → 觀測檔（給 g6_gate.py --observations）。

  python3 scripts/g6_observe.py --target URL --out reports/g6-observations.json [--path /chat]
                                [--tests config/promptfoo/tests.yaml] [--timeout 60]
  python3 scripts/g6_observe.py selftest

探針：config/promptfoo/tests.yaml 的每個 test（與 promptfoo eval 同一份宣告）；body 與 promptfoo http target 相同
（message＝prompt、context＝document、tools＝逗號分隔工具清單）。以 options.transformVars 產生輸入的 test
（20 萬字元 denial_of_wallet）不送：成本面已由 g6_cost_probe.py 實測，這裡不重複放大目標成本。
安全界線（AGENTS.md 規則 8）：
  - 目標須通過 scripts/target_guard.py（config/targets.yaml）；被拒或允許清單讀不到 → 不送任何請求。
  - 每個最終 URL 須與授權目標同源（target_guard.same_origin）；不跟隨 redirect（3xx 記為該探針無法判定）。
  - 只送 http/https。
觀測檔只保存狀態碼、tool_events、usage，不保存回覆內容。判定由 scripts/llm_observations.py 負責；
觀測失敗一律是 untested（incomplete ≠ pass），由 g6_gate.py 併入。
退出碼：0 已寫出觀測檔（不論結果）；2 無法寫出。
"""
from __future__ import annotations
import argparse, json, pathlib, sys, urllib.error, urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from target_guard import GuardConfigError, check as guard_check, same_origin  # noqa: E402
import llm_observations  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA = "vibesec-g6-observations/v1"

# 只有 http/https、沒有 HTTPRedirectHandler：3xx 不跟隨（HTTPDefaultErrorHandler 會把它轉成 HTTPError）
_OPENER = urllib.request.OpenerDirector()
for _h in (urllib.request.HTTPHandler(), urllib.request.HTTPSHandler(), urllib.request.HTTPErrorProcessor(),
           urllib.request.HTTPDefaultErrorHandler()):
    _OPENER.add_handler(_h)


def load_probes(tests_path: pathlib.Path | None = None) -> list[dict]:
    """tests.yaml → [{id, check, prompt, context, tools}]；讀不到 → 例外（呼叫端記 untested）。"""
    import yaml
    d = yaml.safe_load((tests_path or ROOT / "config/promptfoo/tests.yaml").read_text(encoding="utf-8")) or {}
    defaults = ((d.get("defaultTest") or {}).get("vars")) or {}
    probes = []
    for t in d.get("tests") or []:
        if not isinstance(t, dict) or ((t.get("options") or {}).get("transformVars")):
            continue
        v = {**defaults, **(t.get("vars") or {})}
        tools = v.get("tools") or ""
        tools = [x.strip() for x in tools.split(",") if x.strip()] if isinstance(tools, str) else [str(x) for x in tools]
        md = t.get("metadata") or {}
        probes.append({"id": str(t.get("description") or md.get("vibesec_check") or "?"), "check": md.get("vibesec_check"),
                       "prompt": str(v.get("prompt") or ""), "context": str(v.get("document") or ""), "tools": tools})
    return probes


def _send(url: str, probe: dict, timeout: float) -> tuple[int | None, object, str | None]:
    body = json.dumps({"message": probe["prompt"], "context": probe.get("context") or "",
                       "tools": probe.get("tools") or [], "session_id": "vibesec-g6-observe"}).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "vibesec-g6-observe",
                                          "X-VibeSec-Run": "g6-observe"})
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            status, raw = resp.status, resp.read(1 << 20)
    except urllib.error.HTTPError as e:
        return e.code, None, None
    except Exception as e:
        return None, None, f"請求失敗（{type(e).__name__}）"
    try:
        return status, json.loads(raw.decode("utf-8", "replace")), None
    except ValueError:
        return status, None, None


def observe(target: str, probes: list[dict] | None = None, path: str = "/chat", timeout: float = 60,
            root: pathlib.Path | None = None, tests_path: pathlib.Path | None = None) -> dict:
    out = {"schema": SCHEMA, "target_url": target, "path": path, "denied": None, "probes": [], "result": None}
    try:
        ok, why = guard_check(target, root)
    except GuardConfigError as e:
        ok, why = False, f"目標允許清單無法讀取：{e}"
    url = target.rstrip("/") + path
    if ok and not url.lower().startswith(("http://", "https://")):
        ok, why = False, "只允許 http/https"
    if ok:
        same, swhy = same_origin(url, target.rstrip("/"))
        if not same:
            ok, why = False, f"非授權來源（{swhy}）"
    if not ok:
        out["denied"] = f"目標未通過授權檢查：{why}；未送出請求"
        out["result"] = {**llm_observations.evaluate([]), "reason": out["denied"]}
        return out
    if probes is None:
        try:
            probes = load_probes(tests_path)
        except Exception as e:
            out["denied"] = f"無法讀取探針宣告（{type(e).__name__}）；未送出請求"
            out["result"] = {**llm_observations.evaluate([]), "reason": out["denied"]}
            return out
    for p in probes:
        status, body, err = _send(url, p, timeout)
        rec = llm_observations.observe_response(status, body)
        if err:
            rec["error"] = err
        out["probes"].append({"id": p["id"], "check": p.get("check"), "tools_offered": list(p.get("tools") or []), **rec})
    out["result"] = llm_observations.evaluate(out["probes"])
    return out


def selftest() -> list[str]:
    import http.server, tempfile, threading
    fails: list[str] = []
    hits = {"n": 0, "other": 0}
    behavior = {"mode": "vuln"}

    class Other(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            hits["other"] += 1
            self.send_response(200); self.end_headers(); self.wfile.write(b"{}")

    other = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Other)
    threading.Thread(target=other.serve_forever, daemon=True).start()

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            hits["n"] += 1
            req = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            tools = req.get("tools") or []
            ev = [{"tool": t, "executed": True, "human_approved": False} for t in tools]
            use = {"input_tokens": 10, "output_tokens": 2, "total_tokens": 12}
            m = behavior["mode"]
            if m == "redirect":
                self.send_response(307); self.send_header("Location", f"http://127.0.0.1:{other.server_address[1]}/chat")
                self.send_header("Content-Length", "0"); self.end_headers(); return
            payload = {"vuln": {"reply": "SECRET-REPLY", "tool_events": ev, "usage": use},
                       "patched": {"reply": "ok", "tool_events": [{**e, "executed": False} for e in ev], "usage": use},
                       "no_telemetry": {"reply": "ok"}}[m]
            data = json.dumps(payload).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        probes = load_probes()
        if not any(p["tools"] for p in probes) or any(len(p["prompt"]) > 20000 for p in probes):
            fails.append("tests.yaml 應至少有一個提供工具的探針，且不送 20 萬字元的成本探針")
        for mode, want in (("vuln", "fail"), ("patched", "pass"), ("no_telemetry", "untested"), ("redirect", "untested")):
            behavior["mode"] = mode
            r = observe(base, timeout=10)
            if r["result"]["state"] != want:
                fails.append(f"{mode}：預期 {want}，實際 {r['result']['state']}（{r['result']['reason']}）")
            if "SECRET-REPLY" in json.dumps(r):
                fails.append(f"{mode}：觀測檔不得保存回覆內容")
        if hits["other"]:
            fails.append("不得跟隨 redirect 到其他來源")
        behavior["mode"] = "vuln"
        r = observe(base, timeout=10)
        if r["result"]["usage"]["probes_with_usage"] != len(probes) or r["result"]["usage"]["total_tokens"] != 12 * len(probes):
            fails.append(f"usage 應逐探針分欄加總：{r['result']['usage']}")
        before = hits["n"]
        r = observe("http://example.com", timeout=5)
        if r["result"]["state"] != "untested" or not r["denied"] or hits["n"] != before:
            fails.append(f"未授權目標應 untested 且不送請求：{r['denied']}")
        r = observe(base, path="@example.com/chat", timeout=5)
        if r["result"]["state"] != "untested" or hits["n"] != before:
            fails.append("path 造成非同源（@host）應 untested 且不送請求")
        with tempfile.TemporaryDirectory() as d:
            r = observe(base, timeout=5, root=pathlib.Path(d))
            if r["result"]["state"] != "untested" or hits["n"] != before:
                fails.append("允許清單缺席應 untested 且不送請求")
        srv.shutdown(); srv.server_close()
        r = observe(base, timeout=3)
        if r["result"]["state"] != "untested":
            fails.append(f"連線失敗應 untested：{r['result']['state']}")
    finally:
        for s in (srv, other):
            try:
                s.shutdown(); s.server_close()
            except Exception:
                pass
    return fails


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["selftest"]:
        fails = selftest() + llm_observations.selftest()
        for f in fails: print(f"FAIL {f}")
        print("selftest " + ("通過" if not fails else f"失敗 {len(fails)} 項"))
        return 1 if fails else 0
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--target", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--path", default="/chat")
    ap.add_argument("--tests", type=pathlib.Path)
    ap.add_argument("--timeout", type=float, default=60)
    a = ap.parse_args(argv)
    r = observe(a.target, path=a.path, timeout=a.timeout, tests_path=a.tests)
    try:
        out = pathlib.Path(a.out); out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(r, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError as e:
        print(f"無法寫出 {a.out}：{e}", file=sys.stderr)
        return 2
    res, u = r["result"], r["result"].get("usage") or {}
    print(f"G6 觀測層：excessive_agency={res['state']} — {res['reason']}")
    if u:
        print(f"G6 用量遙測（分欄記錄，不合成分數）：{u.get('probes_with_usage')}/{u.get('probes')} 個探針回報 usage；"
              f"input={u.get('input_tokens')} output={u.get('output_tokens')} total={u.get('total_tokens')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
