#!/usr/bin/env python3
"""VibeSec 多模型審查：呼叫 config/providers.yaml 中的非 Claude Code provider，取得第二個 family 的意見（docs/09、SKILL.md 步驟 2.6）。

  python3 scripts/review_provider.py call --provider openai-cloud --role architecture \
      --data-class internal --packet packet.json --out opinion.json
  python3 scripts/review_provider.py selftest

規則：
  - 只送給 allowed_data_classes 包含 --data-class 的 provider；不符 → state=refused，不送出任何內容（CLAUDE.md 規則 7、docs/08 §12）。
    本工具不替內容判定分級，也不降級；分級由呼叫端依 docs/08 §12 決定。
  - 金鑰只從 api_key_env 讀，不印、不寫入輸出。缺金鑰 → state=missing；逾時 → timeout；HTTP／解析失敗 → error。
    這些狀態都不是意見，呼叫端必須照實記錄（incomplete ≠ pass，規則 2），不得補假意見。
  - system prompt = config/harness/roles/<role>.md 全文（與 sub-agent 同一份）；temperature 0、JSON 輸出。
  - 回應中的 confidence／信心類欄位一律丟棄（規則 4：模型自評信心不轉成證據等級）。
離開碼：0 = ran；2 = missing／timeout／error；3 = refused；4 = 參數或設定錯誤。
"""
from __future__ import annotations
import argparse, json, os, pathlib, re, socket, sys, urllib.error, urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFIDENCE_KEYS = re.compile(r"confidence|certainty|probability|信心", re.I)

try:
    import yaml
except ImportError:
    print("工具缺席：PyYAML", file=sys.stderr); sys.exit(4)


def load_provider(name: str, root: pathlib.Path = ROOT) -> dict:
    pv = (yaml.safe_load((root / "config/providers.yaml").read_text(encoding="utf-8")) or {}).get("providers") or {}
    if name not in pv:
        raise KeyError(f"providers.yaml 沒有 provider {name!r}")
    return {"name": name, **(pv[name] or {})}


def load_role(role: str, root: pathlib.Path = ROOT) -> tuple[str, str | None]:
    text = (root / "config/harness/roles" / f"{role}.md").read_text(encoding="utf-8")
    m = re.search(r"^prompt_version:\s*(\S+)", text, re.M)
    return text, (m.group(1) if m else None)


def strip_confidence(x):
    if isinstance(x, dict):
        return {k: strip_confidence(v) for k, v in x.items() if not CONFIDENCE_KEYS.search(str(k))}
    if isinstance(x, list):
        return [strip_confidence(v) for v in x]
    return x


def _post(url: str, headers: dict, body: dict, timeout: float) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 — URL 來自 providers.yaml
        return json.loads(r.read().decode())


def _openai(p: dict, key: str, system: str, user: str) -> tuple[dict, str | None, list[str]]:
    """Chat Completions 相容端點。部分模型不接受 temperature 或 max_tokens：遇到對應的 400 時調整一次並記在 notes。"""
    notes: list[str] = []
    body = {"model": p["model"], "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": p.get("temperature", 0), "max_tokens": p.get("max_tokens", 4096)}
    if p.get("json_mode", True):
        body["response_format"] = {"type": "json_object"}
    url = p["base_url"].rstrip("/") + "/chat/completions"
    for _ in range(3):
        try:
            d = _post(url, {"Authorization": f"Bearer {key}"}, body, p.get("timeout_seconds", 120))
            break
        except urllib.error.HTTPError as e:
            msg = e.read().decode(errors="replace")[:500]
            if e.code == 400 and "max_tokens" in msg and "max_tokens" in body:
                body["max_completion_tokens"] = body.pop("max_tokens"); notes.append("改用 max_completion_tokens"); continue
            if e.code == 400 and "temperature" in msg and "temperature" in body:
                body.pop("temperature"); notes.append("模型不接受 temperature，改用預設值（輸出可比較性下降）"); continue
            raise RuntimeError(f"HTTP {e.code}: {msg}") from None
    else:
        raise RuntimeError("參數調整後仍失敗")
    return json.loads(d["choices"][0]["message"]["content"]), d.get("model"), notes


def _anthropic(p: dict, key: str, system: str, user: str) -> tuple[dict, str | None, list[str]]:
    body = {"model": p["model"], "system": system, "max_tokens": p.get("max_tokens", 4096),
            "temperature": p.get("temperature", 0), "messages": [{"role": "user", "content": user + "\n\n只回傳 JSON。"}]}
    d = _post(p["base_url"].rstrip("/") + "/v1/messages", {"x-api-key": key, "anthropic-version": "2023-06-01"},
              body, p.get("timeout_seconds", 120))
    text = "".join(b.get("text", "") for b in d.get("content") or [] if b.get("type") == "text")
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError("回應中沒有 JSON")
    return json.loads(m.group(0)), d.get("model"), []


def call(provider: str, role: str, data_class: str, packet: dict, root: pathlib.Path = ROOT, env=os.environ) -> dict:
    p = load_provider(provider, root)
    system, prompt_version = load_role(role, root)
    out = {"provider": provider, "family": p.get("family"), "model": p.get("model"), "role": role,
           "prompt_version": prompt_version, "data_class": data_class, "state": None, "opinion": None, "note": None}
    if not p.get("enabled", False):
        return {**out, "state": "refused", "note": "provider 未啟用（enabled: false）"}
    if data_class not in (p.get("allowed_data_classes") or []):
        return {**out, "state": "refused",
                "note": f"no provider allowed for data_class={data_class}：{provider} 只收 {p.get('allowed_data_classes')}（未送出任何內容）"}
    key = env.get(p.get("api_key_env") or "", "")
    if not key:
        return {**out, "state": "missing", "note": f"{p.get('api_key_env')} 未設定"}
    user = ("以下是審查包（JSON）。依你的角色說明審查，只回傳角色說明定義的 JSON。\n\n"
            + json.dumps(packet, ensure_ascii=False, indent=2))
    fn = {"openai_compatible": _openai, "anthropic": _anthropic}.get(p.get("kind"))
    if fn is None:
        return {**out, "state": "error", "note": f"不支援的 kind {p.get('kind')!r}"}
    try:
        opinion, served, notes = fn(p, key, system, user)
    except (socket.timeout, TimeoutError):
        return {**out, "state": "timeout", "note": f"超過 {p.get('timeout_seconds', 120)} 秒"}
    except urllib.error.URLError as e:
        st = "timeout" if isinstance(getattr(e, "reason", None), (socket.timeout, TimeoutError)) else "error"
        return {**out, "state": st, "note": str(e.reason)[:300]}
    except (RuntimeError, ValueError, KeyError, IndexError) as e:
        return {**out, "state": "error", "note": str(e).replace(key, "***")[:500]}
    return {**out, "state": "ran", "model": served or p.get("model"), "opinion": strip_confidence(opinion),
            "note": "；".join(notes) or None}


# ------------------------------------------------------------------ selftest
def selftest() -> list[str]:
    import http.server, tempfile, threading, time
    fails: list[str] = []
    seen: list[dict] = []

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append({"auth": self.headers.get("Authorization"), "body": body})
            if body["model"] == "slow":
                time.sleep(2)
            if body["model"] == "no-temp" and "temperature" in body:
                self.send_response(400); self.end_headers()
                self.wfile.write(b'{"error":{"message":"Unsupported parameter: temperature"}}'); return
            content = json.dumps({"verdict": "confirm", "confidence": 0.9, "rationale": "r", "cited_evidence": ["a:1"]})
            resp = {"model": body["model"] + "-served", "choices": [{"message": {"content": content}}]}
            try:
                self.send_response(200); self.end_headers(); self.wfile.write(json.dumps(resp).encode())
            except BrokenPipeError:  # 逾時案例：用戶端已斷線
                pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    with tempfile.TemporaryDirectory() as d:
        root = pathlib.Path(d); (root / "config/harness/roles").mkdir(parents=True)
        (root / "config/harness/roles/architecture.md").write_text("---\nprompt_version: architecture@2026-01-01.1\n---\n角色\n")
        mk = lambda model, **kw: {"family": "openai", "kind": "openai_compatible", "base_url": base, "api_key_env": "K",
                                  "model": model, "timeout_seconds": 1, "allowed_data_classes": ["public", "internal"],
                                  "enabled": True, **kw}
        (root / "config/providers.yaml").write_text(yaml.safe_dump({"providers": {
            "ok": mk("m"), "slow": mk("slow"), "notemp": mk("no-temp"), "pub": mk("m", allowed_data_classes=["public"]),
            "off": mk("m", enabled=False)}}))
        env = {"K": "sk-secret-123"}
        pk = {"finding": {"id": "VS-20260101-00000000"}}
        r = call("ok", "architecture", "internal", pk, root, env)
        if r["state"] != "ran" or r["opinion"].get("verdict") != "confirm": fails.append(f"正常呼叫應 ran：{r}")
        if "confidence" in (r["opinion"] or {}): fails.append("confidence 欄位應被丟棄")
        if r["prompt_version"] != "architecture@2026-01-01.1" or r["model"] != "m-served": fails.append(f"prompt_version／model 記錄錯誤：{r}")
        if seen and (seen[-1]["body"].get("temperature") != 0 or seen[-1]["body"]["messages"][0]["content"] != "---\nprompt_version: architecture@2026-01-01.1\n---\n角色\n"):
            fails.append("應送 temperature 0 與完整 role prompt")
        if "sk-secret-123" in json.dumps(r): fails.append("輸出不得含金鑰")
        n = len(seen)
        r = call("pub", "architecture", "internal", pk, root, env)
        if r["state"] != "refused" or len(seen) != n: fails.append("分級不允許 → refused 且不得送出")
        r = call("off", "architecture", "public", pk, root, env)
        if r["state"] != "refused" or len(seen) != n: fails.append("未啟用 → refused 且不得送出")
        r = call("ok", "architecture", "internal", pk, root, {})
        if r["state"] != "missing" or len(seen) != n: fails.append("缺金鑰 → missing 且不得送出")
        r = call("slow", "architecture", "internal", pk, root, env)
        if r["state"] != "timeout": fails.append(f"逾時 → timeout：{r}")
        r = call("notemp", "architecture", "internal", pk, root, env)
        if r["state"] != "ran" or "temperature" not in (r["note"] or ""): fails.append(f"不接受 temperature → 調整後 ran 並註記：{r}")
    srv.shutdown()
    return fails


def main(argv: list[str]) -> int:
    if argv[1:2] == ["selftest"]:
        fails = selftest()
        for f in fails: print(f"FAIL {f}")
        print("selftest " + ("通過" if not fails else f"失敗 {len(fails)} 項"))
        return 1 if fails else 0
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["call"])
    ap.add_argument("--provider", required=True)
    ap.add_argument("--role", required=True, choices=["architecture", "appsec", "identity-authz", "supplychain-cicd"])
    ap.add_argument("--data-class", required=True, choices=["public", "internal", "confidential", "pii"])
    ap.add_argument("--packet", required=True, help="審查包 JSON 檔")
    ap.add_argument("--out", help="輸出檔；省略則印到 stdout")
    a = ap.parse_args(argv[1:])
    try:
        packet = json.loads(pathlib.Path(a.packet).read_text(encoding="utf-8"))
        res = call(a.provider, a.role, a.data_class, packet)
    except (OSError, ValueError, KeyError) as e:
        print(f"設定錯誤：{e}", file=sys.stderr); return 4
    text = json.dumps(res, ensure_ascii=False, indent=2)
    if a.out:
        pathlib.Path(a.out).write_text(text, encoding="utf-8")
    print(text if not a.out else f"{res['provider']} {res['state']}" + (f"：{res['note']}" if res["note"] else ""))
    return {"ran": 0, "refused": 3}.get(res["state"], 2)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
