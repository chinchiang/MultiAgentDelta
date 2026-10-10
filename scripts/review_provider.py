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
  - 回應必須符合審查包要求的輸出契約：審查包的 output 要 {"opinions", "general"} 時用 review-summary，
    否則是 docs/09 §3 的單一 opinion。不是合法 JSON 或不符契約 → 重試一次，再不符 → state=error（docs/09 §1）；
    harness 不替模型改寫格式。
離開碼：0 = ran；2 = missing／timeout／error；3 = refused；4 = 參數或設定錯誤。
"""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, re, socket, sys, urllib.error, urllib.parse, urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFIDENCE_KEYS = re.compile(r"confidence|certainty|probability|信心", re.I)
VERDICTS = ("confirm", "refute", "uncertain")


class BadResponse(ValueError):
    """模型回應不是可解析的 JSON 物件：可以重試一次（與 HTTP／設定錯誤不同）。"""

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


# 只裝 HTTP／HTTPS（與代理）handler：不支援 file:// 等其他 scheme，即使 providers.yaml 的 base_url 被改壞也讀不到本機檔案
_OPENER = urllib.request.OpenerDirector()
for _h in (urllib.request.ProxyHandler(), urllib.request.HTTPHandler(), urllib.request.HTTPSHandler(),
           urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor()):
    _OPENER.add_handler(_h)


def _post(url: str, headers: dict, body: dict, timeout: float) -> dict:
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise ValueError(f"base_url 必須是 http(s)：{url!r}")
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json", **headers})
    with _OPENER.open(req, timeout=timeout) as r:
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
    choice = d['choices'][0]
    finish = choice.get('finish_reason')
    if finish is not None and finish != 'stop':
        # 過濾或截斷不是格式錯誤，不自動重試。 / Filtering or truncation is not a formatting retry.
        raise RuntimeError(f'Model response incomplete / 模型回應未完成: finish_reason={str(finish)[:100]}')
    try:
        return json.loads(choice["message"]["content"]), d.get("model"), notes
    except json.JSONDecodeError as e:
        raise BadResponse(f"回應不是合法 JSON（{e.msg}）") from None


def _anthropic(p: dict, key: str, system: str, user: str) -> tuple[dict, str | None, list[str]]:
    body = {"model": p["model"], "system": system, "max_tokens": p.get("max_tokens", 4096),
            "temperature": p.get("temperature", 0), "messages": [{"role": "user", "content": user + "\n\n只回傳 JSON。"}]}
    d = _post(p["base_url"].rstrip("/") + "/v1/messages", {"x-api-key": key, "anthropic-version": "2023-06-01"},
              body, p.get("timeout_seconds", 120))
    if d.get('stop_reason') not in (None, 'end_turn', 'stop_sequence'):
        raise RuntimeError('Anthropic response incomplete / 回應未完成: ' + str(d['stop_reason'])[:100])
    text = "".join(b.get("text", "") for b in d.get("content") or [] if b.get("type") == "text")
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise BadResponse("回應中沒有 JSON")
    try:
        return json.loads(m.group(0)), d.get("model"), []
    except json.JSONDecodeError as e:
        raise BadResponse(f"回應不是合法 JSON（{e.msg}）") from None


def _bedrock(p, key, system, user, env):
    """以明確憑證呼叫 Bedrock；不使用隱含帳號。 / Call Bedrock with explicit credentials, not an implicit identity."""
    try:
        import boto3
        from botocore.config import Config
        from botocore.exceptions import BotoCoreError, ClientError, ConnectTimeoutError, ReadTimeoutError
    except ImportError:
        raise RuntimeError("Bedrock 需要 boto3 / Bedrock requires boto3") from None
    region = p.get("aws_region", "us-east-1")
    try:
        session = boto3.Session(aws_access_key_id=key, aws_secret_access_key=env["AWS_SECRET_ACCESS_KEY"],
                                aws_session_token=env.get("AWS_SESSION_TOKEN"), region_name=region)
        client = session.client("bedrock-runtime", config=Config(connect_timeout=15,
                                read_timeout=p.get("timeout_seconds", 120), retries={"max_attempts": 0}))
        response = client.converse(modelId=p["model"], system=[{"text": system}],
                                  messages=[{"role": "user", "content": [{"text": user + "\nReturn only JSON."}]}],
                                  inferenceConfig={"maxTokens": p.get("max_tokens", 4096), "temperature": p.get("temperature", 0)})
    except (ConnectTimeoutError, ReadTimeoutError):
        raise TimeoutError("Bedrock timeout") from None
    except ClientError as e:
        raise RuntimeError("Bedrock: " + str(e.response.get("Error", {}).get("Code", "ClientError"))) from None
    except BotoCoreError as e:
        raise RuntimeError("Bedrock: " + type(e).__name__) from None
    if response.get('stopReason') not in (None, 'end_turn', 'stop_sequence'):
        raise RuntimeError('Bedrock response incomplete / 回應未完成: ' + str(response['stopReason'])[:100])
    text = "".join(part.get("text", "") for part in response.get("output", {}).get("message", {}).get("content", []))
    match = re.search(r"\{.*\}", text, re.S)
    if not match:
        raise BadResponse("Bedrock 回應缺少 JSON / Bedrock response lacks JSON")
    try:
        opinion = json.loads(match[0])
    except json.JSONDecodeError:
        raise BadResponse("Bedrock JSON 格式錯誤 / Invalid Bedrock JSON") from None
    return opinion, p["model"], ["AWS Bedrock " + region, "usage=" + json.dumps(response.get("usage", {}))]


def output_contract(packet: dict) -> str:
    """審查包要求的輸出形狀：明列 output_contract 優先；output 說明要 general 摘要者為 review-summary。"""
    if packet.get("output_contract") in ("review-summary", "finding-opinion"):
        return packet["output_contract"]
    out = packet.get("output")
    return "review-summary" if isinstance(out, str) and '"general"' in out else "finding-opinion"


def contract_errors(opinion, contract: str) -> list[str]:
    """回應不符輸出契約的原因（空 = 符合）。只檢查形狀，不判斷內容對錯。"""
    if not isinstance(opinion, dict):
        return ["回應不是 JSON 物件"]
    errs = []
    if contract == "review-summary":
        ops = opinion.get("opinions")
        if not isinstance(ops, list):
            errs.append("缺 opinions 陣列")
        else:
            for i, o in enumerate(ops):   # 每則意見都要有 verdict／rationale／cited_evidence（第四次審視 S-13）
                sub = contract_errors(o, "finding-opinion")
                if sub:
                    errs.append(f"opinions[{i}]：" + "；".join(sub)); break
        g = opinion.get("general")
        if not isinstance(g, dict) or not isinstance(g.get("summary"), str) or not isinstance(g.get("concerns"), list):
            errs.append("缺 general.summary 或 general.concerns")
        else:
            for i, c in enumerate(g["concerns"]):
                if not isinstance(c, dict) or not isinstance(c.get("title"), str) or not isinstance(c.get("cited_evidence"), list):
                    errs.append(f"general.concerns[{i}] 缺 title 或 cited_evidence"); break
        return errs
    if opinion.get("verdict") not in VERDICTS:
        errs.append("verdict 必須是 " + "／".join(VERDICTS))
    if not isinstance(opinion.get("rationale"), str):
        errs.append("缺 rationale")
    ev = opinion.get("cited_evidence")
    if not isinstance(ev, list):
        errs.append("cited_evidence 必須是陣列")
    elif not ev and opinion.get("verdict") != "uncertain":
        errs.append("cited_evidence 為空時 verdict 只能是 uncertain（docs/09 §3）")
    return errs


def redact_key(value, key):
    """供應商可能在正常或被拒絕的回應反射認證資訊；所有回傳路徑都遮罩。"""
    if not key:
        return value
    if isinstance(value, str):
        return value.replace(key, "[REDACTED sha256:" + hashlib.sha256(key.encode()).hexdigest() + "]")
    if isinstance(value, list):
        return [redact_key(item, key) for item in value]
    if isinstance(value, dict):
        return {redact_key(k, key): redact_key(v, key) for k, v in value.items()}
    return value


def call(provider: str, role: str, data_class: str, packet: dict, root: pathlib.Path = ROOT, env=os.environ) -> dict:
    p = load_provider(provider, root)
    names = [p.get("api_key_env") or ""]
    if p.get("kind") == "bedrock":
        names += ["AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]
    result = _call(provider, role, data_class, packet, root, env)
    for name in names:
        result = redact_key(result, env.get(name, ""))
    return result


def _call(provider: str, role: str, data_class: str, packet: dict, root: pathlib.Path = ROOT, env=os.environ) -> dict:
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
    if p.get("kind") == "bedrock" and not env.get("AWS_SECRET_ACCESS_KEY"):
        return {**out, "state": "missing", "note": "AWS_SECRET_ACCESS_KEY 未設定 / not configured"}
    user = ("以下是審查包（JSON）。依你的角色說明審查，只回傳角色說明定義的 JSON。\n\n"
            + json.dumps(packet, ensure_ascii=False, indent=2))
    fn = {"openai_compatible": _openai, "anthropic": _anthropic}.get(p.get("kind"))
    if p.get("kind") == "bedrock":
        fn = lambda provider, key, system, prompt: _bedrock(provider, key, system, prompt, env)
    if fn is None:
        return {**out, "state": "error", "note": f"不支援的 kind {p.get('kind')!r}"}
    contract = output_contract(packet)
    rejected: list[str] = []
    attempts: list[dict] = []   # 被拒絕的回應原樣保存（稽核用，不採用）
    prompt = user
    for _ in range(2):   # 不符契約只重試一次（docs/09 §1）；HTTP／逾時／設定錯誤不重試
        try:
            opinion, served, notes = fn(p, key, system, prompt)
        except (socket.timeout, TimeoutError):
            return {**out, "state": "timeout", "note": f"超過 {p.get('timeout_seconds', 120)} 秒"}
        except urllib.error.URLError as e:
            st = "timeout" if isinstance(getattr(e, "reason", None), (socket.timeout, TimeoutError)) else "error"
            return {**out, "state": st, "note": redact_key(str(e.reason), key)[:300]}
        except BadResponse as e:
            opinion, problems = None, [str(e)]   # 無法解析的文字不保存（資料分級；與 #66 一致）
        except (RuntimeError, ValueError, KeyError, IndexError, TypeError, AttributeError) as e:
            return {**out, "state": "error", "note": str(e).replace(key, "***")[:500]}
        else:
            problems = contract_errors(opinion, contract)
        if not problems:
            break
        rejected.append("、".join(problems))
        attempts.append({"problems": problems, "response": opinion})
        # temperature 0 下送出同一份內容只會得到同一個回應：重試時說明上次哪裡不符、應回什麼形狀。
        # 只補格式說明，不改審查包內容，也不替模型改寫結論。
        prompt = (user + "\n\n上一次回應不符輸出契約（" + "、".join(problems) + "），不採用。請只回傳一個 JSON 物件，"
                  + (f"形狀完全依照審查包的 output 欄位：{packet.get('output')}" if contract == "review-summary"
                     else "形狀依照角色說明的單一 opinion（verdict 為 confirm／refute／uncertain，含 rationale 與 cited_evidence）")
                  + "。審查內容由你重新判斷。")
    else:
        return {**out, "state": "error", "rejected_attempts": attempts,
                "note": f"回應兩次都不符輸出契約 {contract}（docs/09 §1，不採用）：" + "／".join(rejected)}
    if rejected:
        notes = [f"第 1 次回應不符輸出契約 {contract}，已附格式說明重試一次：{rejected[0]}", *notes]
    result = {**out, "state": "ran", "model": served or p.get("model"), "opinion": strip_confidence(opinion),
              "note": "；".join(notes) or None}
    if attempts:
        result["rejected_attempts"] = attempts
    return result


# ------------------------------------------------------------------ selftest
def selftest() -> list[str]:
    import http.server, tempfile, threading, time
    fails: list[str] = []
    seen: list[dict] = []
    calls: dict[str, int] = {}

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
            good = {"verdict": "confirm", "confidence": 0.9, "rationale": "r", "cited_evidence": ["a:1"]}
            summary = {"opinions": [], "general": {"summary": "s", "concerns": [{"title": "t", "cited_evidence": [{"kind": "code_excerpt", "ref": "a.py:1"}]}]}}
            model = body["model"]
            calls[model] = calls.get(model, 0) + 1
            if model == "flip":        # 第一次回錯形狀，第二次正確
                content = json.dumps(summary if calls[model] > 1 else good)
            elif model == "needhint":  # 決定性模型：同一份輸入永遠同一個回應，只有收到格式說明才改回正確形狀
                content = json.dumps(summary if "上一次回應不符輸出契約" in body["messages"][-1]["content"] else good)
            elif model == "bad":       # 一直回錯形狀
                content = json.dumps(good)
            elif model == "badconcern":   # concern 缺 cited_evidence
                content = json.dumps({"opinions": [], "general": {"summary": "s", "concerns": [{"title": "t"}]}})
            elif model == "norationale":
                content = json.dumps({k: v for k, v in good.items() if k != "rationale"})
            elif model == "badverdict":
                content = json.dumps({**good, "verdict": "yes"})
            elif model == "noopinions":   # 只有 general，缺 opinions
                content = json.dumps({"general": summary["general"]})
            elif model == "nojson":
                content = "not json"
            elif model == "noev":      # 沒有證據卻 confirm
                content = json.dumps({**good, "cited_evidence": []})
            elif model == "http500":
                self.send_response(500); self.end_headers(); self.wfile.write(b"boom"); return
            else:
                content = json.dumps(good)
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
            "off": mk("m", enabled=False), "file": mk("m", base_url="file:///etc"),
            "flip": mk("flip"), "needhint": mk("needhint"), "bad": mk("bad"), "nojson": mk("nojson"), "noopinions": mk("noopinions"), "badconcern": mk("badconcern"), "badverdict": mk("badverdict"), "norationale": mk("norationale"), "noev": mk("noev"), "http500": mk("http500")}}))
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
        r = call("file", "architecture", "internal", pk, root, env)
        if r["state"] != "error" or "http" not in (r["note"] or ""): fails.append(f"file:// base_url → error：{r}")
        r = call("notemp", "architecture", "internal", pk, root, env)
        if r["state"] != "ran" or "temperature" not in (r["note"] or ""): fails.append(f"不接受 temperature → 調整後 ran 並註記：{r}")
        # 輸出契約：G4 審查包要 {opinions, general}；不符重試一次，再不符 error，不改寫模型輸出
        g4 = {"findings": [], "output": '回傳 {"opinions": [], "general": {"summary": "…", "concerns": []}}'}
        r = call("flip", "architecture", "internal", g4, root, env)
        if r["state"] != "ran" or calls.get("flip") != 2 or "重試一次" not in (r["note"] or "") or "general" not in (r["opinion"] or {}):
            fails.append(f"第一次形狀不符 → 重試一次後 ran 並註記：{r}")
        n = len(seen)
        r = call("needhint", "architecture", "internal", g4, root, env)
        retry_msg = seen[-1]["body"]["messages"][-1]["content"] if len(seen) == n + 2 else ""
        if r["state"] != "ran" or "general" not in (r["opinion"] or {}) or g4["output"] not in retry_msg:
            fails.append(f"重試要附上不符原因與審查包的 output 形狀，決定性模型才會改正：{r}")
        if [a["response"] for a in r.get("rejected_attempts") or []] != [{"verdict": "confirm", "confidence": 0.9, "rationale": "r", "cited_evidence": ["a:1"]}]:
            fails.append(f"被拒絕的回應要原樣保存在 rejected_attempts：{r.get('rejected_attempts')}")
        if seen[n]["body"]["messages"][-1]["content"] not in retry_msg or "上一次回應不符輸出契約" in seen[n]["body"]["messages"][-1]["content"]:
            fails.append("第一次送出不含格式說明；重試保留完整審查包並附加說明")
        r = call("bad", "architecture", "internal", g4, root, env)
        if r["state"] != "error" or calls.get("bad") != 2 or r["opinion"] is not None or "兩次" not in (r["note"] or ""):
            fails.append(f"兩次形狀都不符 → error、不採用意見、只重試一次：{r}")
        if len(r.get("rejected_attempts") or []) != 2:
            fails.append(f"兩次都不符時兩個回應都要保存：{r.get('rejected_attempts')}")
        r = call("ok", "architecture", "internal", g4, root, env)
        if r["state"] != "error": fails.append(f"G4 審查包收到單一 opinion 形狀 → 不符契約：{r}")
        r = call("noopinions", "architecture", "internal", g4, root, env)
        if r["state"] != "error" or "opinions" not in (r["note"] or ""): fails.append(f"缺 opinions 陣列 → 不符契約：{r}")
        r = call("badconcern", "architecture", "internal", g4, root, env)
        if r["state"] != "error" or "concerns[0]" not in (r["note"] or ""): fails.append(f"concern 缺 cited_evidence → 不符契約：{r}")
        r = call("badverdict", "architecture", "internal", pk, root, env)
        if r["state"] != "error" or "verdict" not in (r["note"] or ""): fails.append(f"verdict 不在 confirm／refute／uncertain → 不符契約：{r}")
        r = call("norationale", "architecture", "internal", pk, root, env)
        if r["state"] != "error" or "rationale" not in (r["note"] or ""): fails.append(f"缺 rationale → 不符契約：{r}")
        r = call("nojson", "architecture", "internal", pk, root, env)
        if r["state"] != "error" or calls.get("nojson") != 2 or "JSON" not in (r["note"] or ""):
            fails.append(f"不是 JSON → 重試一次後 error：{r}")
        if [a["response"] for a in r.get("rejected_attempts") or []] != [None, None]:
            fails.append(f"不是 JSON 的回應記為 None（不保存無法解析的文字）：{r.get('rejected_attempts')}")
        r = call("noev", "architecture", "internal", pk, root, env)
        if r["state"] != "error" or "uncertain" not in (r["note"] or ""): fails.append(f"沒有證據卻 confirm → 不符契約：{r}")
        r = call("http500", "architecture", "internal", pk, root, env)
        if r["state"] != "error" or calls.get("http500") != 1: fails.append(f"HTTP 錯誤不重試：{r}／{calls.get('http500')}")
        if output_contract({"output_contract": "finding-opinion", **g4}) != "finding-opinion": fails.append("明列 output_contract 優先")
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
