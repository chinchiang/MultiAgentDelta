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
  - 每個最終 URL 須與授權目標同源（AuthorizedTarget.request）；不跟隨 redirect（3xx 記為該探針無法判定）。
  - 只送 http/https。
觀測檔只保存狀態碼、tool_events、usage，不保存回覆內容。判定由 scripts/llm_observations.py 負責；
觀測失敗一律是 untested（incomplete ≠ pass），由 g6_gate.py 併入。
退出碼：0 已寫出觀測檔（不論結果）；2 無法寫出。
"""
from __future__ import annotations
import argparse, json, pathlib, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from target_guard import (  # noqa: E402
    HttpResponse,
    OffOrigin,
    TargetDenied,
    TargetTransport,
    TransportError,
    authorize_target,
)
import llm_observations  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA = "vibesec-g6-observations/v1"
USER_AGENT = "vibesec-g6-observe"


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


def _denied_out(out: dict, message: str) -> dict:
    out["denied"] = message
    out["result"] = {**llm_observations.evaluate([]), "reason": message}
    return out


def observe(
    target: str,
    probes: list[dict] | None = None,
    path: str = "/chat",
    timeout: float = 60,
    root: pathlib.Path | None = None,
    tests_path: pathlib.Path | None = None,
    *,
    transport: TargetTransport | None = None,
) -> dict:
    out: dict = {"schema": SCHEMA, "target_url": target, "path": path, "denied": None, "probes": [], "result": None}
    auth = authorize_target(target, root=root, transport=transport, user_agent=USER_AGENT)
    if isinstance(auth, TargetDenied):
        return _denied_out(out, f"目標未通過授權檢查：{auth.reason}；未送出請求")
    if probes is None:
        try:
            probes = load_probes(tests_path)
        except Exception as e:
            return _denied_out(out, f"無法讀取探針宣告（{type(e).__name__}）；未送出請求")
    for p in probes:
        outcome = auth.request(
            path,
            method="POST",
            json_body={
                "message": p["prompt"],
                "context": p.get("context") or "",
                "tools": p.get("tools") or [],
                "session_id": "vibesec-g6-observe",
            },
            headers={"X-VibeSec-Run": "g6-observe"},
            timeout=timeout,
        )
        if isinstance(outcome, OffOrigin):
            out["probes"].clear()
            return _denied_out(out, f"目標未通過授權檢查：非授權來源（{outcome.reason}）；未送出請求")
        if isinstance(outcome, TransportError):
            rec = llm_observations.observe_response(None, None)
            rec["error"] = outcome.reason
        else:
            assert isinstance(outcome, HttpResponse)
            body = outcome.json() if outcome.status == 200 else None
            rec = llm_observations.observe_response(outcome.status, body)
        out["probes"].append({"id": p["id"], "check": p.get("check"), "tools_offered": list(p.get("tools") or []), **rec})
    out["result"] = llm_observations.evaluate(out["probes"])
    return out


def selftest() -> list[str]:
    """輕量離線煙霧測試（完整狀態真值表已移至 tests/test_g6_and_zap.py）。"""
    import tempfile
    fails: list[str] = []
    probes = load_probes()
    if not any(p["tools"] for p in probes) or any(len(p["prompt"]) > 20000 for p in probes):
        fails.append("tests.yaml 應至少有一個提供工具的探針，且不送 20 萬字元的成本探針")
    r_unlisted = observe("http://example.com", timeout=5)
    if r_unlisted["result"]["state"] != "untested" or not r_unlisted["denied"]:
        fails.append(f"未授權目標應 untested：{r_unlisted['denied']}")
    r_off = observe("http://127.0.0.1:8000", path="@example.com/chat", timeout=5)
    if r_off["result"]["state"] != "untested" or "非授權來源" not in (r_off["denied"] or ""):
        fails.append(f"path 造成非同源（@host）應 untested：{r_off['denied']}")
    with tempfile.TemporaryDirectory() as d:
        r_missing = observe("http://127.0.0.1:8000", timeout=5, root=pathlib.Path(d))
        if r_missing["result"]["state"] != "untested" or "目標允許清單無法讀取" not in (r_missing["denied"] or ""):
            fails.append(f"允許清單缺席應 untested：{r_missing['denied']}")
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
