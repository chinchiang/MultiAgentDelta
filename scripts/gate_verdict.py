#!/usr/bin/env python3
"""VibeSec 閘門判定（gate verdict）：全 repo 唯一一份「閘門狀態怎麼判」的規則（GLOSSARY.md「閘門判定」）。

以前同一條規則（blocking 優先、incomplete ≠ pass）在各閘門與三個 workflow 各寫一份、順序不一致（#120、#121
都是這裡的 bug）。現在各閘門只產出計數、控制覆蓋、未完成原因與待人工裁決，狀態一律由本 module 決定。

公開入口（interface）：
  verdict(*, blocking, coverage, problems=(), awaiting_human=(), not_applicable=None, notes=()) -> (status, status_reason)
      單一閘門的狀態。優先順序：not_applicable（呼叫端宣告）→ blocking > 0 即 fail → 未完成原因或未實測的控制
      → incomplete → 待人工裁決 → pending → pass。coverage 的 pending（待併入）不在此計入，交給 finalize。
  merge(gate, *, blocking, advisory, coverage, problems=(), tools=(), notes=()) -> gate
      把子結果（例如 G1 的 SBOM、KEV）併入閘門結果：子結果狀態由 verdict 計算，與原狀態依
      fail > incomplete > pending > pass > not_applicable 取較嚴者；coverage 依 control_id 取代。
  finalize(gate) -> gate
      最終判定：仍待併入（coverage pending）或必須併入卻缺席（REQUIRED_CONTROLS）的控制視同未實測；
      schema 的舊狀態 untested 視為 incomplete。
  is_clean(gate) -> bool
      finalize 後為 pass 或 not_applicable（夜間監測用）。
  enforce(gates, *, mode, incomplete_blocking_gates, report_only=None) -> Decision
      阻擋判定：shadow 或 report_only → 0；enforce 下政策列為「incomplete 也擋」的閘門未完成、或 mode／政策
      讀不到 → 2（優先）；有 blocking（或狀態為 fail）→ 1。Decision 含跳脫後的 Markdown 與 GitHub outputs。
  blackbox_health(gates, *, lab, required_tools, job_result="success") -> [問題]
      staging 黑箱通知：靶場看靶場驗收（fail、有 blocking、必要工具都執行），外部目標看 is_clean。

CLI（workflow 以受信任樹的這支執行；PR head 只提供 gate JSON）：
  python3 scripts/gate_verdict.py enforce --trusted-root _trusted --gate G1=reports/g1-gate.json … \\
      [--mode enforce] [--report-only 理由] [--title 標題] [--markdown-out P] [--github-output P]
  python3 scripts/gate_verdict.py blackbox --trusted-root _trusted --gate G5=… --gate G6=… [--lab] \\
      [--job-result success] [--github-output P]
  python3 scripts/gate_verdict.py selftest

輸入不合法（未知狀態、負數計數、缺 control_id、矛盾的 not_applicable）→ ValueError：那是閘門程式的 bug。
PR head 送進來的 gate JSON 由 CLI 先以 schema 驗證，不合法記 incomplete（不拋例外）。
"""
from __future__ import annotations
import argparse, copy, json, pathlib, re, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vibesec_mode import MODES, apply_override, read_mode  # noqa: E402  mode 的語意只有一份（#200）；只用標準函式庫

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATUSES = ("pass", "fail", "incomplete", "pending", "not_applicable")
COVERAGE_STATES = ("pass", "fail", "pending", "untested", "not_applicable")
RANK = {"not_applicable": 0, "pass": 1, "pending": 2, "incomplete": 3, "fail": 4}
UNFINISHED_PREFIX = "另有未完成項目："
# vibesec.yaml gates.*.tools 的名稱 → gate JSON tools[].name（由 g5_api_probes、g5_zap、g6_gate 寫入）。
# 前綴另存變數：「"api-…": "較長的識別碼字串"」會被 gitleaks generic-api-key 誤判為金鑰（#139；.gitleaksignore 已有前例）
_G5_TOOL = "vibesec-g5-"
TOOL_ALIASES = {
    "api-probes": _G5_TOOL + "api-probes",
    "promptfoo": "promptfoo-eval",
}
# vibesec.yaml 沒列、但靶場驗收一定要執行的工具（LLM10 成本面）
EXTRA_REQUIRED = {"G6": ["vibesec-g6-cost-probe"]}
LAB_GATE_KEYS = {"G5": "g5_dast_api", "G6": "g6_ai_red_team"}
# 由後續步驟併入的控制（G1：g1_sbom.py、g1_kev.py）：最終判定時缺席與待併入一樣視同未實測
REQUIRED_CONTROLS = {"G1": ("VS-G1-SBOM", "ASVS5-V15.2")}


# ------------------------------------------------------------------ 輸入檢查（不合法 → ValueError）
def _count(name, v) -> int:
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        raise ValueError(f"{name} 必須是非負整數（得到 {v!r}）")
    return v


def _coverage(coverage) -> list[dict]:
    if not isinstance(coverage, (list, tuple)):
        raise ValueError(f"coverage 必須是清單（得到 {type(coverage).__name__}）")
    for c in coverage:
        if not isinstance(c, dict) or not isinstance(c.get("control_id"), str) or not c["control_id"]:
            raise ValueError(f"coverage 項目缺 control_id：{c!r}")
        if c.get("state") not in COVERAGE_STATES:
            raise ValueError(f"coverage {c['control_id']} 的 state 不合法：{c.get('state')!r}")
    return list(coverage)


def _texts(name, items) -> list[str]:
    if isinstance(items, str) or not isinstance(items, (list, tuple, set, frozenset)):
        raise ValueError(f"{name} 必須是字串清單（得到 {items!r}）")
    out = []
    for x in items:
        if not isinstance(x, str) or not x.strip():
            raise ValueError(f"{name} 的項目必須是非空字串（得到 {x!r}）")
        out.append(x.strip())
    return out


def _dedupe(items) -> list[str]:
    return list(dict.fromkeys(items))


def _untested(coverage) -> list[str]:
    return [f"{c['control_id']} 未實測（{c['reason']}）" if c.get("reason") else f"{c['control_id']} 未實測"
            for c in coverage if c["state"] == "untested"]


# ------------------------------------------------------------------ 單一閘門
def verdict(*, blocking, coverage, problems=(), awaiting_human=(), not_applicable=None, notes=()):
    """單一閘門的 (status, status_reason)。notes 只附在理由末尾（例如「外部專案的例外未套用」），不影響狀態。"""
    blocking = _count("blocking", blocking)
    coverage = _coverage(coverage)
    problems, awaiting, notes = _texts("problems", problems), _texts("awaiting_human", awaiting_human), _texts("notes", notes)
    if not_applicable is not None:
        if not isinstance(not_applicable, str) or not not_applicable.strip():
            raise ValueError("not_applicable 必須附理由（schema：not_applicable 時 status_reason 必填）")
        if blocking or problems or awaiting:
            raise ValueError("not_applicable 不得同時有 blocking 發現、未完成原因或待人工裁決（矛盾的輸入）")
        return "not_applicable", "；".join(_dedupe([not_applicable.strip(), *notes]))
    unfinished = _dedupe(problems + _untested(coverage))
    waiting = [f"待人工裁決：{a}" for a in _dedupe(awaiting)]
    if blocking:
        parts = ([UNFINISHED_PREFIX + "；".join(unfinished)] if unfinished else []) + waiting + notes
        return "fail", "；".join(_dedupe(parts)) or None
    if unfinished:
        return "incomplete", "；".join(_dedupe(unfinished + waiting + notes))
    if waiting:
        return "pending", "；".join(_dedupe(waiting + notes))
    return "pass", "；".join(_dedupe(notes)) or None


def _status_of(gate) -> str:
    st = gate.get("status")
    if st == "untested":          # schema 的舊值：沒有證據顯示跑完 → incomplete
        return "incomplete"
    if st not in STATUSES:
        raise ValueError(f"閘門狀態不合法：{st!r}")
    return st


def _combine(parts, final) -> str | None:
    """依最終狀態組合多段理由：最終為 fail 時，非 fail 段的理由冠上「另有未完成項目：」。"""
    out = []
    for st, reason in parts:
        if not reason:
            continue
        if final == "fail" and st != "fail" and not reason.startswith(UNFINISHED_PREFIX):
            reason = UNFINISHED_PREFIX + reason
        out.append(reason)
    return "；".join(_dedupe(out)) or None


def merge(gate, *, blocking, advisory, coverage, problems=(), tools=(), notes=()):
    """把子結果併入閘門結果，回傳新的 dict（不修改 gate）。notes 與 verdict 相同：只附在理由，不影響狀態。"""
    advisory = _count("advisory", advisory)
    sub_status, sub_reason = verdict(blocking=blocking, coverage=coverage, problems=problems, notes=notes)
    g = copy.deepcopy(gate)
    base = _status_of(g)
    final = max(base, sub_status, key=RANK.__getitem__)
    g["status"], g["status_reason"] = final, _combine([(base, g.get("status_reason")), (sub_status, sub_reason)], final)
    sub_ids = {c["control_id"] for c in coverage}
    g["coverage"] = [c for c in g.get("coverage") or [] if c.get("control_id") not in sub_ids] + copy.deepcopy(list(coverage))
    fc = g.setdefault("findings_count", {"blocking": 0, "advisory": 0})
    fc["blocking"] = int(fc.get("blocking") or 0) + blocking
    fc["advisory"] = int(fc.get("advisory") or 0) + advisory
    g["tools"] = list(g.get("tools") or []) + copy.deepcopy(list(tools))
    return g


def finalize(gate):
    """最終判定，回傳新的 dict：仍待併入的控制視同未實測（GLOSSARY.md「最終判定」）。"""
    g = copy.deepcopy(gate)
    base = _status_of(g)
    cov = _coverage(g.get("coverage") or [])
    # 控制的 reason 已寫在閘門理由裡（例如 G4 的「LLM 審查未在 CI 執行」同時是未完成原因）就不再重複附上
    had = g.get("status_reason") or ""
    pend = [f"{c['control_id']} 待併入、視同未實測" + (f"（{c['reason']}）" if c.get("reason") and c["reason"] not in had else "")
            for c in cov if c["state"] == "pending"]
    have = {c["control_id"] for c in cov}
    pend += [f"{cid} 缺席（應由後續步驟併入）、視同未實測" for cid in REQUIRED_CONTROLS.get(g.get("gate"), ()) if cid not in have]
    final = max(base, "incomplete", key=RANK.__getitem__) if pend and base != "not_applicable" else base
    g["status"] = final
    if pend and base != "not_applicable":
        g["status_reason"] = _combine([(base, g.get("status_reason")), ("incomplete", "；".join(pend))], final)
    return g


def is_clean(gate) -> bool:
    return finalize(gate)["status"] in ("pass", "not_applicable")


# ------------------------------------------------------------------ 多閘門：阻擋判定與黑箱健康
class Invalid:
    """PR head 送來、無法採信的 gate JSON（缺席、無法解析、不符 schema）；blocking 為檔案自稱的值，只會更嚴。"""
    def __init__(self, reason: str, blocking: int | None = None):
        self.reason, self.blocking = reason, blocking


_MD = re.compile(r"([\\`*_\[\]()<>!|#~])")


def _cell(v) -> str:
    """受測方字串（檔名、紀錄內容）跳脫 Markdown 控制字元與 @，避免破壞表格或插入連結。"""
    return _MD.sub(r"\\\1", str(v if v is not None else "").replace("\n", " ")).replace("@", "＠")


def _row(gid, g) -> dict:
    if g is None:
        return {"gate": gid, "status": "incomplete", "label": "missing", "blocking": None, "advisory": None,
                "reason": "沒有產出閘門結果（incomplete ≠ pass）", "tools_ran": set(), "valid": False}
    if isinstance(g, Invalid):
        return {"gate": gid, "status": "incomplete", "label": "invalid", "blocking": g.blocking, "advisory": None,
                "reason": g.reason, "tools_ran": set(), "valid": False}
    f = finalize(g)
    fc = f.get("findings_count") or {}
    return {"gate": gid, "status": f["status"], "label": f["status"], "blocking": fc.get("blocking"),
            "advisory": fc.get("advisory"), "reason": f.get("status_reason") or "",
            "tools_ran": {t.get("name") for t in f.get("tools") or [] if t.get("state") == "ran"}, "valid": True}


def enforce(gates, *, mode, incomplete_blocking_gates, report_only=None, title="VibeSec 閘門狀態", errors=(), notes=()):
    """阻擋判定。gates：{閘門 ID: gate dict | Invalid | None（缺席）}；mode 為 None 表示讀不到（視同 enforce）；
    incomplete_blocking_gates 為 None 表示政策讀不到（未完成的閘門一律擋）。notes：附註（例如忽略的 --mode 降級），不影響判定。"""
    errors = list(errors)
    if mode not in MODES:
        errors.append(f"mode 無法取得（{mode!r}），視同 enforce")
        mode = "enforce"
    if incomplete_blocking_gates is None:
        errors.append("blocking-policy 無法讀取：未完成的閘門一律視為阻擋")
    rows = [_row(gid, g) for gid, g in gates.items()]
    block, notes = [], list(notes)
    code = 0
    if mode == "enforce" and not report_only:
        for r in rows:
            b = r["blocking"] or 0
            if b > 0 or r["status"] == "fail":   # 自稱 fail 卻沒有 blocking 計數：輸入矛盾，取較嚴者
                block.append(f"{r['gate']} {r['label']}（blocking {b}）"); code = code or 1
            if r["status"] in ("incomplete", "pending"):
                if incomplete_blocking_gates is None or r["gate"] in incomplete_blocking_gates:
                    block.append(f"{r['gate']} {r['label']}（政策：enforce 下未完成也擋）"); code = 2
                else:
                    notes.append(f"{r['gate']} {r['label']} 依政策只報告（不在 incomplete_gate_is_blocking_in_enforce）")
        if errors:
            code = 2
    md = [f"# {title}", "", f"模式：`{mode}`" + (f"（{report_only}）" if report_only else ""), "",
          "| 閘門 | 狀態 | blocking | advisory | 說明 |", "|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['gate']} | `{r['label']}` | {'-' if r['blocking'] is None else r['blocking']} | "
                  f"{'-' if r['advisory'] is None else r['advisory']} | {_cell(r['reason'])} |")
    md += ["", "> incomplete ≠ pass：工具缺席／逾時／API 失敗的閘門不視為通過。", ""]
    if block or errors:
        md.append("**判定：阻擋** — " + _cell("；".join(errors + block)))
    else:
        why = "shadow 只報告" if mode == "shadow" else (report_only or "沒有 blocking 發現")
        md.append(f"**判定：不阻擋**（{_cell(why)}）" + ("；" + _cell("；".join(notes)) if notes else ""))
    outputs = {}
    for r in rows:
        k = r["gate"].lower()
        outputs[f"{k}_status"] = r["label"]
        outputs[f"{k}_blocking"] = "" if r["blocking"] is None else str(r["blocking"])
    return {"code": code, "mode": mode, "rows": rows, "block": block, "notes": notes, "errors": errors,
            "markdown": "\n".join(md), "outputs": outputs}


def required_tools(cfg: dict) -> dict[str, list[str]]:
    """受信任 vibesec.yaml 的 G5／G6 tools 對應到 gate JSON 的工具名稱，加上一定要執行的工具。"""
    gates = (cfg or {}).get("gates") or {}
    out = {}
    for gid, key in LAB_GATE_KEYS.items():
        names = [TOOL_ALIASES.get(str(t), str(t)) for t in ((gates.get(key) or {}).get("tools") or [])]
        out[gid] = list(dict.fromkeys(names + EXTRA_REQUIRED.get(gid, [])))
    return out


def blackbox_health(gates, *, lab, required_tools, job_result="success") -> list[str]:
    """staging 黑箱是否需要通知（GLOSSARY.md「黑箱健康」）。回傳問題清單；空清單＝健康。"""
    problems = []
    if job_result != "success":
        problems.append(f"blackbox job 結果為 `{job_result or 'unknown'}`")
    for gid, g in gates.items():
        r = _row(gid, g)
        if r["label"] in ("missing", "invalid"):
            problems.append(f"{gid} {r['reason']}")
            continue
        if lab:
            if r["status"] != "fail" or not (r["blocking"] or 0) > 0:
                problems.append(f"{gid} 在靶場上預期 `fail` 且有 blocking，實際為 `{r['status']}`"
                                f"（blocking {r['blocking']}）：偵測能力可能退步")
            need = (required_tools or {}).get(gid)
            if not need:
                problems.append(f"{gid} 無法從受信任的 vibesec.yaml 取得必要工具清單")
            else:
                miss = [t for t in need if t not in r["tools_ran"]]
                if miss:
                    problems.append(f"{gid} 必要工具未執行（{', '.join(miss)}）：找到漏洞也不算驗收通過")
        elif r["status"] not in ("pass", "not_applicable"):
            problems.append(f"{gid} 為 `{r['status']}`（blocking {r['blocking']}）")
    return problems


# ------------------------------------------------------------------ CLI：讀檔、schema 驗證、受信任設定
def _load_gates(specs, trusted_root: pathlib.Path):
    """--gate G1=path → {G1: dict | Invalid | None}。不合法一律 Invalid（不拋例外）。"""
    try:
        from jsonschema import Draft202012Validator
        validator = Draft202012Validator(json.loads((trusted_root / "schemas/gate-result.schema.json").read_text(encoding="utf-8")))
    except Exception as e:
        validator, why = None, f"gate schema 無法載入（{type(e).__name__}），視為 incomplete"
    gates = {}
    for spec in specs:
        gid, _, path = spec.partition("=")
        p = pathlib.Path(path)
        if not p.is_file():
            gates[gid] = None; continue
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            gates[gid] = Invalid(f"gate 結果無法解析（{type(e).__name__}），視為 incomplete"); continue
        claimed = None
        if isinstance(raw, dict):
            b = (raw.get("findings_count") or {}).get("blocking") if isinstance(raw.get("findings_count"), dict) else None
            claimed = b if isinstance(b, int) and not isinstance(b, bool) and b > 0 else None
        if validator is None:
            gates[gid] = Invalid(why, claimed); continue
        errs = sorted(validator.iter_errors(raw), key=lambda e: list(e.absolute_path)) if isinstance(raw, dict) else []
        if not isinstance(raw, dict):
            gates[gid] = Invalid("gate 結果不是 JSON 物件，視為 incomplete")
        elif errs:
            where = "/".join(str(x) for x in errs[0].absolute_path) or "(root)"
            gates[gid] = Invalid(f"gate 結果不符合 schema（{where}：{errs[0].message[:120]}），視為 incomplete", claimed)
        elif raw.get("gate") != gid:
            gates[gid] = Invalid(f"gate 欄位為 {raw.get('gate')!r}，預期 {gid}，視為 incomplete", claimed)
        else:
            try:
                finalize(raw); gates[gid] = raw
            except ValueError as e:
                gates[gid] = Invalid(f"gate 結果無法判定（{e}），視為 incomplete", claimed)
    return gates


def _read_settings(trusted_root: pathlib.Path, requested_mode):
    """(mode, incomplete_blocking_gates, cfg, errors, notes)。mode 與「--mode 只能把 shadow 升為 enforce」都由
    vibesec_policy.load_policy 決定（#200：以前這裡自己讀 mode、自己寫升級規則）；讀不到（含 mode 缺席或不合法、
    --mode 不合法）→ incomplete_blocking_gates None（未完成的閘門一律擋）、記為錯誤。mode 仍以同一份 read_mode／
    apply_override 單獨讀出（政策檔壞掉不等於 mode 不明：shadow 下維持只報告，與 #200 之前相同）；mode 本身讀不到 → None
    （enforce() 視同 enforce）。cfg 是 vibesec.yaml 的內容，只給 blackbox 的 required_tools 用。"""
    errors, notes, cfg, text = [], [], None, None
    try:
        text = (trusted_root / "vibesec.yaml").read_text(encoding="utf-8")
        import yaml
        cfg = yaml.safe_load(text) or {}
    except Exception as e:
        errors.append(f"受信任的 vibesec.yaml 無法讀取（{type(e).__name__}）")
    try:
        sys.path.insert(0, str(trusted_root / "scripts"))
        from vibesec_policy import load_policy
        policy, problem = load_policy(trusted_root, project_root=None, mode_override=requested_mode)
    except Exception as e:
        policy, problem = None, f"blocking-policy 無法讀取（{type(e).__name__}）"
    if problem:
        errors.append(problem)
        mode, mode_problem = read_mode(text) if text is not None else (None, "vibesec.yaml 無法讀取")
        if mode_problem is None:
            try:
                mode, note = apply_override(mode, requested_mode)
                notes += [note] if note else []
            except ValueError:
                mode = None
        return mode, None, cfg, errors, notes
    if policy.mode_note:
        notes.append(policy.mode_note)
    return policy.mode, set(policy.incomplete_blocking_gates), cfg, errors, notes


def _write_outputs(path, pairs: dict):
    if path:
        with open(path, "a", encoding="utf-8") as f:
            for k, v in pairs.items():
                f.write(f"{k}={v}\n")


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["selftest"]:
        fails = selftest()
        for f in fails: print(f"FAIL {f}")
        print("selftest 通過" if not fails else f"selftest 失敗 {len(fails)} 項")
        return 1 if fails else 0
    ap = argparse.ArgumentParser(description="VibeSec 閘門判定")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("enforce", "blackbox"):
        p = sub.add_parser(name)
        p.add_argument("--trusted-root", required=True, type=pathlib.Path)
        p.add_argument("--gate", action="append", default=[], required=True, help="G1=reports/g1-gate.json")
        p.add_argument("--github-output")
    e = sub.choices["enforce"]
    e.add_argument("--mode"); e.add_argument("--report-only"); e.add_argument("--title", default="VibeSec 閘門狀態")
    e.add_argument("--markdown-out")
    b = sub.choices["blackbox"]
    b.add_argument("--lab", action="store_true"); b.add_argument("--job-result", default="success")
    a = ap.parse_args(argv)
    gates = _load_gates(a.gate, a.trusted_root)
    if a.cmd == "enforce":
        mode, inc, _, errs, notes = _read_settings(a.trusted_root, a.mode)
        d = enforce(gates, mode=mode, incomplete_blocking_gates=inc, report_only=a.report_only, title=a.title, errors=errs,
                    notes=notes)
        print(d["markdown"])
        if a.markdown_out:
            pathlib.Path(a.markdown_out).write_text(d["markdown"] + "\n", encoding="utf-8")
        _write_outputs(a.github_output, d["outputs"])
        return d["code"]
    cfg = _read_settings(a.trusted_root, None)[2]
    problems = blackbox_health(gates, lab=a.lab, required_tools=required_tools(cfg) if a.lab else None,
                               job_result=a.job_result)
    print(json.dumps(problems, ensure_ascii=False, indent=1))
    _write_outputs(a.github_output, {"blackbox_problems": json.dumps(problems, ensure_ascii=False)})
    return 0


# ------------------------------------------------------------------ selftest：真值表（interface 即測試面）
def selftest() -> list[str]:
    import tempfile
    fails: list[str] = []
    ok = lambda cid: {"control_id": cid, "state": "pass", "reason": None}
    unt = lambda cid, why=None: {"control_id": cid, "state": "untested", "reason": why}
    pend = lambda cid: {"control_id": cid, "state": "pending", "reason": None}

    # verdict 真值表：(blocking, coverage, problems, awaiting, not_applicable) → status
    table = [
        ("全部通過", 0, [ok("A")], [], [], None, "pass"),
        ("沒有控制也沒有問題", 0, [], [], [], None, "pass"),
        ("有 blocking", 2, [ok("A")], [], [], None, "fail"),
        ("blocking 優先於未完成原因（#121 前 G1 記 incomplete）", 1, [ok("A")], ["registry 逾時"], [], None, "fail"),
        ("blocking 優先於未實測", 1, [unt("A")], [], [], None, "fail"),
        ("blocking 優先於待人工裁決", 1, [ok("A")], [], ["F1 意見分歧"], None, "fail"),
        ("只有未完成原因", 0, [ok("A")], ["缺 token"], [], None, "incomplete"),
        ("只有未實測的控制", 0, [unt("A", "工具缺席")], [], [], None, "incomplete"),
        ("incomplete 優先於 pending", 0, [unt("A")], [], ["F1"], None, "incomplete"),
        ("只有待人工裁決", 0, [ok("A")], [], ["F1"], None, "pending"),
        ("coverage pending 不在 verdict 計入（交給 finalize）", 0, [pend("SBOM")], [], [], None, "pass"),
        ("advisory 的 coverage fail 不是閘門 fail", 0, [{"control_id": "A", "state": "fail", "reason": None}], [], [], None, "pass"),
        ("呼叫端宣告不適用", 0, [], [], [], "contains_llm: false", "not_applicable"),
    ]
    for label, b, cov, probs, wait, na, want in table:
        try:
            st, why = verdict(blocking=b, coverage=cov, problems=probs, awaiting_human=wait, not_applicable=na)
        except ValueError as e:
            fails.append(f"verdict「{label}」不應拋例外：{e}"); continue
        if st != want:
            fails.append(f"verdict「{label}」應為 {want}（得到 {st}）")
        elif st == "incomplete" and not why:
            fails.append(f"verdict「{label}」incomplete 須說明原因")
    st, why = verdict(blocking=1, coverage=[unt("A", "x")], problems=["p"], awaiting_human=["F1"], notes=["n"])
    if why != f"{UNFINISHED_PREFIX}p；A 未實測（x）；待人工裁決：F1；n":
        fails.append(f"status_reason 順序應為 problems → 未實測 → 待人工裁決 → notes（得到 {why!r}）")
    st, why = verdict(blocking=0, coverage=[], problems=["p", "p"], notes=["n"])
    if (st, why) != ("incomplete", "p；n"):
        fails.append(f"status_reason 應去重並保留 notes（得到 {(st, why)!r}）")
    if verdict(blocking=0, coverage=[], notes=["例外未套用"]) != ("pass", "例外未套用"):
        fails.append("notes 不影響狀態，只附在理由")
    for label, kw in [("blocking 為負", dict(blocking=-1, coverage=[])),
                      ("blocking 為布林", dict(blocking=True, coverage=[])),
                      ("coverage 未知 state", dict(blocking=0, coverage=[{"control_id": "A", "state": "skipped"}])),
                      ("coverage 缺 control_id", dict(blocking=0, coverage=[{"state": "pass"}])),
                      ("problems 不是清單", dict(blocking=0, coverage=[], problems="p")),
                      ("problems 有空字串", dict(blocking=0, coverage=[], problems=[""])),
                      ("not_applicable 沒有理由", dict(blocking=0, coverage=[], not_applicable=" ")),
                      ("not_applicable 卻有 blocking", dict(blocking=1, coverage=[], not_applicable="x")),
                      ("not_applicable 卻有未完成原因", dict(blocking=0, coverage=[], problems=["p"], not_applicable="x"))]:
        try:
            verdict(**kw); fails.append(f"verdict「{label}」應拋 ValueError")
        except ValueError:
            pass

    # merge：子結果依排序取較嚴者；coverage 依 control_id 取代；計數相加；理由組合
    base = {"gate": "G0", "status": "pass", "status_reason": None, "findings_count": {"blocking": 0, "advisory": 2},
            "coverage": [ok("SLOP"), pend("SBOM")], "tools": [{"name": "slop", "state": "ran"}]}
    for label, g0, kw, want in [
        ("pass + 子結果 pass", base, dict(blocking=0, advisory=0, coverage=[ok("SBOM")]), "pass"),
        ("pass + 子結果有 blocking", base, dict(blocking=1, advisory=0, coverage=[ok("SBOM")]), "fail"),
        ("pass + 子結果未實測", base, dict(blocking=0, advisory=0, coverage=[unt("SBOM", "缺 syft")]), "incomplete"),
        ("incomplete + 子結果有 blocking（blocking 優先）", {**base, "status": "incomplete", "status_reason": "registry 逾時"},
         dict(blocking=1, advisory=0, coverage=[ok("KEV")]), "fail"),
        ("fail + 子結果未實測（不降級）", {**base, "status": "fail"}, dict(blocking=0, advisory=0, coverage=[unt("KEV")]), "fail"),
        ("pending + 子結果未實測（incomplete 優先）", {**base, "status": "pending", "status_reason": "待人工裁決：F1"},
         dict(blocking=0, advisory=0, coverage=[unt("KEV")]), "incomplete"),
        ("舊狀態 untested 視為 incomplete", {**base, "status": "untested"}, dict(blocking=0, advisory=0, coverage=[]), "incomplete"),
    ]:
        m = merge(g0, **kw)
        if m["status"] != want:
            fails.append(f"merge「{label}」應為 {want}（得到 {m['status']}）")
    m = merge({**base, "status": "incomplete", "status_reason": "registry 逾時"}, blocking=1, advisory=3,
              coverage=[ok("SBOM"), ok("KEV")], tools=[{"name": "grype", "state": "ran"}])
    if m["findings_count"] != {"blocking": 1, "advisory": 5} or [c["control_id"] for c in m["coverage"]] != ["SLOP", "SBOM", "KEV"] \
            or [t["name"] for t in m["tools"]] != ["slop", "grype"] or m["status_reason"] != UNFINISHED_PREFIX + "registry 逾時":
        fails.append(f"merge 應相加計數、依 control_id 取代 coverage、附加 tools、fail 時冠上未完成前綴（得到 {m}）")
    if base["status"] != "pass" or len(base["coverage"]) != 2:
        fails.append("merge 不得修改傳入的 gate")

    # finalize／is_clean：仍待併入 → incomplete；not_applicable 不變
    if finalize(base)["status"] != "incomplete" or "SBOM 待併入" not in (finalize(base)["status_reason"] or ""):
        fails.append("finalize：coverage 仍待併入 → incomplete 並說明")
    if finalize({**base, "status": "fail", "status_reason": "x"})["status_reason"] != f"x；{UNFINISHED_PREFIX}SBOM 待併入、視同未實測":
        fails.append(f"finalize：fail 時待併入項目冠上未完成前綴（得到 {finalize({**base, 'status': 'fail', 'status_reason': 'x'})['status_reason']!r}）")
    done = merge(base, blocking=0, advisory=0, coverage=[ok("SBOM")])
    if finalize(done)["status"] != "pass" or not is_clean(done) or is_clean(base):
        fails.append("finalize／is_clean：子結果併入後為 pass；仍待併入不乾淨")
    g4 = {"gate": "G4", "status": "incomplete", "status_reason": "LLM 審查未在 CI 執行",
          "coverage": [{"control_id": "VS-G4-LLM-REVIEW", "state": "pending", "reason": "LLM 審查未在 CI 執行"}]}
    if (finalize(g4)["status_reason"] or "").count("LLM 審查未在 CI 執行") != 1 or "VS-G4-LLM-REVIEW 待併入" not in finalize(g4)["status_reason"]:
        fails.append(f"finalize：控制的 reason 已在閘門理由中就不再重複附上（得到 {finalize(g4)['status_reason']!r}）")
    if "（缺 syft）" not in (finalize({**g4, "coverage": [{**g4["coverage"][0], "reason": "缺 syft"}]})["status_reason"] or ""):
        fails.append("finalize：理由中沒有的 reason 仍要附上")
    sbom_only = merge({**base, "gate": "G1"}, blocking=0, advisory=0, coverage=[ok("SBOM"), ok("VS-G1-SBOM")])
    if finalize(sbom_only)["status"] != "incomplete" or "ASVS5-V15.2 缺席" not in (finalize(sbom_only)["status_reason"] or ""):
        fails.append(f"finalize：G1 的 KEV 控制缺席（不是 pending）也視同未實測（得到 {finalize(sbom_only)}）")
    if not is_clean(merge(sbom_only, blocking=0, advisory=0, coverage=[ok("ASVS5-V15.2")])):
        fails.append("finalize：G1 的必要控制都併入後為 pass")
    if not is_clean({**done, "gate": "G3"}):
        fails.append("finalize：必要控制只適用於 G1")
    na = {**base, "status": "not_applicable", "status_reason": "不適用", "coverage": []}
    if not is_clean(na) or finalize(na)["status"] != "not_applicable":
        fails.append("is_clean：not_applicable 算乾淨")
    if is_clean({**done, "status": "pending"}):
        fails.append("is_clean：pending 不算乾淨")

    # enforce：退出碼與 Markdown 跳脫
    g = lambda gid, st, b=0, reason=None, cov=(): {"gate": gid, "status": st, "status_reason": reason,
                                                    "findings_count": {"blocking": b, "advisory": 0}, "coverage": list(cov), "tools": []}
    inc = {"G1", "G2"}
    for label, gates, mode, rep, want in [
        ("shadow 永遠 0", {"G1": g("G1", "fail", 3)}, "shadow", None, 0),
        ("enforce 全部 pass", {"G2": g("G2", "pass"), "G3": g("G3", "pass")}, "enforce", None, 0),
        ("enforce G1 缺必要控制 → 2", {"G1": g("G1", "pass", cov=[ok("VS-G1-SBOM")])}, "enforce", None, 2),
        ("enforce 有 blocking → 1", {"G3": g("G3", "fail", 1)}, "enforce", None, 1),
        ("enforce 政策列出的閘門 incomplete → 2", {"G1": g("G1", "incomplete", reason="x")}, "enforce", None, 2),
        ("enforce 2 優先於 1", {"G1": g("G1", "incomplete", reason="x"), "G3": g("G3", "fail", 1)}, "enforce", None, 2),
        ("enforce 未列出的閘門 incomplete 只報告", {"G3": g("G3", "incomplete", reason="x")}, "enforce", None, 0),
        ("enforce 政策列出的閘門缺席 → 2", {"G1": None}, "enforce", None, 2),
        ("enforce 仍待併入經 finalize 變 incomplete → 2", {"G1": g("G1", "pass", cov=[pend("SBOM")])}, "enforce", None, 2),
        ("enforce 自稱 fail 但 blocking 為 0 → 1", {"G3": g("G3", "fail", 0)}, "enforce", None, 1),
        ("enforce 不合法但自稱有 blocking → 1", {"G3": Invalid("不符 schema", 2)}, "enforce", None, 1),
        ("mode 讀不到視同 enforce 並回 2", {"G3": g("G3", "pass")}, None, None, 2),
        ("report_only（靶場）→ 0", {"G1": g("G1", "fail", 5)}, "enforce", "靶場只報告", 0),
    ]:
        d = enforce(gates, mode=mode, incomplete_blocking_gates=inc, report_only=rep)
        if d["code"] != want:
            fails.append(f"enforce「{label}」退出碼應為 {want}（得到 {d['code']}：{d['block']} {d['errors']}）")
    d = enforce({"G3": g("G3", "incomplete", reason="see [x](http://evil) @bob |a")}, mode="enforce", incomplete_blocking_gates=None)
    if d["code"] != 2 or "\\[x\\]\\(http://evil\\)" not in d["markdown"] or "@bob" in d["markdown"] or "\\|a" not in d["markdown"]:
        fails.append("enforce：政策讀不到時未完成一律擋；Markdown 須跳脫連結、表格與 @")
    if d["outputs"] != {"g3_status": "incomplete", "g3_blocking": "0"}:
        fails.append(f"enforce outputs 應含各閘門 status／blocking（得到 {d['outputs']}）")

    # blackbox_health：靶場驗收與外部目標
    tools = lambda *names: [{"name": n, "state": "ran"} for n in names]
    req = {"G5": ["vibesec-g5-api-probes"], "G6": ["promptfoo-eval", "vibesec-g6-cost-probe"]}
    lab_ok = {"G5": {**g("G5", "fail", 3), "tools": tools("vibesec-g5-api-probes")},
              "G6": {**g("G6", "fail", 1), "tools": tools("promptfoo-eval", "vibesec-g6-cost-probe")}}
    if blackbox_health(lab_ok, lab=True, required_tools=req):
        fails.append(f"靶場：fail、有 blocking、必要工具都執行 → 健康（得到 {blackbox_health(lab_ok, lab=True, required_tools=req)}）")
    for label, gates, rt, jr in [
        ("靶場 G5 pass（偵測退步）", {**lab_ok, "G5": {**lab_ok["G5"], "status": "pass", "findings_count": {"blocking": 0, "advisory": 0}}}, req, "success"),
        ("靶場必要工具未執行", {**lab_ok, "G6": {**lab_ok["G6"], "tools": tools("promptfoo-eval")}}, req, "success"),
        ("靶場取不到必要工具清單", lab_ok, {}, "success"),
        ("job 失敗", lab_ok, req, "failure"),
        ("缺閘門結果", {**lab_ok, "G6": None}, req, "success"),
    ]:
        if not blackbox_health(gates, lab=True, required_tools=rt, job_result=jr):
            fails.append(f"blackbox_health「{label}」應回報問題")
    ext = {"G5": g("G5", "pass"), "G6": g("G6", "not_applicable", reason="不適用")}
    if blackbox_health(ext, lab=False, required_tools=None):
        fails.append("外部目標：pass／not_applicable → 健康")
    if not blackbox_health({**ext, "G5": g("G5", "incomplete", reason="缺 token")}, lab=False, required_tools=None):
        fails.append("外部目標：incomplete → 問題")
    cfg = {"gates": {"g5_dast_api": {"tools": ["zap-baseline", "api-probes"]}, "g6_ai_red_team": {"tools": ["promptfoo", "garak"]}}}
    if required_tools(cfg) != {"G5": ["zap-baseline", "vibesec-g5-api-probes"], "G6": ["promptfoo-eval", "garak", "vibesec-g6-cost-probe"]}:
        fails.append(f"required_tools 對照錯誤：{required_tools(cfg)}")

    # CLI：schema 驗證、--mode 只能升級
    with tempfile.TemporaryDirectory() as d:
        D = pathlib.Path(d)
        good = {"gate": "G3", "status": "pass", "status_reason": None, "mode": "shadow", "scope": "full",
                "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:01:00Z", "tools": [],
                "findings_count": {"blocking": 0, "advisory": 0}, "coverage": []}
        (D / "g3.json").write_text(json.dumps(good)); (D / "bad.json").write_text("{")
        (D / "g2.json").write_text(json.dumps({**good, "gate": "G2", "status": "weird"}))
        gates = _load_gates(["G3=" + str(D / "g3.json"), "G1=" + str(D / "bad.json"), "G2=" + str(D / "g2.json"),
                             "G4=" + str(D / "none.json")], ROOT)
        if not isinstance(gates["G3"], dict) or not isinstance(gates["G1"], Invalid) or not isinstance(gates["G2"], Invalid) \
                or gates["G4"] is not None:
            fails.append(f"_load_gates：合法 → dict；無法解析／不符 schema → Invalid；缺檔 → None（得到 {gates}）")
        mode, inc, _, errs, notes = _read_settings(ROOT, None)
        real = __import__("yaml").safe_load((ROOT / "vibesec.yaml").read_text(encoding="utf-8")).get("mode")
        if mode != real or errs or notes:
            fails.append(f"_read_settings：mode 取自受信任設定（{real}）（得到 {mode}，{errs}，{notes}）")
        if _read_settings(ROOT, "enforce")[0] != "enforce":
            fails.append("--mode enforce 可以升級")
        # 受信任設定是 enforce：--mode shadow 不得降級，並在 summary 註明已忽略（#200：規則在 vibesec_policy，只有一份）
        from vibesec_policy import POLICY_UNREADABLE, temp_policy_root
        with temp_policy_root() as tr:
            vbp = tr / "vibesec.yaml"
            text = vbp.read_text(encoding="utf-8")
            vbp.write_text(re.sub(r"(?m)^mode:.*$", "mode: enforce", text, count=1), encoding="utf-8")
            mode, inc, _, errs, notes = _read_settings(tr, "shadow")
            if mode != "enforce" or errs or not any("降級" in n for n in notes):
                fails.append(f"--mode shadow 不得降級受信任設定的 enforce，並附註（得到 {mode}，{errs}，{notes}）")
            d = enforce({"G3": good}, mode=mode, incomplete_blocking_gates=inc, errors=errs, notes=notes)
            if not any("降級" in n for n in d["notes"]) or "降級" not in d["markdown"] or d["code"] != 0:
                fails.append(f"忽略降級的附註寫進 summary、不影響退出碼（得到 {d['code']}：{d['markdown'][-200:]}）")
            # 受信任的 mode 缺席或不合法 → 記為錯誤（政策讀不到）、視同 enforce、退出碼 2
            for line in ("", "mode: Enforce"):
                vbp.write_text(re.sub(r"(?m)^mode:.*$", line, text, count=1), encoding="utf-8")
                mode, inc, _, errs, notes = _read_settings(tr, None)
                d = enforce({"G3": good}, mode=mode, incomplete_blocking_gates=inc, errors=errs, notes=notes)
                if d["code"] != 2 or d["mode"] != "enforce" or not any(e.startswith(POLICY_UNREADABLE + "（") for e in errs):
                    fails.append(f"受信任的 mode {line or '缺席'} → 錯誤、視同 enforce、退出碼 2（得到 {d['code']}、{d['mode']}、{errs}）")
            vbp.write_text(text, encoding="utf-8")
            # 政策檔壞掉但 mode 合法：mode 照樣讀得到（shadow 下只報告，與 #200 之前相同），未完成的閘門一律擋
            pol = tr / "config/policy/blocking-policy.yaml"
            pol_text = pol.read_text(encoding="utf-8")
            pol.write_text("blocking: [\n", encoding="utf-8")
            for req, want in ((None, real), ("enforce", "enforce")):
                mode, inc, _, errs, _ = _read_settings(tr, req)
                if mode != want or inc is not None or not errs:
                    fails.append(f"政策檔壞掉、--mode {req!r} → mode {want}、未完成的閘門一律擋、記為錯誤（得到 {mode}、{inc}、{errs}）")
            pol.write_text(pol_text, encoding="utf-8")
            if _read_settings(tr, "x")[3] == [] or _read_settings(tr, "x")[0] is not None:
                fails.append("--mode 不合法 → 記為錯誤，不得忽略")
        out = D / "out.txt"
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main(["enforce", "--trusted-root", str(ROOT), "--gate", "G3=" + str(D / "g3.json"), "--github-output", str(out)])
        if rc != 0 or "g3_status=pass" not in out.read_text():
            fails.append(f"CLI enforce：exit 0 並寫出 outputs（得到 {rc}）")
        # 受信任樹的政策檔讀不到 → enforce 下阻擋（退出碼 2），即使閘門自己報 pass：閘門腳本在政策讀不到時記 incomplete，
        # 不在 incomplete_gate_is_blocking_in_enforce 的閘門（G0、G3–G6）就靠這一道擋下（#170、#171）
        from vibesec_policy import broken_policy_root
        with broken_policy_root() as pr:
            md = D / "status.md"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = main(["enforce", "--trusted-root", str(pr), "--mode", "enforce", "--gate", "G3=" + str(D / "g3.json"),
                           "--markdown-out", str(md)])
            if rc != 2 or "**判定：阻擋**" not in md.read_text(encoding="utf-8") or "blocking-policy 無法讀取" not in md.read_text(encoding="utf-8"):
                fails.append(f"CLI enforce：受信任樹的政策檔讀不到 → 退出碼 2、判定阻擋並寫明原因（得到 {rc}）")
        out.write_text("")
        with contextlib.redirect_stdout(io.StringIO()):
            main(["blackbox", "--trusted-root", str(ROOT), "--gate", "G5=" + str(D / "none.json"), "--github-output", str(out)])
        line = out.read_text().strip()
        if not line.startswith("blackbox_problems=") or not json.loads(line.split("=", 1)[1]):
            fails.append(f"CLI blackbox：問題清單以 JSON 寫入 blackbox_problems（得到 {line!r}）")
    return fails


if __name__ == "__main__":
    sys.exit(main())
