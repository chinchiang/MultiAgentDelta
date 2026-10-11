#!/usr/bin/env python3
"""VibeSec 閘門彙整與判定：pr-gates.yml（summary job）與 staging-blackbox.yml（黑箱彙整與判定）共用。

用法：
  python3 scripts/gate_verdict.py --profile pr --policy-root _trusted --mode "$VIBESEC_MODE" \
      --gate G1=reports/g1-gate.json --gate G2=reports/g2-gate.json … --out reports/gate-status.md
  python3 scripts/gate_verdict.py --profile staging --policy-root _trusted --mode "$VIBESEC_MODE" [--lab] \
      --gate G5=reports/g5-gate.json --gate G6=reports/g6-gate.json
  python3 scripts/gate_verdict.py selftest

原則（CLAUDE.md 規則 1、2）：
  - mode、blocking-policy、gate schema、必要工具清單一律取自 --policy-root（CI 為 default branch 的 _trusted/）；
    PR head 只提供 gate JSON（資料）。--mode 只能把 mode 升為 enforce，不能把受信任設定的 enforce 降為 shadow。
  - 每份 gate JSON 都以 schemas/gate-result.schema.json 驗證；缺席、無法解析、不符合 schema、gate 欄位不符 → 該閘門 incomplete（附原因），絕不 pass。
  - 狀態只有 pass／fail／not_applicable／incomplete 照原樣採用；其他（untested、pending、未知字串）一律視為 incomplete。
  - enforce：blocking 發現 → exit 1；incomplete 且列在 incomplete_gate_is_blocking_in_enforce → exit 2（優先）；
    mode 或政策無法讀取 → exit 2（不知道也要擋）。shadow 永遠 exit 0（只報告）。
  - --profile pr 另外沿用舊行為：enforce 下 status 為 fail 即阻擋（即使 blocking 為 0）。
  - --lab（目標是刻意有漏洞的 examples/vulnapp）：不阻擋，但做「偵測驗收」：每個閘門必須 fail、blocking > 0，
    且 G5／G6 的必要工具（vibesec.yaml gates.*.tools 對應的 gate JSON tools 名稱，外加成本探針）都 state=ran。
    必要工具沒跑，即使找到漏洞也不算驗收通過；結果以 g5_missing_tools／g6_missing_tools 輸出給 staging-issue.js。
"""
from __future__ import annotations
import argparse, json, os, pathlib, shutil, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA = "schemas/gate-result.schema.json"
POLICY = "config/policy/blocking-policy.yaml"
TAKEN_AS_IS = ("pass", "fail", "not_applicable", "incomplete")
# vibesec.yaml gates.*.tools 的名稱 → gate JSON tools[].name（scripts/g5_zap.py、staging 探針、scripts/g6_gate.py 寫入的名稱）
TOOL_ALIASES = {"api-probes": "vibesec-g5-api-probes", "promptfoo": "promptfoo-eval"}
# vibesec.yaml 沒列、但靶場驗收一定要跑的工具（LLM10 成本面）
EXTRA_REQUIRED = {"G6": ["vibesec-g6-cost-probe"]}
LAB_GATE_KEYS = {"G5": "g5_dast_api", "G6": "g6_ai_red_team"}
MISSING = object()   # gate 檔不存在


def _yaml(path: pathlib.Path):
    import yaml
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _cell(v) -> str:
    return str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")


def load_gate(path: str):
    """回傳 dict／其他 JSON 值；檔案不存在 → MISSING；無法解析 → ('unparseable', 例外名稱)。"""
    p = pathlib.Path(path)
    if not p.is_file():
        return MISSING
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return ("unparseable", type(e).__name__)


def normalize(gid: str, raw, validator, missing_reason: str) -> dict:
    """把一份 gate 結果正規化為表格列；任何不可信的輸入都變成 incomplete（incomplete ≠ pass）。"""
    row = {"gate": gid, "status": "incomplete", "label": "incomplete", "blocking": None, "advisory": None,
           "reason": "", "tools_ran": set(), "valid": False}
    if raw is MISSING:
        row.update(label="missing", reason=missing_reason)
        return row
    if isinstance(raw, tuple):
        row["reason"] = f"gate 結果無法解析（{raw[1]}），視為 incomplete"
        return row
    if validator is None:
        row["reason"] = "缺 jsonschema，無法驗證 gate 結果，視為 incomplete"
    else:
        errors = sorted(validator.iter_errors(raw), key=lambda e: list(e.absolute_path)) if isinstance(raw, dict) else []
        if not isinstance(raw, dict):
            row["reason"] = "gate 結果不是 JSON 物件，視為 incomplete"
        elif errors:
            e = errors[0]
            where = "/".join(str(x) for x in e.absolute_path) or "(root)"
            row["reason"] = f"gate 結果不符合 schema（{where}：{e.message[:120]}），視為 incomplete"
        elif raw.get("gate") != gid:
            row["reason"] = f"gate 欄位為 {raw.get('gate')!r}，預期 {gid}，視為 incomplete"
        else:
            row["valid"] = True
    if not row["valid"]:
        # 不可信的檔案仍自稱有 blocking 發現 → 保守採計（只會更嚴，不會因 schema 錯誤而放行）
        fc = raw.get("findings_count") if isinstance(raw, dict) else None
        b = fc.get("blocking") if isinstance(fc, dict) else None
        if isinstance(b, int) and not isinstance(b, bool) and b > 0:
            row["blocking"] = b
        return row
    st, fc = raw["status"], raw["findings_count"]
    reason = raw.get("status_reason") or ""
    row.update(blocking=fc["blocking"], advisory=fc["advisory"],
               tools_ran={t["name"] for t in raw.get("tools") or [] if t.get("state") == "ran"})
    if st in TAKEN_AS_IS:
        row.update(status=st, label=st, reason=reason)
    else:
        row["reason"] = f"狀態 `{st}` 不是 pass／fail／not_applicable，視為 incomplete" + (f"；{reason}" if reason else "")
    return row


def required_tools(cfg: dict) -> dict[str, list[str]]:
    gates = (cfg or {}).get("gates") or {}
    out = {}
    for gid, key in LAB_GATE_KEYS.items():
        names = [TOOL_ALIASES.get(str(t), str(t)) for t in ((gates.get(key) or {}).get("tools") or [])]
        out[gid] = list(dict.fromkeys(names + EXTRA_REQUIRED.get(gid, [])))
    return out


def verdict(gate_paths: dict[str, str], root: pathlib.Path, requested_mode: str | None = None,
            profile: str = "pr", lab: bool = False) -> dict:
    """回傳 {code, mode, rows, block, notes, errors, lab_problems, missing_tools}；不寫任何檔案。"""
    errors, block, notes = [], [], []
    cfg = None
    try:
        cfg = _yaml(root / "vibesec.yaml")
        mode = cfg.get("mode")
    except Exception as e:
        mode = None
        errors.append(f"受信任的 vibesec.yaml 無法讀取（{type(e).__name__}）")
    if mode not in ("shadow", "enforce"):
        errors.append(f"受信任的 vibesec.yaml mode 缺席或不合法（{mode!r}）")
        mode = requested_mode if requested_mode in ("shadow", "enforce") else "missing"
    if requested_mode == "enforce":
        mode = "enforce"       # 只能升級
    elif requested_mode not in (None, "", mode) and mode == "enforce":
        notes.append(f"--mode {requested_mode} 不能降級受信任設定的 enforce")
    if requested_mode not in (None, "", "shadow", "enforce"):
        errors.append(f"--mode 不合法（{requested_mode!r}）")

    try:
        from jsonschema import Draft202012Validator
        validator = Draft202012Validator(json.loads((root / SCHEMA).read_text(encoding="utf-8")))
    except Exception as e:
        validator = None
        notes.append(f"gate schema 無法載入（{type(e).__name__}）：所有閘門視為 incomplete")

    inc_block, policy_ok = set(), True
    try:
        inc_block = set(_yaml(root / POLICY).get("incomplete_gate_is_blocking_in_enforce") or [])
    except Exception as e:
        policy_ok = False
        (errors if mode == "enforce" else notes).append(f"blocking-policy 無法讀取（{type(e).__name__}）")

    missing_reason = ("未產生 gate 結果（job 失敗或 artifact 缺席）" if profile == "pr"
                      else "沒有產出閘門結果（incomplete ≠ pass）")
    rows = [normalize(gid, load_gate(p), validator, missing_reason) for gid, p in gate_paths.items()]

    code = 2 if errors else 0
    if mode == "enforce" and not lab:
        for r in rows:
            b = r["blocking"] or 0
            if b > 0 or (profile == "pr" and r["status"] == "fail"):
                block.append(f"{r['gate']} {r['label']}（blocking {b}）"); code = code or 1
            if r["status"] == "incomplete":
                if r["gate"] in inc_block or not policy_ok:
                    block.append(f"{r['gate']} {r['label']}（政策：enforce 下 incomplete 也擋）"); code = 2
                elif profile == "staging":
                    notes.append(f"{r['gate']} {r['label']} 依政策只報告（不在 incomplete_gate_is_blocking_in_enforce），追蹤 issue 會列出")

    lab_problems, missing_tools = [], {}
    req = required_tools(cfg) if lab else {}
    for r in rows:
        need = req.get(r["gate"], [])
        missing_tools[r["gate"]] = [t for t in need if t not in r["tools_ran"]]
        if not lab:
            continue
        if r["status"] != "fail" or not (r["blocking"] or 0) > 0:
            lab_problems.append(f"{r['gate']} 預期 fail 且 blocking > 0，實際 {r['label']}（blocking {r['blocking'] if r['blocking'] is not None else '?'}）")
        if r["gate"] in req and not req[r["gate"]]:
            lab_problems.append(f"{r['gate']} 無法從受信任的 vibesec.yaml 取得必要工具清單")
            missing_tools[r["gate"]] = ["(vibesec.yaml tools 缺席)"]
        elif missing_tools[r["gate"]]:
            lab_problems.append(f"{r['gate']} 必要工具未執行（{', '.join(missing_tools[r['gate']])}）：找到漏洞也不算驗收通過")
    return {"code": code, "mode": mode, "rows": rows, "block": block, "notes": notes, "errors": errors,
            "lab_problems": lab_problems, "missing_tools": missing_tools}


def render(v: dict, profile: str, lab: bool) -> str:
    mode = v["mode"]
    if profile == "pr":
        out = ["# VibeSec 閘門狀態", "", f"模式：`{mode}`", ""]
    else:
        out = [f"# VibeSec 黑箱閘門狀態（G5 / G6；mode：`{mode}`；目標：{'靶場' if lab else '外部'}）", ""]
    out += ["| 閘門 | 狀態 | blocking | advisory | 說明 |", "|---|---|---|---|---|"]
    for r in v["rows"]:
        b = "-" if r["blocking"] is None else r["blocking"]
        a = "-" if r["advisory"] is None else r["advisory"]
        out.append(f"| {r['gate']} | `{r['label']}` | {b} | {a} | {_cell(r['reason'])} |")
    out.append("")
    if profile == "pr":
        out.append("> incomplete ≠ pass：工具缺席／逾時／API 失敗的閘門不視為通過。")
        if v["errors"] or v["notes"]:
            out += [""] + [f"- {x}" for x in v["errors"] + v["notes"]]
        return "\n".join(out)
    out += ["> 攻擊性探針僅對 config/targets.yaml 允許的目標執行；缺 token／目標限制的檢查記為 untested，incomplete ≠ pass。", ""]
    reasons = v["errors"] + v["block"]
    if reasons:
        out.append("**判定：阻擋** — " + "；".join(reasons))
    else:
        why = "shadow 只報告" if mode == "shadow" else "靶場只報告" if lab else "沒有 blocking 發現"
        out.append(f"**判定：不阻擋**（{why}）" + ("；" + "；".join(v["notes"]) if v["notes"] else ""))
    if lab:
        out += ["", "**靶場偵測驗收：通過**（G5、G6 皆 fail、有 blocking，且必要工具都已執行）" if not v["lab_problems"]
                else "**靶場偵測驗收：未通過** — " + "；".join(v["lab_problems"])]
    return "\n".join(out)


def github_outputs(v: dict) -> list[str]:
    lines = []
    for r in v["rows"]:
        g = r["gate"].lower()
        lines += [f"{g}_status={r['label']}", f"{g}_blocking={r['blocking'] if r['valid'] else ''}",
                  f"{g}_missing_tools={','.join(v['missing_tools'].get(r['gate'], []))}"]
    return lines


# ------------------------------------------------------------------ selftest
def selftest() -> list[str]:
    fails: list[str] = []
    base = {"mode": "shadow", "scope": "full", "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:01:00Z",
            "coverage": [], "status_reason": None}

    def gate(gid, status, blocking=0, advisory=0, tools=(), reason=None):
        g = dict(base, gate=gid, status=status, findings_count={"blocking": blocking, "advisory": advisory},
                 tools=[{"name": t, "state": s} for t, s in tools])
        if reason or status in ("incomplete", "not_applicable"):
            g["status_reason"] = reason or "原因"
        return g

    with tempfile.TemporaryDirectory() as d:
        root = pathlib.Path(d) / "trusted"
        (root / "schemas").mkdir(parents=True); (root / "config/policy").mkdir(parents=True)
        shutil.copy(ROOT / SCHEMA, root / SCHEMA)
        (root / POLICY).write_text("incomplete_gate_is_blocking_in_enforce: [G1, G2]\n", encoding="utf-8")
        cfg_text = ("mode: {m}\ngates:\n  g5_dast_api:\n    tools: [zap-baseline, zap-api-scan, api-probes]\n"
                    "  g6_ai_red_team:\n    tools: [promptfoo, garak]\n")
        rep = pathlib.Path(d) / "reports"; rep.mkdir()

        def put(name, obj):
            p = rep / name
            p.write_text(obj if isinstance(obj, str) else json.dumps(obj), encoding="utf-8")
            return str(p)

        def run(m, gates, profile="pr", lab=False, requested=None):
            (root / "vibesec.yaml").write_text(cfg_text.format(m=m), encoding="utf-8")
            return verdict(gates, root, requested or m, profile, lab)

        ok = {"G1": put("g1.json", gate("G1", "pass")), "G2": put("g2.json", gate("G2", "pass")),
              "G3": put("g3.json", gate("G3", "not_applicable", reason="無 IaC")), "G4": put("g4.json", gate("G4", "pass", advisory=2))}
        cases = [
            # (說明, 覆寫, mode, 預期 exit, 預期該閘門的 label)
            ("全部 pass", {}, "enforce", 0, None),
            ("G3 fail 有 blocking", {"G3": put("g3f.json", gate("G3", "fail", 2))}, "enforce", 1, ("G3", "fail")),
            ("G3 fail 有 blocking（shadow）", {"G3": put("g3f.json", gate("G3", "fail", 2))}, "shadow", 0, ("G3", "fail")),
            ("pr：G4 fail 但 blocking 0 → 仍擋（沿用舊行為）", {"G4": put("g4f.json", gate("G4", "fail", 0, 1))}, "enforce", 1, ("G4", "fail")),
            ("G1 incomplete（政策會擋）", {"G1": put("g1i.json", gate("G1", "incomplete"))}, "enforce", 2, ("G1", "incomplete")),
            ("G3 incomplete（政策不擋）", {"G3": put("g3i.json", gate("G3", "incomplete"))}, "enforce", 0, ("G3", "incomplete")),
            ("G2 untested → incomplete → 擋", {"G2": put("g2u.json", gate("G2", "untested"))}, "enforce", 2, ("G2", "incomplete")),
            ("G2 pending → incomplete → 擋", {"G2": put("g2p.json", gate("G2", "pending"))}, "enforce", 2, ("G2", "incomplete")),
            ("G1 未知狀態字串 → 不符 schema → 擋", {"G1": put("g1x.json", dict(gate("G1", "pass"), status="ok"))}, "enforce", 2, ("G1", "incomplete")),
            ("G1 缺必要欄位 → 擋", {"G1": put("g1s.json", {"gate": "G1", "status": "pass"})}, "enforce", 2, ("G1", "incomplete")),
            ("G2 無法解析 → 擋", {"G2": put("g2b.json", "{not json")}, "enforce", 2, ("G2", "incomplete")),
            ("G1 檔案缺席 → 擋", {"G1": str(rep / "nope.json")}, "enforce", 2, ("G1", "missing")),
            ("G1 gate 欄位不符（拿 G4 的檔冒充）→ 擋", {"G1": ok["G4"]}, "enforce", 2, ("G1", "incomplete")),
            ("G4 不符 schema 但自稱 blocking 3 → 保守採計", {"G4": put("g4x.json", {"gate": "G4", "findings_count": {"blocking": 3}})}, "enforce", 1, ("G4", "incomplete")),
            ("G1 缺席（shadow 不擋）", {"G1": str(rep / "nope.json")}, "shadow", 0, ("G1", "missing")),
        ]
        for desc, over, m, want, label in cases:
            v = run(m, {**ok, **over})
            if v["code"] != want:
                fails.append(f"{desc}：exit 預期 {want}，實際 {v['code']}（{v['block']}{v['errors']}）")
            if label:
                r = next(x for x in v["rows"] if x["gate"] == label[0])
                if r["label"] != label[1]:
                    fails.append(f"{desc}：{label[0]} 預期 {label[1]}，實際 {r['label']}")
                if r["status"] not in ("pass", "fail", "not_applicable", "incomplete"):
                    fails.append(f"{desc}：正規化後狀態不得為 {r['status']}")
            if any(x["status"] == "pass" and not x["valid"] for x in v["rows"]):
                fails.append(f"{desc}：不可信的 gate 結果被當成 pass")

        # 降級：受信任設定 enforce，--mode shadow 仍為 enforce
        (root / "vibesec.yaml").write_text(cfg_text.format(m="enforce"), encoding="utf-8")
        v = verdict({**ok, "G1": str(rep / "nope.json")}, root, "shadow", "pr")
        if v["mode"] != "enforce" or v["code"] != 2:
            fails.append(f"--mode shadow 不得降級 enforce：mode={v['mode']} code={v['code']}")
        # 設定不合法 → exit 2；政策檔缺席（enforce）→ exit 2
        (root / "vibesec.yaml").write_text("mode: maybe\n", encoding="utf-8")
        if verdict(ok, root, None, "pr")["code"] != 2:
            fails.append("mode 不合法應 exit 2")
        (root / POLICY).rename(root / (POLICY + ".bak"))
        if run("enforce", ok)["code"] != 2:
            fails.append("enforce 下政策檔缺席應 exit 2")
        if run("shadow", ok)["code"] != 0:
            fails.append("shadow 下政策檔缺席只報告，應 exit 0")
        (root / (POLICY + ".bak")).rename(root / POLICY)

        # staging：只有 fail 且 blocking > 0 才擋；G5／G6 都不在政策清單 → incomplete 只報告
        g5t = [("vibesec-g5-api-probes", "ran"), ("zap-api-scan", "ran"), ("zap-baseline", "ran")]
        g6t = [("promptfoo-eval", "ran"), ("garak", "ran"), ("vibesec-g6-cost-probe", "ran"), ("promptfoo-redteam", "missing")]
        g5f, g6f = put("g5f.json", gate("G5", "fail", 4, 1, g5t)), put("g6f.json", gate("G6", "fail", 3, 0, g6t))
        v = run("enforce", {"G5": g5f, "G6": g6f}, "staging")
        if v["code"] != 1:
            fails.append(f"staging 外部 fail+blocking 應 exit 1：{v['code']}")
        v = run("enforce", {"G5": put("g5a.json", gate("G5", "fail", 0, 2, g5t)), "G6": put("g6i.json", gate("G6", "untested", 0, 0, g6t))}, "staging")
        if v["code"] != 0 or not v["notes"]:
            fails.append(f"staging：fail 但 blocking 0 不擋、G6 untested 只報告：{v['code']} {v['notes']}")
        # 靶場驗收
        v = run("enforce", {"G5": g5f, "G6": g6f}, "staging", lab=True)
        if v["code"] != 0 or v["lab_problems"]:
            fails.append(f"靶場：fail+blocking 且必要工具都 ran → 驗收通過、不擋：{v['code']} {v['lab_problems']}")
        gout = github_outputs(v)
        if "g5_missing_tools=" not in gout or "g6_blocking=3" not in gout:
            fails.append(f"GITHUB_OUTPUT 內容不對：{gout}")
        g5_nozap = put("g5nz.json", gate("G5", "fail", 4, 1, [("vibesec-g5-api-probes", "ran"), ("zap-api-scan", "error"), ("zap-baseline", "ran")]))
        v = run("shadow", {"G5": g5_nozap, "G6": g6f}, "staging", lab=True)
        if not any("zap-api-scan" in p for p in v["lab_problems"]) or v["missing_tools"]["G5"] != ["zap-api-scan"]:
            fails.append(f"靶場：ZAP API 沒跑完，即使有 blocking 也不得驗收：{v['lab_problems']}")
        g6_nocost = put("g6nc.json", gate("G6", "fail", 3, 0, g6t[:2]))
        v = run("shadow", {"G5": g5f, "G6": g6_nocost}, "staging", lab=True)
        if v["missing_tools"]["G6"] != ["vibesec-g6-cost-probe"]:
            fails.append(f"靶場：成本探針是必要工具：{v['missing_tools']}")
        v = run("shadow", {"G5": str(rep / "nope.json"), "G6": put("g6p.json", gate("G6", "pass", 0, 0, g6t))}, "staging", lab=True)
        if len(v["lab_problems"]) < 2 or v["code"] != 0:
            fails.append(f"靶場：缺席／pass 都不是預期的 fail：{v['lab_problems']}")
        if "g5_status=missing" not in github_outputs(v):
            fails.append("缺席的 gate 檔要輸出 missing（staging-issue.js 依此判斷）")
        txt = render(v, "staging", True)
        if "靶場偵測驗收：未通過" not in txt or "**判定：不阻擋**（shadow 只報告）" not in txt:
            fails.append(f"staging 摘要格式不對：{txt[-200:]}")
        if "| G1 | `missing` | - | - | 未產生 gate 結果" not in render(run("shadow", {**ok, "G1": str(rep / "nope.json")}), "pr", False):
            fails.append("pr 摘要缺席列格式不對")
    return fails


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["selftest"]:
        fails = selftest()
        for f in fails: print(f"FAIL {f}")
        print("selftest " + ("通過" if not fails else f"失敗 {len(fails)} 項"))
        return 1 if fails else 0
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--profile", choices=["pr", "staging"], required=True)
    ap.add_argument("--gate", action="append", required=True, help="G1=reports/g1-gate.json（依序列出，順序即表格順序）")
    ap.add_argument("--policy-root", type=pathlib.Path, default=ROOT, help="受信任的設定根目錄（CI：_trusted）")
    ap.add_argument("--mode", help="受信任的 mode（vibesec-trusted action 的輸出）；只能升級為 enforce")
    ap.add_argument("--lab", action="store_true", help="目標是 examples/vulnapp：不阻擋，改做偵測驗收")
    ap.add_argument("--out", help="同時寫出 Markdown 摘要（例如 reports/gate-status.md）")
    a = ap.parse_args(argv)
    gates = {}
    for item in a.gate:
        gid, sep, path = item.partition("=")
        if not sep or not gid:
            ap.error(f"--gate 格式應為 G1=path：{item!r}")
        gates[gid] = path
    v = verdict(gates, a.policy_root, a.mode, a.profile, a.lab)
    text = render(v, a.profile, a.lab)
    if a.out:
        pathlib.Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(a.out).write_text(text + "\n", encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh: fh.write(text + "\n")
    if a.profile == "staging" and os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as fh: fh.write("\n".join(github_outputs(v)) + "\n")
    print(text)
    for e in v["errors"]:
        print(f"::error::{e} → exit 2")
    if a.lab and v["lab_problems"]:
        print("::warning::靶場偵測驗收未通過：" + "；".join(v["lab_problems"]))
    if v["code"] == 2 and not v["errors"]:
        print("::error::enforce 模式下 blocking 閘門 incomplete → exit 2")
    elif v["code"] == 1:
        print("::error::enforce 模式下存在 blocking 發現 → exit 1")
    return v["code"]


if __name__ == "__main__":
    sys.exit(main())
