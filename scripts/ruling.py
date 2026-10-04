#!/usr/bin/env python3
"""VibeSec 人工裁決工具：把 requires_human 的發現，以固定格式的裁決紀錄收斂（docs/09 §7）。

子命令：
  request <finding_id> --findings reports/findings.json   輸出貼到 PR 的「請求裁決」留言（Markdown）
  check   <ruling.yaml> --findings reports/findings.json  驗證裁決紀錄（schema + 規則），不改檔
  apply   <ruling.yaml> --findings reports/findings.json  驗證通過後，把結果寫回 findings.json
  selftest                                               內建規則自我測試（validate.py 會呼叫）

不可違反（CLAUDE.md #5、#6）：
  - 裁決者必須是人（decided_by.type = human，handle 不得是模型／bot）。
  - 模型共識不是依據：confirm 必須有 reproduced／manual_review，且附至少一筆非 model_review 的證據。
  - 每一則 minority 意見都必須逐一回應；意見本身不刪除、不覆寫。
  - 只決定 validation_status / evidence_grade / requires_human；不改嚴重度、CVSS、policy_tier、priority。
  - defer 必須附 next_review_by，且維持 pending + requires_human（不是通過）。
退出碼：0 通過；1 違反規則；2 工具缺席（缺 PyYAML／jsonschema）→ 無法驗證，不放行。
"""
from __future__ import annotations
import argparse, copy, datetime, json, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "schemas/human-ruling.schema.json"
BOT_WORDS = re.compile(r"(claude|anthropic|openai|gpt|glm|deepseek|gemini|(?<![a-z])(llm|ai|bot|agent)(?![a-z]))", re.I)
HARD_EVIDENCE = {"tool_output", "http_exchange", "code_excerpt", "trace", "human_note", "advisory"}

try:
    import yaml
    from jsonschema import Draft202012Validator
except ImportError as e:  # incomplete ≠ pass
    print(f"工具缺席：{e.name}；無法驗證裁決，視為未通過", file=sys.stderr)
    sys.exit(2)


def load_ruling(path: pathlib.Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def find_finding(doc: dict, fid: str) -> dict | None:
    return next((f for f in doc.get("findings", []) if f.get("id") == fid), None)


def minority_of(finding: dict) -> list[tuple[str, str]]:
    ops = (finding.get("review") or {}).get("opinions") or []
    return sorted({(o["role"], o["provider"]) for o in ops if o.get("minority")})


def check(ruling: dict, finding: dict | None) -> list[str]:
    """回傳違反規則的清單；空 = 通過。"""
    v = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")), format_checker=Draft202012Validator.FORMAT_CHECKER)
    errs = [f"schema：{e.message} @ {'/'.join(map(str, e.path)) or '(root)'}" for e in sorted(v.iter_errors(ruling), key=str)]
    if errs:
        return errs
    dec, basis = ruling["decision"], ruling["basis"]
    if BOT_WORDS.search(ruling["decided_by"]["handle"]) or BOT_WORDS.search(ruling["decided_by"]["role"]):
        errs.append("decided_by 看起來是模型或 bot；裁決必須由人做出")
    hard = [e for e in ruling.get("evidence_refs") or [] if e["kind"] in HARD_EVIDENCE]
    if dec == "confirm":
        if basis not in ("reproduced", "manual_review"):
            errs.append("confirm 的 basis 必須是 reproduced 或 manual_review（模型共識不是依據）")
        if not hard:
            errs.append("confirm 必須附至少一筆非 model_review 的 evidence_refs")
    elif dec == "refute":
        if basis == "insufficient_evidence":
            errs.append("證據不足應 defer，不應 refute")
        if basis in ("reproduced", "manual_review") and not hard:
            errs.append("refute 以 reproduced／manual_review 為依據時，必須附 evidence_refs")
    else:  # defer
        if basis != "insufficient_evidence":
            errs.append("defer 的 basis 必須是 insufficient_evidence")
        if not ruling.get("next_review_by"):
            errs.append("defer 必須填 next_review_by")
    if dec != "defer" and ruling.get("next_review_by"):
        errs.append("next_review_by 只用於 defer")
    if finding is None:
        errs.append(f"findings.json 找不到 {ruling['finding_id']}")
        return errs
    if not (finding.get("review") or {}).get("requires_human"):
        errs.append("此 finding 的 review.requires_human 不是 true，無需（也不得）裁決")
    need = set(minority_of(finding))
    got = {(m["role"], m["provider"]) for m in ruling["minority_acknowledged"]}
    for role, provider in sorted(need - got):
        errs.append(f"少數意見未回應：{role} / {provider}")
    for role, provider in sorted(got - need):
        errs.append(f"minority_acknowledged 列了不存在的少數意見：{role} / {provider}")
    return errs


def apply(ruling: dict, finding: dict, ruling_path: str) -> dict:
    """只改 validation_status / evidence_grade / requires_human / human_decision / ruling_ref 與 evidence_refs。"""
    f = copy.deepcopy(finding)
    dec = ruling["decision"]
    f["validation_status"] = {"confirm": "confirmed", "refute": "refuted", "defer": "pending"}[dec]
    if dec == "confirm":
        f["evidence_grade"] = "E3"       # 人工核對／重現 → E3（docs/10 §1）
    review = f.setdefault("review", {})
    review["requires_human"] = dec == "defer"
    day = ruling["decided_at"][:10]
    first = " ".join(ruling["rationale"].split())[:120]
    review["human_decision"] = f"{day} {ruling['decided_by']['handle']}（{ruling['decided_by']['role']}）：{dec} — {first}"
    review["ruling_ref"] = ruling_path
    have = {(e["kind"], e["ref"]) for e in f.get("evidence_refs", [])}
    for e in ruling.get("evidence_refs") or []:
        if (e["kind"], e["ref"]) not in have:
            f.setdefault("evidence_refs", []).append({"kind": e["kind"], "ref": e["ref"], "digest": None, "note": e.get("note")})
    return f


def request_comment(finding: dict) -> str:
    ops = (finding.get("review") or {}).get("opinions") or []
    rows = "\n".join(
        f"| {o['role']} | {o['provider']} ({o['family']}) | {o['round']} | {o['verdict']} | {'是' if o.get('minority') else ''} | {(o.get('rationale') or '').replace('|', '／')[:140]} |"
        for o in sorted(ops, key=lambda o: (o["role"], o["round"], o["provider"])))
    mino = minority_of(finding)
    mlist = "\n".join(f"- {r} / {p}" for r, p in mino) or "（無；分歧來自 family 不足或 uncertain）"
    loc = finding.get("location") or {}
    where = loc.get("path") or loc.get("url") or loc.get("package") or "—"
    return f"""### 請求人工裁決：{finding['id']}

**{finding['title']}**（{finding['gate']} · `{finding['rule_id']}` · tier `{finding['policy_tier']}`）
位置：`{where}` · 目前：`{finding['validation_status']}` / `{finding['evidence_grade']}`

模型意見（不多數決；以下全部保留）：

| 角色 | Provider (family) | 輪 | 判斷 | 少數 | 理由 |
|---|---|---|---|---|---|
{rows}

需逐一回應的少數意見：
{mlist}

**裁決者請做的事**
1. 重放或人工核對證據；模型意見只是線索，不是依據。
2. 複製 `docs/templates/human-ruling.example.yaml` 為 `rulings/{finding['id']}.yaml`，填 decision、basis、evidence_refs、rationale，並逐一回應上面的少數意見。
3. 本機檢查：`python3 scripts/ruling.py check rulings/{finding['id']}.yaml --findings reports/findings.json`
4. 開 PR 讓另一位人員審查；合併後由 harness 執行 `apply` 寫回 findings.json。

不能 confirm 的情況：只有模型意見、沒有重現或人工核對。證據不足請選 `defer` 並填 `next_review_by`。
"""


def _synthetic() -> tuple[dict, dict]:
    finding = {"id": "VS-20261003-1a2b3c4d", "gate": "G4", "rule_id": "vibesec.g4.bola", "title": "t",
               "evidence_grade": "E2", "validation_status": "pending", "policy_tier": "blocking", "severity": "high",
               "priority": None, "evidence_refs": [{"kind": "model_review", "ref": "x", "digest": None}],
               "review": {"requires_human": True, "human_decision": None, "opinions": [
                   {"role": "identity-authz", "provider": "anthropic-cloud", "family": "anthropic", "round": 3, "verdict": "confirm"},
                   {"role": "identity-authz", "provider": "openai-cloud", "family": "openai", "round": 3, "verdict": "refute", "minority": True}]}}
    ruling = yaml.safe_load((ROOT / "docs/templates/human-ruling.example.yaml").read_text(encoding="utf-8"))
    ruling["minority_acknowledged"][0].update(role="identity-authz")
    return finding, ruling


def selftest() -> list[str]:
    """回傳自我測試失敗清單（空 = 通過）。涵蓋：正例通過、各條規則會擋、apply 不碰不該碰的欄位。"""
    fails: list[str] = []
    finding, ruling = _synthetic()
    errs = check(ruling, finding)
    if errs:
        fails.append(f"範例裁決應通過：{errs}")
    out = apply(ruling, finding, "rulings/x.yaml")
    if (out["validation_status"], out["evidence_grade"], out["review"]["requires_human"]) != ("confirmed", "E3", False):
        fails.append("apply 後應為 confirmed / E3 / requires_human false")
    for k in ("severity", "policy_tier", "priority"):
        if out.get(k) != finding.get(k):
            fails.append(f"apply 不得更動 {k}")
    if out["review"]["opinions"] != finding["review"]["opinions"]:
        fails.append("apply 不得更動或刪除模型意見")

    def bad(label, mutate, expect):
        f, r = _synthetic(); mutate(f, r)
        if not any(expect in e for e in check(r, f)):
            fails.append(f"應被擋下但沒有：{label}")
    bad("模型身分裁決", lambda f, r: r["decided_by"].update(handle="claude-reviewer"), "人做出")
    bad("只有 model 共識", lambda f, r: r.update(evidence_refs=[]), "非 model_review")
    bad("confirm 以 scope_exclusion 為依據", lambda f, r: r.update(basis="scope_exclusion"), "basis 必須是")
    bad("漏回應少數意見", lambda f, r: r.update(minority_acknowledged=[]), "少數意見未回應")
    bad("defer 沒有複查日", lambda f, r: r.update(decision="defer", basis="insufficient_evidence", next_review_by=None), "next_review_by")
    bad("refute 證據不足", lambda f, r: r.update(decision="refute", basis="insufficient_evidence"), "應 defer")
    bad("非 requires_human 的 finding", lambda f, r: f["review"].update(requires_human=False), "無需")
    f, r = _synthetic(); r.update(decision="defer", basis="insufficient_evidence", next_review_by="2026-11-01", evidence_refs=[])
    if check(r, f):
        fails.append(f"合法的 defer 應通過：{check(r, f)}")
    else:
        d = apply(r, f, "rulings/x.yaml")
        if (d["validation_status"], d["review"]["requires_human"], d["evidence_grade"]) != ("pending", True, "E2"):
            fails.append("defer 應維持 pending / requires_human / 原 evidence_grade")
    if "請求人工裁決" not in request_comment(finding) or "identity-authz / openai-cloud" not in request_comment(finding):
        fails.append("request 留言應列出少數意見")
    return fails


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("request", "check", "apply"):
        p = sub.add_parser(name)
        p.add_argument("target")
        p.add_argument("--findings", default=str(ROOT / "reports/findings.json"))
    sub.add_parser("selftest")
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        fails = selftest()
        print("\n".join(f"FAIL {x}" for x in fails) or "ruling selftest ok")
        return 1 if fails else 0
    fp = pathlib.Path(a.findings)
    if not fp.exists():
        print(f"找不到 {fp}（需先執行 harness 產出 findings.json）", file=sys.stderr)
        return 2
    doc = json.loads(fp.read_text(encoding="utf-8"))
    if a.cmd == "request":
        f = find_finding(doc, a.target)
        if not f:
            print(f"findings.json 找不到 {a.target}", file=sys.stderr); return 1
        print(request_comment(f)); return 0
    rp = pathlib.Path(a.target)
    ruling = load_ruling(rp)
    finding = find_finding(doc, ruling.get("finding_id", ""))
    errs = check(ruling, finding)
    if errs:
        print("\n".join(f"違反：{e}" for e in errs), file=sys.stderr); return 1
    if a.cmd == "check":
        print(f"裁決通過檢查：{ruling['finding_id']} → {ruling['decision']}"); return 0
    new = apply(ruling, finding, str(rp.relative_to(ROOT) if rp.is_absolute() and ROOT in rp.parents else rp))
    doc["findings"] = [new if f.get("id") == new["id"] else f for f in doc["findings"]]
    fp.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"已寫回 {fp}：{new['id']} → {new['validation_status']} / {new['evidence_grade']}"
          f"{' / 仍需人工（defer）' if new['review']['requires_human'] else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
