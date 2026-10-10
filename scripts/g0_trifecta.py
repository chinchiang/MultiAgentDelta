#!/usr/bin/env python3
"""VibeSec G0：致命三要素（Lethal Trifecta）決定性檢查。

規則（docs/01 §5「致命三要素」）：agents[] 中三要素
（accesses_private_data、exposed_to_untrusted_content、can_communicate_externally）皆 true，
且沒有任何「切腳」mitigation 附可驗證證據 → vibesec.g0.lethal-trifecta-open（blocking）。
  - human_in_the_loop 是補償、不算切腳（docs/01 §5 表格），只有它通過驗證仍報。
  - trifecta_leg_cut 只是宣告：必須有切該腳的 mitigation（§5 表格）附可驗證證據，否則照報。

只判斷威脅模型「宣告」的內容；宣告是否屬實（例如 mitigation 是否真的生效）屬 G0 人工／LLM 審查範圍。

用法：python3 scripts/g0_trifecta.py [threat-model.yaml]   # 預設讀 vibesec.yaml 的 project.threat_model
離開碼：0 = 無發現；1 = 有 blocking 發現；2 = 無法讀取、為空或不符 schemas/threat-model.schema.json（incomplete，非通過）
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULE = "vibesec.g0.lethal-trifecta-open"
LEGS = ("accesses_private_data", "exposed_to_untrusted_content", "can_communicate_externally")
HITL = "human_in_the_loop"   # 補償：不算切腳，只能與 LEG_CUTS 之一並用（docs/01 §5）
LEG_CUTS = {"external_comms": ("sandbox", "egress_allowlist", "tool_allowlist"),   # docs/01 §5「切哪隻腳」表格
            "private_data": ("read_only_data",), "untrusted_content": ("no_untrusted_input",)}


def _permission_rules(path: Path) -> set[str] | None:
    """Claude Code 設定檔中 permissions.ask ∪ permissions.deny；檔案缺席或無法解析 → None。"""
    try:
        perms = (json.loads(path.read_text(encoding="utf-8")) or {}).get("permissions") or {}
    except (OSError, ValueError):
        return None
    return {str(r) for k in ("ask", "deny") for r in perms.get(k) or []}


def verify_mitigation(name: str, evidence: list[dict], root: Path, high_impact: list[str] | tuple = ()) -> tuple[bool, str]:
    """mitigation 是否有可驗證的落實：至少一筆證據，且每筆證據列出的規則都在對應設定檔的 ask／deny 中。
    有 high_impact_tools 時，任何以 claude_permission 為證據的 mitigation 都須涵蓋每個工具：證據的 covers 把工具對到規則（第四次 harness 審查 N1）。
    只驗證「每個工具至少有一條規則」，不驗證規則能擋住該工具的所有等價呼叫（前綴比對的限制見 t-hitl-bypass）。"""
    if not evidence:
        return False, f"{name}：沒有 mitigation_evidence"
    for ev in evidence:
        if ev.get("kind") != "claude_permission":
            return False, f"{name}：不支援的證據類型 {ev.get('kind')!r}"
        rel = Path(str(ev.get("ref") or ""))
        if rel.is_absolute() or ".." in rel.parts:
            return False, f"{name}：證據路徑不安全 {ev.get('ref')!r}"
        have = _permission_rules(root / rel)
        if have is None:
            return False, f"{name}：{rel} 不存在或無法解析"
        missing = [r for r in ev.get("rules") or [] if r not in have]
        if not ev.get("rules") or missing:
            return False, f"{name}：{rel} 的 ask／deny 缺 " + ("、".join(missing) if missing else "（未列規則）")
        stray = [r for rs in (ev.get("covers") or {}).values() for r in rs or [] if r not in (ev.get("rules") or [])]
        if stray:
            return False, f"{name}：covers 引用了 rules 以外的規則 " + "、".join(stray)
    if high_impact:   # 不論 mitigation 叫什麼名字：改名不能讓涵蓋檢查消失（第四次審視 S-6）
        covered = {t for ev in evidence for t, rs in (ev.get("covers") or {}).items() if rs}
        uncovered = [t for t in high_impact if t not in covered]
        if uncovered:
            return False, f"{name}：high_impact_tools 未被任何規則涵蓋 " + "、".join(uncovered)
    return True, f"{name}：已由 " + "、".join(str(e.get("ref")) for e in evidence) + " 落實"


def _tier(root: Path = ROOT) -> str:
    """tier 只來自本 repo（VibeSec）的 blocking-policy，不讀被檢查專案的政策檔——否則被測專案放一份自己的
    blocking-policy.yaml 就能把本規則降為 advisory（--target）。政策檔無法讀取或解析（含 YAMLError、結構不符）
    時退回 blocking（fail closed）。root 只供 selftest 指向壞政策檔。"""
    try:
        sys.path.insert(0, str(ROOT / "scripts"))
        from vibesec_policy import Policy
        return Policy(root).tier(RULE)
    except Exception:   # yaml.YAMLError 不是 ValueError 的子類別；任何讀取失敗都不得讓本規則消失或降級
        return "blocking"


def load_threat_model(path: Path) -> tuple[dict | None, str | None]:
    """讀取並以 schemas/threat-model.schema.json 驗證威脅模型 → (模型, None) 或 (None, 理由)。
    空檔、{}、不符 schema、缺 jsonschema 都是「無法判定」，不是「沒有發現」（incomplete ≠ pass）。"""
    try:
        import yaml
    except ImportError:
        return None, "工具缺席：PyYAML，無法讀取威脅模型"
    try:
        tm = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError) as e:
        return None, f"無法讀取威脅模型：{type(e).__name__}: {e}"
    if not isinstance(tm, dict) or not tm:
        return None, f"威脅模型 {path} 為空或不是物件"
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        return None, "工具缺席：jsonschema，無法驗證威脅模型是否符合 schema"
    try:
        schema = json.loads((ROOT / "schemas/threat-model.schema.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return None, f"無法讀取 threat-model schema：{type(e).__name__}: {e}"
    errs = sorted(Draft202012Validator(schema).iter_errors(tm), key=str)
    if errs:
        return None, (f"{path} 不符 threat-model schema：{errs[0].message} @ {'/'.join(map(str, errs[0].path)) or '(root)'}"
                      + (f"（共 {len(errs)} 處）" if len(errs) > 1 else ""))
    return tm, None


def trifecta_findings(threat_model: dict, root: Path | None = None) -> list[dict]:
    """三要素皆成立，且沒有任何「切腳」mitigation 有可驗證證據 → 發現。
    只宣告 mitigation 名稱不算數（第二次 harness 審查發現 A：宣告與落實不符時 fail-open）；同理：
      - human_in_the_loop 不算切腳（docs/01 §5），只有它通過驗證仍報；
      - trifecta_leg_cut 只是宣告，宣告了也要有切該腳的 mitigation 附可驗證證據（否則改一個欄位就能跳過檢查）。
    root：mitigation_evidence 的 ref 相對的專案根目錄（被檢查的專案）；tier 一律取自本 repo 的政策。"""
    root = root or ROOT
    out = []
    for a in (threat_model or {}).get("agents") or []:
        if not all(a.get(k) is True for k in LEGS):
            continue
        leg = a.get("trifecta_leg_cut")
        cutters = LEG_CUTS.get(leg, ()) if leg is not None else tuple(m for ms in LEG_CUTS.values() for m in ms)
        evid = a.get("mitigation_evidence") or {}
        results = {m: verify_mitigation(m, evid.get(m) or [], root, a.get("high_impact_tools") or [])
                   for m in a.get("mitigations") or []}
        if any(ok for m, (ok, _) in results.items() if m in cutters):
            continue
        why = [msg for _, msg in results.values()] or ["沒有 mitigation"]
        if results.get(HITL, (False,))[0]:
            why.append(f"{HITL} 是補償、不算切腳，須與切腳的 mitigation 並用")
        if leg is not None and not any(m in cutters for m in results):
            why.append(f"宣告 trifecta_leg_cut: {leg}，但 mitigations 沒有切這隻腳的項目（{'、'.join(cutters) or '無'}）")
        head = (f"宣告切斷 {leg}，但沒有切該腳且可驗證的 mitigation" if leg is not None
                else "未切斷任何一腳，且沒有可驗證的切腳 mitigation")
        out.append({"rule_id": RULE, "control_id": "VS-G0-LETHAL-TRIFECTA", "policy_tier": _tier(),
                    "agent": a.get("id"),
                    "reason": f"agent {a.get('id')!r} 三要素皆成立、{head}（{'；'.join(why)}）"})
    return out


def selftest() -> list[str]:
    import tempfile
    fails: list[str] = []
    agent = lambda **kw: {"agents": [{"id": "a", "accesses_private_data": True, "exposed_to_untrusted_content": True,
                                      "can_communicate_externally": True, "trifecta_leg_cut": None, **kw}]}
    ev = lambda rules, ref=".claude/settings.json", m="human_in_the_loop": {m: [{"kind": "claude_permission", "ref": ref, "rules": rules}]}
    cov = lambda rules, covers, m="human_in_the_loop": {m: [{"kind": "claude_permission", "ref": ".claude/settings.json",
                                                             "rules": rules, "covers": covers}]}
    with tempfile.TemporaryDirectory() as d:
        root = Path(d); (root / ".claude").mkdir()
        (root / ".claude/settings.json").write_text(json.dumps({"permissions": {"ask": ["mcp__x__merge"], "deny": ["Bash(rm *)"]}}))
        TA = "tool_allowlist"
        cases = [
            ("無 mitigation", agent(mitigations=[]), True),
            ("只宣告、無證據", agent(mitigations=[TA]), True),
            ("證據規則不在設定檔", agent(mitigations=[TA], mitigation_evidence=ev(["mcp__x__other"], m=TA)), True),
            ("證據檔不存在", agent(mitigations=[TA], mitigation_evidence=ev(["mcp__x__merge"], "nope.json", m=TA)), True),
            ("證據路徑跳出 repo", agent(mitigations=[TA], mitigation_evidence=ev(["mcp__x__merge"], "../x.json", m=TA)), True),
            ("ask＋deny 皆涵蓋", agent(mitigations=[TA], mitigation_evidence=ev(["mcp__x__merge", "Bash(rm *)"], m=TA)), False),
            # docs/01 §5：human_in_the_loop 不算切腳——證據再完整，只有它仍報
            ("只有 HITL（證據完整）", agent(mitigations=["human_in_the_loop"], mitigation_evidence=ev(["mcp__x__merge", "Bash(rm *)"])), True),
            ("只有 HITL（high_impact_tools 全涵蓋）", agent(mitigations=["human_in_the_loop"], high_impact_tools=["merge", "rm"],
                mitigation_evidence=cov(["mcp__x__merge", "Bash(rm *)"], {"merge": ["mcp__x__merge"], "rm": ["Bash(rm *)"]})), True),
            ("HITL ＋ 可驗證的切腳 mitigation", agent(mitigations=[TA, "human_in_the_loop"],
                mitigation_evidence={**ev(["Bash(rm *)"], m=TA), **ev(["mcp__x__merge"])}), False),
            # trifecta_leg_cut 只是宣告：須有切該腳的 mitigation 且證據可驗證
            ("只宣告切腳、無 mitigation", agent(mitigations=[], trifecta_leg_cut="external_comms"), True),
            ("宣告切腳、mitigation 無證據", agent(mitigations=["egress_allowlist"], trifecta_leg_cut="external_comms"), True),
            ("宣告切腳、只有 HITL 證據", agent(mitigations=["human_in_the_loop"], trifecta_leg_cut="external_comms",
                mitigation_evidence=ev(["mcp__x__merge"])), True),
            ("宣告切腳、證據屬於切別腳的 mitigation", agent(mitigations=[TA], trifecta_leg_cut="private_data",
                mitigation_evidence=ev(["mcp__x__merge"], m=TA)), True),
            ("宣告切腳、切該腳的 mitigation 可驗證", agent(mitigations=[TA], trifecta_leg_cut="external_comms",
                mitigation_evidence=ev(["mcp__x__merge"], m=TA)), False),
            ("一項可驗證即可", agent(mitigations=["egress_allowlist", TA], mitigation_evidence=ev(["mcp__x__merge"], m=TA)), False),
            ("high_impact_tools 全涵蓋", agent(mitigations=[TA], high_impact_tools=["merge", "rm"],
                mitigation_evidence=cov(["mcp__x__merge", "Bash(rm *)"], {"merge": ["mcp__x__merge"], "rm": ["Bash(rm *)"]}, m=TA)), False),
            ("high_impact_tools 有未涵蓋者", agent(mitigations=[TA], high_impact_tools=["merge", "rm"],
                mitigation_evidence=cov(["mcp__x__merge", "Bash(rm *)"], {"merge": ["mcp__x__merge"]}, m=TA)), True),
            ("high_impact_tools 但沒有 covers", agent(mitigations=[TA], high_impact_tools=["merge"],
                mitigation_evidence=ev(["mcp__x__merge"], m=TA)), True),
            ("covers 引用 rules 以外的規則", agent(mitigations=[TA], high_impact_tools=["merge"],
                mitigation_evidence=cov(["mcp__x__merge"], {"merge": ["mcp__x__other"]}, m=TA)), True),
            ("改名 mitigation 也要涵蓋高影響工具", agent(mitigations=["egress_allowlist"], high_impact_tools=["merge"],
                mitigation_evidence={"egress_allowlist": [{"kind": "claude_permission", "ref": ".claude/settings.json", "rules": ["Bash(rm *)"]}]}), True),
        ]
        for label, tm, expect in cases:
            if bool(trifecta_findings(tm, root)) != expect:
                fails.append(f"{label}：預期 {'有' if expect else '無'}發現")
        (root / "config/policy").mkdir(parents=True)
        (root / "config/policy/blocking-policy.yaml").write_text(
            "version: 1\ndefault_tier: advisory\nblocking: []\nadvisory: [{rule_id: %s}]\n" % RULE)
        (root / "vibesec.yaml").write_text("risk_tier: L1\n")
        got = trifecta_findings(agent(mitigations=[]), root)
        if not got or got[0]["policy_tier"] != "blocking":
            fails.append("tier 取自本 repo 的政策，不讀被檢查專案的 blocking-policy.yaml")
        # 政策檔是壞 YAML → 退回 blocking，不拋出例外
        (root / "config/policy/blocking-policy.yaml").write_text("blocking: [\n  - {rule_id: x\n")
        try:
            if _tier(root) != "blocking":
                fails.append("政策檔 YAML 壞掉時 tier 應退回 blocking")
        except Exception as e:
            fails.append(f"政策檔 YAML 壞掉時不應拋出例外：{type(e).__name__}")
        # 獨立 CLI：空檔、{}、不符 schema → 離開碼 2（incomplete），不是 0（無發現）
        import contextlib, io
        for label, body in [("空檔", ""), ("{}", "{}\n"), ("不符 schema", "agents: []\n"), ("壞 YAML", "a: [\n")]:
            (root / "tm.yaml").write_text(body)
            with contextlib.redirect_stdout(io.StringIO()):
                rc = main(["g0_trifecta.py", str(root / "tm.yaml")])
            if rc != 2:
                fails.append(f"威脅模型為{label} → 離開碼 2（incomplete），得到 {rc}")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main(["g0_trifecta.py", str(ROOT / "docs/templates/threat-model.yaml")])
        if rc == 2:
            fails.append("符合 schema 的威脅模型不應為 incomplete")
    return fails


def main(argv: list[str]) -> int:
    if argv[1:2] == ["selftest"]:
        fails = selftest()
        for f in fails: print(f"FAIL {f}")
        print("selftest " + ("通過" if not fails else f"失敗 {len(fails)} 項"))
        return 1 if fails else 0
    def incomplete(reason: str) -> int:
        print(json.dumps({"gate": "G0", "status": "incomplete", "status_reason": reason}, ensure_ascii=False))
        return 2
    if len(argv) > 1:
        path = Path(argv[1])
    else:
        try:
            import yaml
            vb = yaml.safe_load((ROOT / "vibesec.yaml").read_text(encoding="utf-8")) or {}
            rel = (vb.get("project") or {}).get("threat_model") or ""
        except Exception as e:   # 缺 PyYAML、讀不到、YAMLError、結構不符
            return incomplete(f"無法從 vibesec.yaml 取得 project.threat_model：{type(e).__name__}: {e}")
        if not rel:
            return incomplete("vibesec.yaml 未設定 project.threat_model")
        path = ROOT / rel
    tm, err = load_threat_model(path)
    if err:
        return incomplete(err)
    findings = trifecta_findings(tm)
    print(json.dumps({"gate": "G0", "findings": findings}, ensure_ascii=False, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
