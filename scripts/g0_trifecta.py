#!/usr/bin/env python3
"""VibeSec G0：致命三要素（Lethal Trifecta）決定性檢查。

規則（docs/01「Lethal Trifecta」）：agents[] 中三要素
（accesses_private_data、exposed_to_untrusted_content、can_communicate_externally）皆 true，
且 mitigations 為空、trifecta_leg_cut 為 null → vibesec.g0.lethal-trifecta-open（blocking）。

只判斷威脅模型「宣告」的內容；宣告是否屬實（例如 mitigation 是否真的生效）屬 G0 人工／LLM 審查範圍。

用法：python3 scripts/g0_trifecta.py [threat-model.yaml]   # 預設讀 vibesec.yaml 的 project.threat_model
離開碼：0 = 無發現；1 = 有 blocking 發現；2 = 無法讀取（incomplete，非通過）
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULE = "vibesec.g0.lethal-trifecta-open"
LEGS = ("accesses_private_data", "exposed_to_untrusted_content", "can_communicate_externally")


def _permission_rules(path: Path) -> set[str] | None:
    """Claude Code 設定檔中 permissions.ask ∪ permissions.deny；檔案缺席或無法解析 → None。"""
    try:
        perms = (json.loads(path.read_text(encoding="utf-8")) or {}).get("permissions") or {}
    except (OSError, ValueError):
        return None
    return {str(r) for k in ("ask", "deny") for r in perms.get(k) or []}


def verify_mitigation(name: str, evidence: list[dict], root: Path, high_impact: list[str] | tuple = ()) -> tuple[bool, str]:
    """mitigation 是否有可驗證的落實：至少一筆證據，且每筆證據列出的規則都在對應設定檔的 ask／deny 中。
    human_in_the_loop 另須涵蓋 agent 的每個 high_impact_tools：證據的 covers 把工具對到規則（第四次 harness 審查 N1）。
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
    if name == "human_in_the_loop" and high_impact:
        covered = {t for ev in evidence for t, rs in (ev.get("covers") or {}).items() if rs}
        uncovered = [t for t in high_impact if t not in covered]
        if uncovered:
            return False, f"{name}：high_impact_tools 未被任何規則涵蓋 " + "、".join(uncovered)
    return True, f"{name}：已由 " + "、".join(str(e.get("ref")) for e in evidence) + " 落實"


def _tier() -> str:
    """tier 只來自本 repo（VibeSec）的 blocking-policy，不讀被檢查專案的政策檔——否則被測專案放一份自己的
    blocking-policy.yaml 就能把本規則降為 advisory（--target）。政策檔無法讀取時退回 blocking（fail closed）。"""
    try:
        sys.path.insert(0, str(ROOT / "scripts"))
        from vibesec_policy import Policy
        return Policy(ROOT).tier(RULE)
    except (OSError, ValueError):
        return "blocking"


def trifecta_findings(threat_model: dict, root: Path | None = None) -> list[dict]:
    """三要素皆成立、未切腳，且沒有任何「有可驗證證據」的 mitigation → 發現。
    只宣告 mitigation 名稱不算數（第二次 harness 審查發現 A：宣告與落實不符時 fail-open）。
    root：mitigation_evidence 的 ref 相對的專案根目錄（被檢查的專案）；tier 一律取自本 repo 的政策。"""
    root = root or ROOT
    out = []
    for a in (threat_model or {}).get("agents") or []:
        if not all(a.get(k) is True for k in LEGS) or a.get("trifecta_leg_cut") is not None:
            continue
        evid = a.get("mitigation_evidence") or {}
        results = [verify_mitigation(m, evid.get(m) or [], root, a.get("high_impact_tools") or [])
                   for m in a.get("mitigations") or []]
        if any(ok for ok, _ in results):
            continue
        why = "；".join(msg for _, msg in results) if results else "沒有 mitigation"
        out.append({"rule_id": RULE, "control_id": "VS-G0-LETHAL-TRIFECTA", "policy_tier": _tier(),
                    "agent": a.get("id"),
                    "reason": f"agent {a.get('id')!r} 三要素皆成立、未切斷任何一腳，且沒有可驗證的 mitigation（{why}）"})
    return out


def selftest() -> list[str]:
    import tempfile
    fails: list[str] = []
    agent = lambda **kw: {"agents": [{"id": "a", "accesses_private_data": True, "exposed_to_untrusted_content": True,
                                      "can_communicate_externally": True, "trifecta_leg_cut": None, **kw}]}
    ev = lambda rules, ref=".claude/settings.json": {"human_in_the_loop": [{"kind": "claude_permission", "ref": ref, "rules": rules}]}
    cov = lambda rules, covers: {"human_in_the_loop": [{"kind": "claude_permission", "ref": ".claude/settings.json",
                                                        "rules": rules, "covers": covers}]}
    with tempfile.TemporaryDirectory() as d:
        root = Path(d); (root / ".claude").mkdir()
        (root / ".claude/settings.json").write_text(json.dumps({"permissions": {"ask": ["mcp__x__merge"], "deny": ["Bash(rm *)"]}}))
        cases = [
            ("無 mitigation", agent(mitigations=[]), True),
            ("只宣告、無證據", agent(mitigations=["human_in_the_loop"]), True),
            ("證據規則不在設定檔", agent(mitigations=["human_in_the_loop"], mitigation_evidence=ev(["mcp__x__other"])), True),
            ("證據檔不存在", agent(mitigations=["human_in_the_loop"], mitigation_evidence=ev(["mcp__x__merge"], "nope.json")), True),
            ("證據路徑跳出 repo", agent(mitigations=["human_in_the_loop"], mitigation_evidence=ev(["mcp__x__merge"], "../x.json")), True),
            ("ask＋deny 皆涵蓋", agent(mitigations=["human_in_the_loop"], mitigation_evidence=ev(["mcp__x__merge", "Bash(rm *)"])), False),
            ("已切腳", agent(mitigations=[], trifecta_leg_cut="external_comms"), False),
            ("一項可驗證即可", agent(mitigations=["tool_allowlist", "human_in_the_loop"], mitigation_evidence=ev(["mcp__x__merge"])), False),
            ("high_impact_tools 全涵蓋", agent(mitigations=["human_in_the_loop"], high_impact_tools=["merge", "rm"],
                mitigation_evidence=cov(["mcp__x__merge", "Bash(rm *)"], {"merge": ["mcp__x__merge"], "rm": ["Bash(rm *)"]})), False),
            ("high_impact_tools 有未涵蓋者", agent(mitigations=["human_in_the_loop"], high_impact_tools=["merge", "rm"],
                mitigation_evidence=cov(["mcp__x__merge", "Bash(rm *)"], {"merge": ["mcp__x__merge"]})), True),
            ("high_impact_tools 但沒有 covers", agent(mitigations=["human_in_the_loop"], high_impact_tools=["merge"],
                mitigation_evidence=ev(["mcp__x__merge"])), True),
            ("covers 引用 rules 以外的規則", agent(mitigations=["human_in_the_loop"], high_impact_tools=["merge"],
                mitigation_evidence=cov(["mcp__x__merge"], {"merge": ["mcp__x__other"]})), True),
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
    return fails


def main(argv: list[str]) -> int:
    if argv[1:2] == ["selftest"]:
        fails = selftest()
        for f in fails: print(f"FAIL {f}")
        print("selftest " + ("通過" if not fails else f"失敗 {len(fails)} 項"))
        return 1 if fails else 0
    import yaml
    try:
        if len(argv) > 1:
            path = Path(argv[1])
        else:
            vb = yaml.safe_load((ROOT / "vibesec.yaml").read_text(encoding="utf-8")) or {}
            path = ROOT / ((vb.get("project") or {}).get("threat_model") or "")
        tm = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as e:
        print(json.dumps({"gate": "G0", "status": "incomplete", "status_reason": f"無法讀取威脅模型：{e}"},
                         ensure_ascii=False))
        return 2
    findings = trifecta_findings(tm)
    print(json.dumps({"gate": "G0", "findings": findings}, ensure_ascii=False, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
