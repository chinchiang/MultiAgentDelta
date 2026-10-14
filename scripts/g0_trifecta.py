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
ALL_CUTS = frozenset(m for ms in LEG_CUTS.values() for m in ms)


def _permission_rules(path: Path, kinds: tuple[str, ...] = ("ask", "deny")) -> set[str] | None:
    """Claude Code 設定檔中 kinds 指定的 permissions 清單聯集；檔案缺席或無法解析 → None。"""
    try:
        perms = (json.loads(path.read_text(encoding="utf-8")) or {}).get("permissions") or {}
    except (OSError, ValueError):
        return None
    return {str(r) for k in kinds for r in perms.get(k) or []}


def verify_mitigation(name: str, evidence: list[dict], root: Path, high_impact: list[str] | tuple = ()) -> tuple[bool, str]:
    """mitigation 是否有可驗證的落實：至少一筆證據，且每筆證據列出的規則都在對應設定檔的 ask／deny 中。
    切腳的 mitigation（ALL_CUTS）只採信 deny：ask 是「執行前問人」，本質上就是 human_in_the_loop（補償、不算切腳，
    docs/01 §5）；以前 ask 也算，一條無關的 ask 規則冠上 egress_allowlist 的名字就能讓 blocking 發現消失。
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
        kinds = ("deny",) if name in ALL_CUTS else ("ask", "deny")
        have = _permission_rules(root / rel, kinds)
        if have is None:
            return False, f"{name}：{rel} 不存在或無法解析"
        missing = [r for r in ev.get("rules") or [] if r not in have]
        if not ev.get("rules") or missing:
            where = "deny（切腳只採信 deny；ask 是 human_in_the_loop、不算切腳）" if name in ALL_CUTS else "ask／deny"
            return False, f"{name}：{rel} 的 {where} 缺 " + ("、".join(missing) if missing else "（未列規則）")
        stray = [r for rs in (ev.get("covers") or {}).values() for r in rs or [] if r not in (ev.get("rules") or [])]
        if stray:
            return False, f"{name}：covers 引用了 rules 以外的規則 " + "、".join(stray)
    if high_impact:   # 不論 mitigation 叫什麼名字：改名不能讓涵蓋檢查消失（第四次審視 S-6）
        covered = {t for ev in evidence for t, rs in (ev.get("covers") or {}).items() if rs}
        uncovered = [t for t in high_impact if t not in covered]
        if uncovered:
            return False, f"{name}：high_impact_tools 未被任何規則涵蓋 " + "、".join(uncovered)
    return True, f"{name}：已由 " + "、".join(str(e.get("ref")) for e in evidence) + " 落實"


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


def policy_notes(findings: list[dict], tm_rel: str | None, project: "ProjectPolicy") -> list[str]:
    """G0 status_reason 的例外說明：命中筆數、忽略的例外（只列 G0 的規則）與缺 agent_id 而未套用的例外。
    project：受驗樹的 ProjectPolicy；沒有 tm_rel（沒有可比對的路徑）→ 沒有說明。
    G0 的例外必須寫明 agent_id（vibesec_policy.AGENT_SCOPED_RULES）：只寫 path_glob 會連同同一份威脅模型裡之後新增的 agent 一起放行。"""
    return project.report(findings, "G0", paths=[tm_rel]) if tm_rel else []


def trifecta_findings(threat_model: dict, root: Path | None = None, tm_rel: str | None = None, *, project: "ProjectPolicy") -> list[dict]:
    """三要素皆成立，且沒有任何「切腳」mitigation 有可驗證證據 → 發現。
    只宣告 mitigation 名稱不算數（第二次 harness 審查發現 A：宣告與落實不符時 fail-open）；同理：
      - human_in_the_loop 不算切腳（docs/01 §5），只有它通過驗證仍報；
      - trifecta_leg_cut 只是宣告，宣告了也要有切該腳的 mitigation 附可驗證證據（否則改一個欄位就能跳過檢查）。
    root：mitigation_evidence 的 ref 相對的專案根目錄（被檢查的專案）。
    tm_rel：威脅模型在受驗樹內的相對路徑，用來比對例外的 path_glob；沒給 → 不比對例外。
    project：受驗樹的 ProjectPolicy（呼叫端以本 repo 的政策建立：不讀被檢查專案的政策檔，否則被測專案放一份自己的
    blocking-policy.yaml 就能把本規則降為 advisory；外部專案沒有例外）。政策讀不到由進入點記 incomplete，不會走到這裡。"""
    root = root or ROOT
    out = []
    for a in (threat_model or {}).get("agents") or []:
        if not all(a.get(k) is True for k in LEGS):
            continue
        leg = a.get("trifecta_leg_cut")
        cutters = LEG_CUTS.get(leg, ()) if leg is not None else tuple(ALL_CUTS)
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
        c = project.classify(RULE, tm_rel, agent_id=a.get("id"))
        f = {"rule_id": RULE, "control_id": "VS-G0-LETHAL-TRIFECTA", "policy_tier": c["policy_tier"],
             "agent": a.get("id"), "reason": f"agent {a.get('id')!r} 三要素皆成立、{head}（{'；'.join(why)}）"}
        ex = c["exception"]
        if ex is not None:   # 已接受風險：降為 advisory，發現與理由照實保留（未套用的例外由 policy_notes 寫進閘門說明）
            f["exception"] = ex
            f["reason"] += f"；依 blocking-policy 例外降為 advisory（核准：{ex['approved_by']}，到期：{ex['expires']}）"
        out.append(f)
    return out


def selftest() -> list[str]:
    import tempfile
    fails: list[str] = []
    agent = lambda **kw: {"agents": [{"id": "a", "accesses_private_data": True, "exposed_to_untrusted_content": True,
                                      "can_communicate_externally": True, "trifecta_leg_cut": None, **kw}]}
    ev = lambda rules, ref=".claude/settings.json", m="human_in_the_loop": {m: [{"kind": "claude_permission", "ref": ref, "rules": rules}]}
    cov = lambda rules, covers, m="human_in_the_loop": {m: [{"kind": "claude_permission", "ref": ".claude/settings.json",
                                                             "rules": rules, "covers": covers}]}
    sys.path.insert(0, str(ROOT / "scripts"))
    from vibesec_policy import Policy
    P = Policy(ROOT).for_project(ROOT)   # 呼叫端（g0_threat_model、validate）以本 repo 的政策綁定受驗樹
    T = Policy(ROOT).tier(RULE)          # 本 repo 政策的 tier
    with tempfile.TemporaryDirectory() as d:
        root = Path(d); (root / ".claude").mkdir()
        (root / ".claude/settings.json").write_text(json.dumps({"permissions": {"ask": ["mcp__x__merge", "Bash(echo hi)"],
                                                                             "deny": ["Bash(rm *)", "mcp__x__block"]}}))
        TA = "tool_allowlist"
        cases = [
            ("無 mitigation", agent(mitigations=[]), True),
            ("只宣告、無證據", agent(mitigations=[TA]), True),
            ("證據規則不在設定檔", agent(mitigations=[TA], mitigation_evidence=ev(["mcp__x__other"], m=TA)), True),
            ("證據檔不存在", agent(mitigations=[TA], mitigation_evidence=ev(["mcp__x__merge"], "nope.json", m=TA)), True),
            ("證據路徑跳出 repo", agent(mitigations=[TA], mitigation_evidence=ev(["mcp__x__merge"], "../x.json", m=TA)), True),
            ("切腳以 deny 落實", agent(mitigations=[TA], mitigation_evidence=ev(["mcp__x__block", "Bash(rm *)"], m=TA)), False),
            # ask 是 human_in_the_loop、不算切腳：切腳的 mitigation 只採信 deny（以前一條無關的 ask 改名就能消掉發現）
            ("切腳只有 ask 規則", agent(mitigations=[TA], mitigation_evidence=ev(["Bash(echo hi)"], m=TA)), True),
            ("切腳混用 ask 與 deny", agent(mitigations=[TA], mitigation_evidence=ev(["mcp__x__merge", "Bash(rm *)"], m=TA)), True),
            ("每種切腳都只採信 deny", agent(mitigations=sorted(ALL_CUTS),
                mitigation_evidence={m: ev(["mcp__x__merge"], m=m)[m] for m in ALL_CUTS}), True),
            ("宣告切腳、切該腳的 mitigation 只有 ask", agent(mitigations=["egress_allowlist"], trifecta_leg_cut="external_comms",
                mitigation_evidence=ev(["Bash(echo hi)"], m="egress_allowlist")), True),
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
                mitigation_evidence=ev(["mcp__x__block"], m=TA)), False),
            ("一項可驗證即可", agent(mitigations=["egress_allowlist", TA], mitigation_evidence=ev(["mcp__x__block"], m=TA)), False),
            ("high_impact_tools 全涵蓋", agent(mitigations=[TA], high_impact_tools=["merge", "rm"],
                mitigation_evidence=cov(["mcp__x__block", "Bash(rm *)"], {"merge": ["mcp__x__block"], "rm": ["Bash(rm *)"]}, m=TA)), False),
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
            if bool(trifecta_findings(tm, root, project=P)) != expect:
                fails.append(f"{label}：預期 {'有' if expect else '無'}發現")
        got = trifecta_findings(agent(mitigations=[TA], mitigation_evidence=ev(["Bash(echo hi)"], m=TA)), root, project=P)
        if not got or "切腳只採信 deny" not in got[0]["reason"]:
            fails.append(f"切腳只有 ask 規則時，reason 應說明只採信 deny：{got}")
        # human_in_the_loop 仍採信 ask（ask 就是執行前問人）：只有 ask 的 HITL 證據通過驗證
        ok, msg = verify_mitigation(HITL, ev(["Bash(echo hi)"])[HITL], root)
        if not ok:
            fails.append(f"human_in_the_loop 應採信 ask 規則：{msg}")
        (root / "config/policy").mkdir(parents=True)
        (root / "config/policy/blocking-policy.yaml").write_text(
            "version: 1\ndefault_tier: advisory\nblocking: []\nadvisory: [{rule_id: %s}]\n" % RULE)
        (root / "vibesec.yaml").write_text("risk_tier: L1\n")
        got = trifecta_findings(agent(mitigations=[]), root, project=P)
        if not got or got[0]["policy_tier"] != "blocking":
            fails.append("tier 取自本 repo 的政策，不讀被檢查專案的 blocking-policy.yaml")
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
    # blocking-policy 例外的接線：命中 → advisory、reason 註明核准者與到期日；tm_rel 是比對路徑；缺 agent_id 的
    # 例外寫進閘門說明（policy_notes 傳入威脅模型路徑）；沒有 tm_rel → 沒有說明。比對規則本身（agent_id、過期、
    # 缺欄位）只在 vibesec_policy 的 selftest 測。例外經 Policy(暫存政策檔).for_project 讀取：暫存 root 放本 repo
    # 政策的副本，只換掉 exceptions（不依賴本 repo 現有例外與其到期日）；暫存 root 就是「本 repo」
    from vibesec_policy import temp_policy_root, write_exceptions
    ex = {"rule_id": RULE, "path_glob": "docs/threat-model.yaml", "agent_id": "a", "reason": "t", "approved_by": "o", "expires": "2099-01-01"}
    tm_open = agent(mitigations=[])
    with temp_policy_root() as PD:

        def with_exceptions(*entries):
            write_exceptions(PD, entries)

        def pp():
            return Policy(PD, project_root=None).for_project(PD)

        with_exceptions(ex)
        got = trifecta_findings(tm_open, tm_rel="docs/threat-model.yaml", project=pp())
        if [(f["policy_tier"], f.get("exception")) for f in got] != [("advisory", {"path_glob": "docs/threat-model.yaml", "reason": "t", "approved_by": "o", "expires": "2099-01-01", "agent_id": "a"})] \
                or "依 blocking-policy 例外降為 advisory（核准：o，到期：2099-01-01）" not in got[0]["reason"]:
            fails.append(f"符合的例外 → advisory、發現保留並註明核准者與到期日：{got}")
        # 接線：tm_rel 就是比對例外的路徑（閘門把路徑寫死時，上一項照樣通過、這一項會失敗）
        if [f["policy_tier"] for f in trifecta_findings(tm_open, tm_rel="other/tm.yaml", project=pp())] != [T]:
            fails.append("path_glob 不符 → 不套用例外（tm_rel 是比對路徑）")
        with_exceptions({k: v for k, v in ex.items() if k != "agent_id"})
        got = trifecta_findings(tm_open, tm_rel="docs/threat-model.yaml", project=pp())
        notes = policy_notes(got, "docs/threat-model.yaml", pp())
        if got[0]["policy_tier"] != T or "缺 agent_id" in got[0]["reason"] \
                or notes != ["忽略的例外：vibesec.g0.lethal-trifecta-open @ docs/threat-model.yaml：G0 例外缺 agent_id，未套用"]:
            fails.append(f"G0 例外缺 agent_id → 不套用，註明在閘門說明（不附加在 finding.reason）：{got}；{notes}")
        if policy_notes([], None, pp()) != []:
            fails.append("沒給 tm_rel（外部專案）→ 沒有例外說明")
    # 政策檔讀不到 → 進入點就停：incomplete（離開碼 2）並寫明原因，不判定任何發現
    # （以前 tier 退回 blocking 照樣判定：讀不到政策就報 fail，原因寫錯）
    from vibesec_policy import POLICY_UNREADABLE, broken_policy_root
    with broken_policy_root() as pr, contextlib.redirect_stdout(io.StringIO()) as out:
        rc = main(["g0_trifecta.py", str(ROOT / "docs/templates/threat-model.yaml")], policy_root=pr)
    got = json.loads(out.getvalue() or "{}")
    if rc != 2 or got.get("status") != "incomplete" or not str(got.get("status_reason")).startswith(POLICY_UNREADABLE + "（"):
        fails.append(f"政策檔讀不到 → 離開碼 2、incomplete 並寫明原因（得到 {rc}、{got}）")
    return fails


def main(argv: list[str], policy_root: Path = ROOT) -> int:
    """policy_root：阻擋政策所在的 repo（selftest 指向壞政策檔）。"""
    if argv[1:2] == ["selftest"]:
        fails = selftest()
        for f in fails: print(f"FAIL {f}")
        print("selftest " + ("通過" if not fails else f"失敗 {len(fails)} 項"))
        return 1 if fails else 0
    def incomplete(reason: str) -> int:
        print(json.dumps({"gate": "G0", "status": "incomplete", "status_reason": reason}, ensure_ascii=False))
        return 2
    sys.path.insert(0, str(ROOT / "scripts"))
    from vibesec_policy import load_policy
    policy, problem = load_policy(policy_root)   # 進入點只建立一次；讀不到 → incomplete，不判定任何發現
    if problem:
        return incomplete(problem)
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
    findings = trifecta_findings(tm, project=policy.for_project(ROOT))   # 沒有 tm_rel → 不比對例外
    print(json.dumps({"gate": "G0", "findings": findings}, ensure_ascii=False, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
