#!/usr/bin/env python3
"""VibeSec 阻擋政策查詢：規則 tier 的唯一來源。

來源：config/policy/blocking-policy.yaml（blocking 清單、default_tier、tier_overrides）＋ vibesec.yaml 的 risk_tier。
config/catalogs/cwe-map.yaml 的 policy_tier 只是預設建議（該檔第 7 行），validate.py 檢查它必須等於這裡的
base_tier；所有發出 finding 的元件（workflow 內嵌探針、scripts/*.py）都必須用這裡算 tier，不得自行寫死。

  from vibesec_policy import Policy
  p = Policy(root)
  p.tier(rule_id)        # 有效 tier：含 risk_tier 的 tier_overrides（CI 阻擋用）
  p.base_tier(rule_id)   # 基礎 tier：不含 tier_overrides（cwe-map／docs／evals 對齊用）
  p.cap(rule_id, req)    # 呼叫端只能把個別發現降為 advisory，不能升級到政策以上

  python3 scripts/vibesec_policy.py <rule_id>...    # 每行印出「<rule_id> <有效 tier>」（給 shell 步驟用）
  python3 scripts/vibesec_policy.py selftest

政策檔缺席或無法解析 → 例外（incomplete ≠ pass，CLAUDE.md #2）；要改政策必須由人類在獨立 PR 決定（規則 1）。
"""
from __future__ import annotations
import pathlib, sys

try:
    import yaml
except ImportError:
    print("工具缺席：PyYAML；無法讀取阻擋政策", file=sys.stderr)
    sys.exit(2)

DEFAULT_ROOT = pathlib.Path(__file__).resolve().parent.parent
TIERS = ("blocking", "advisory")
GATES = ("G0", "G1", "G2", "G3", "G4", "G5", "G6")
RISK_TIERS = ("L1", "L2", "L3")             # vibesec.yaml risk_tier（docs/01 決策樹）
# 外部工具規則前綴 → 閘門（applies_only_to_gates 用）。trivy 同時用於 G1（漏洞）與 G3（IaC 設定），
# 從規則 ID 分不出閘門 → 不列，不因 applies_only_to_gates 降級（fail closed）。
TOOL_GATE = {"gitleaks": "G2", "semgrep": "G3", "checkov": "G3", "zap": "G5", "promptfoo": "G6", "garak": "G6", "grype": "G1"}


def rule_gate(rule_id: str) -> str | None:
    """規則所屬閘門：vibesec.g<N>.* → G<N>；外部工具依 TOOL_GATE；分不出 → None。"""
    rid = str(rule_id)
    if rid.startswith("vibesec.g") and rid[9:10].isdigit() and rid[10:11] == ".":
        return f"G{rid[9]}"
    return TOOL_GATE.get(rid.split(":", 1)[0]) if ":" in rid else None


class Policy:
    def __init__(self, root: pathlib.Path | str | None = None, risk_tier: str | None = None):
        self.root = pathlib.Path(root) if root else DEFAULT_ROOT
        pol = yaml.safe_load((self.root / "config/policy/blocking-policy.yaml").read_text(encoding="utf-8")) or {}
        if risk_tier is None:
            vb = yaml.safe_load((self.root / "vibesec.yaml").read_text(encoding="utf-8")) or {}
            risk_tier = vb.get("risk_tier", "L2")
        overrides = pol.get("tier_overrides") or {}
        # risk_tier 必須是 vibesec.yaml 定義的層級（L1／L2／L3）：以前 l3、L4 這類打錯的值靜默取不到任何 override，
        # L3 的升級規則就消失了（例如 missing-owner-filter 變回 advisory）。打錯 → 例外（fail closed）
        if risk_tier not in RISK_TIERS:
            raise ValueError(f"risk_tier 不合法：{risk_tier!r}（須為 {'／'.join(RISK_TIERS)}）")
        if not set(overrides) <= set(RISK_TIERS):
            raise ValueError(f"blocking-policy tier_overrides 有未知層級：{sorted(set(overrides) - set(RISK_TIERS))}")
        self.risk_tier = risk_tier
        self.default_tier = pol.get("default_tier", "advisory")
        if self.default_tier not in TIERS:
            raise ValueError(f"blocking-policy default_tier 不合法：{self.default_tier!r}")
        self.blocking_base = {r["rule_id"] for r in pol.get("blocking") or [] if isinstance(r, dict) and r.get("rule_id")}
        self.advisory_listed = {r["rule_id"] for r in pol.get("advisory") or [] if isinstance(r, dict) and r.get("rule_id")}
        ov = overrides.get(risk_tier) or {}
        self.promoted = set(ov.get("promote_to_blocking") or [])
        self.demoted = set(ov.get("demote_to_advisory") or [])
        # applies_only_to_gates（例如 L1 只跑 G1、G2）：清單外閘門的規則不套用 → 有效 tier 為 advisory（發現保留、不阻擋）。
        # 以前宣告了卻沒有實作，L1 下 vibesec.g3.sql-string-concat 仍是 blocking。未宣告 → None（所有閘門都套用）
        only = ov.get("applies_only_to_gates")
        if only is not None:
            bad = [g for g in only if g not in GATES] if isinstance(only, list) else [only]
            if bad:
                raise ValueError(f"tier_overrides.{risk_tier}.applies_only_to_gates 不合法：{bad!r}（須為 {'／'.join(GATES)}）")
        self.applies_only_to_gates = set(only) if only is not None else None
        self.incomplete_blocking_gates = list(pol.get("incomplete_gate_is_blocking_in_enforce") or [])

    def base_tier(self, rule_id: str) -> str:
        if rule_id in self.blocking_base:
            return "blocking"
        if rule_id in self.advisory_listed or str(rule_id).startswith("vibesec."):
            return "advisory"
        return self.default_tier

    def gate_applies(self, gate: str | None) -> bool:
        """本 risk_tier 下該閘門的規則是否套用；閘門分不出（None）→ 套用（不因此降級）。"""
        return self.applies_only_to_gates is None or gate is None or gate in self.applies_only_to_gates

    def tier(self, rule_id: str) -> str:
        if rule_id in self.demoted:
            return "advisory"
        if not self.gate_applies(rule_gate(rule_id)):
            return "advisory"
        if rule_id in self.promoted:
            return "blocking"
        return self.base_tier(rule_id)

    def cap(self, rule_id: str, requested: str | None) -> str:
        """requested 為 advisory → advisory（個別發現可降級，例如只有線索）；其餘 → 政策的有效 tier。"""
        return "advisory" if requested == "advisory" else self.tier(rule_id)

    def effective_blocking(self) -> set[str]:
        return {r for r in (self.blocking_base | self.promoted) - self.demoted if self.gate_applies(rule_gate(r))}


def selftest() -> list[str]:
    import tempfile
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as d:
        root = pathlib.Path(d); (root / "config/policy").mkdir(parents=True)
        (root / "config/policy/blocking-policy.yaml").write_text(yaml.safe_dump({
            "default_tier": "advisory",
            "blocking": [{"rule_id": "vibesec.g9.a", "why": "x"}],
            "advisory": [{"rule_id": "vibesec.g9.b", "why": "x"}],
            "tier_overrides": {"L3": {"promote_to_blocking": ["vibesec.g9.b"], "demote_to_advisory": ["vibesec.g9.a"]}}}))
        (root / "vibesec.yaml").write_text("risk_tier: L3\n")
        p = Policy(root)
        checks = [
            (p.base_tier("vibesec.g9.a"), "blocking", "blocking 清單 → base blocking"),
            (p.tier("vibesec.g9.a"), "advisory", "L3 demote → 有效 advisory"),
            (p.base_tier("vibesec.g9.b"), "advisory", "advisory 清單 → base advisory"),
            (p.tier("vibesec.g9.b"), "blocking", "L3 promote → 有效 blocking"),
            (p.tier("vibesec.g9.unlisted"), "advisory", "未列的 vibesec 規則 → advisory"),
            (p.tier("semgrep:foo"), "advisory", "外部規則 → default_tier"),
            (p.cap("vibesec.g9.b", "advisory"), "advisory", "cap：呼叫端可降級"),
            (p.cap("vibesec.g9.a", "blocking"), "advisory", "cap：呼叫端不能升到政策以上"),
            (Policy(root, risk_tier="L2").tier("vibesec.g9.b"), "advisory", "L2 無 override"),
            (sorted(p.effective_blocking()), ["vibesec.g9.b"], "effective_blocking"),
        ]
        for got, want, label in checks:
            if got != want:
                fails.append(f"{label}：得到 {got!r}，預期 {want!r}")
        # risk_tier 打錯（小寫、不存在的層級、非字串）→ 例外，不得靜默取不到 override（以前 l3 讓 L3 升級規則消失）
        for bad in ("l3", "L4", "", None, 3):
            (root / "vibesec.yaml").write_text(yaml.safe_dump({"risk_tier": bad}))
            try:
                Policy(root); fails.append(f"risk_tier={bad!r} 應拋出例外")
            except ValueError:
                pass
        (root / "vibesec.yaml").write_text("project: {name: x}\n")
        if Policy(root).risk_tier != "L2":
            fails.append("vibesec.yaml 未設定 risk_tier → 預設 L2")
        # applies_only_to_gates：清單外閘門的規則有效 tier 為 advisory（發現保留、不阻擋）；分不出閘門的規則不降級。
        # 假規則 ID 在執行期組出：validate.py 會掃 scripts/ 原文中的 vibesec.g<0-6>.* 是否都在 cwe-map
        g1a, g3a, g3b, g4p = ("vibesec." + x for x in ("g1.a", "g3.a", "g3.b", "g4.p"))
        pol = {"default_tier": "advisory",
               "blocking": [{"rule_id": r, "why": "x"} for r in (g1a, g3a, "gitleaks:aws", "semgrep:x",
                                                                 "trivy:AVD-1", "zap:40018", "custom-rule")],
               "tier_overrides": {"L1": {"applies_only_to_gates": ["G1", "G2"], "promote_to_blocking": [g4p]},
                                  "L3": {"promote_to_blocking": [g3b]}}}
        (root / "config/policy/blocking-policy.yaml").write_text(yaml.safe_dump(pol))
        l1, l3 = Policy(root, risk_tier="L1"), Policy(root, risk_tier="L3")
        for rid, want in [(g1a, "blocking"), ("gitleaks:aws", "blocking"), (g3a, "advisory"),
                          ("semgrep:x", "advisory"), ("zap:40018", "advisory"),
                          (g4p, "advisory"),             # promote 也不能讓清單外閘門的規則阻擋
                          ("trivy:AVD-1", "blocking"),              # trivy 同時用於 G1／G3，分不出 → 不降級
                          ("custom-rule", "blocking")]:             # 無閘門資訊 → 不降級（fail closed）
            if l1.tier(rid) != want:
                fails.append(f"L1 applies_only_to_gates：{rid} 應為 {want}（得到 {l1.tier(rid)}）")
        if sorted(l1.effective_blocking()) != ["custom-rule", "gitleaks:aws", "trivy:AVD-1", g1a]:
            fails.append(f"L1 effective_blocking 應排除清單外閘門（得到 {sorted(l1.effective_blocking())}）")
        if l3.tier(g3a) != "blocking" or l3.applies_only_to_gates is not None:
            fails.append("沒有 applies_only_to_gates 的層級：所有閘門都套用")
        for bad_only in (["G7"], ["g1"], "G1"):
            (root / "config/policy/blocking-policy.yaml").write_text(yaml.safe_dump(
                {"tier_overrides": {"L1": {"applies_only_to_gates": bad_only}}}))
            try:
                Policy(root, risk_tier="L1"); fails.append(f"applies_only_to_gates={bad_only!r} 應拋出例外")
            except ValueError:
                pass
        (root / "config/policy/blocking-policy.yaml").write_text(yaml.safe_dump({"tier_overrides": {"L9": {}}}))
        try:
            Policy(root, risk_tier="L2"); fails.append("tier_overrides 有未知層級 L9 應拋出例外")
        except ValueError:
            pass
    # 本 repo 的實際政策：L1 下 G3 規則不阻擋、G1／G2 照常；L3 的升級規則仍在
    real_l1, real_l3 = Policy(risk_tier="L1"), Policy(risk_tier="L3")
    if real_l1.tier("vibesec.g3.sql-string-concat") != "advisory" or real_l1.tier("vibesec.g2.hardcoded-secret") != "blocking":
        fails.append("實際政策 L1：G3 規則應為 advisory、G2 規則照常 blocking")
    if real_l3.tier("vibesec.g4.missing-owner-filter") != "blocking":
        fails.append("實際政策 L3：missing-owner-filter 應升為 blocking")
    return fails


def main(argv: list[str]) -> int:
    if argv[1:2] == ["selftest"]:
        fails = selftest()
        for f in fails: print(f"FAIL {f}")
        print("selftest " + ("通過" if not fails else f"失敗 {len(fails)} 項"))
        return 1 if fails else 0
    if len(argv) < 2:
        print(__doc__); return 2
    p = Policy()
    for rid in argv[1:]:
        print(f"{rid} {p.tier(rid)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
