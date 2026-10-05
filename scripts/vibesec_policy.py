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


class Policy:
    def __init__(self, root: pathlib.Path | str | None = None, risk_tier: str | None = None):
        self.root = pathlib.Path(root) if root else DEFAULT_ROOT
        pol = yaml.safe_load((self.root / "config/policy/blocking-policy.yaml").read_text(encoding="utf-8")) or {}
        if risk_tier is None:
            vb = yaml.safe_load((self.root / "vibesec.yaml").read_text(encoding="utf-8")) or {}
            risk_tier = vb.get("risk_tier", "L2")
        self.risk_tier = risk_tier
        self.default_tier = pol.get("default_tier", "advisory")
        if self.default_tier not in TIERS:
            raise ValueError(f"blocking-policy default_tier 不合法：{self.default_tier!r}")
        self.blocking_base = {r["rule_id"] for r in pol.get("blocking") or [] if isinstance(r, dict) and r.get("rule_id")}
        self.advisory_listed = {r["rule_id"] for r in pol.get("advisory") or [] if isinstance(r, dict) and r.get("rule_id")}
        ov = (pol.get("tier_overrides") or {}).get(risk_tier) or {}
        self.promoted = set(ov.get("promote_to_blocking") or [])
        self.demoted = set(ov.get("demote_to_advisory") or [])
        self.incomplete_blocking_gates = list(pol.get("incomplete_gate_is_blocking_in_enforce") or [])

    def base_tier(self, rule_id: str) -> str:
        if rule_id in self.blocking_base:
            return "blocking"
        if rule_id in self.advisory_listed or str(rule_id).startswith("vibesec."):
            return "advisory"
        return self.default_tier

    def tier(self, rule_id: str) -> str:
        if rule_id in self.demoted:
            return "advisory"
        if rule_id in self.promoted:
            return "blocking"
        return self.base_tier(rule_id)

    def cap(self, rule_id: str, requested: str | None) -> str:
        """requested 為 advisory → advisory（個別發現可降級，例如只有線索）；其餘 → 政策的有效 tier。"""
        return "advisory" if requested == "advisory" else self.tier(rule_id)

    def effective_blocking(self) -> set[str]:
        return (self.blocking_base | self.promoted) - self.demoted


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
