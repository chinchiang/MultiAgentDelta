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


def trifecta_findings(threat_model: dict) -> list[dict]:
    out = []
    for a in (threat_model or {}).get("agents") or []:
        if all(a.get(k) is True for k in LEGS) and not a.get("mitigations") and a.get("trifecta_leg_cut") is None:
            out.append({"rule_id": RULE, "control_id": "VS-G0-LETHAL-TRIFECTA", "policy_tier": "blocking",
                        "agent": a.get("id"),
                        "reason": f"agent {a.get('id')!r} 三要素皆成立，且沒有 mitigation、也未切斷任何一腳"})
    return out


def main(argv: list[str]) -> int:
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
