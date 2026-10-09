#!/usr/bin/env python3
"""以可信設定判定閘門退出碼；模式只能由設定升級至 enforce。"""
import argparse
import json
import os
import pathlib
import sys
import yaml
from jsonschema import Draft202012Validator
from vibesec_policy import Policy

ROOT = pathlib.Path(__file__).resolve().parents[1]


def verdict(gates, root=ROOT, requested=None, lab=False):
    cfg = yaml.safe_load((root / 'vibesec.yaml').read_text())
    mode = cfg.get('mode')
    if mode not in ('shadow', 'enforce'):
        raise ValueError('mode 必須是 shadow 或 enforce')
    if requested == 'enforce': mode = 'enforce'
    policy = Policy(root)
    validator = Draft202012Validator(json.loads((root / 'schemas/gate-result.schema.json').read_text()))
    rows, blocking, incomplete = [], False, False
    for gid, gate in gates.items():
        errors = list(validator.iter_errors(gate)) if isinstance(gate, dict) else ['missing']
        if errors or gate.get('gate') != gid:
            gate = {'gate': gid, 'status': 'incomplete', 'status_reason': '閘門結果缺席或不符合 schema', 'findings_count': {'blocking': 0, 'advisory': 0}}
        rows.append(gate)
        count = gate['findings_count']['blocking']
        blocking |= count > 0
        incomplete |= gate['status'] in ('incomplete', 'untested') and gid in policy.incomplete_blocking_gates
    if lab:
        # 內建漏洞靶場必須真的偵測到兩個閘門的 blocking；這是偵測器驗收，不是部署核准。
        return (0 if all(g['status'] == 'fail' and g['findings_count']['blocking'] > 0 for g in rows) else 1), rows, mode
    return (2 if mode == 'enforce' and incomplete else 1 if mode == 'enforce' and blocking else 0), rows, mode


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--gate', action='append', required=True, help='G1=reports/g1-gate.json')
    ap.add_argument('--policy-root', type=pathlib.Path, default=ROOT)
    ap.add_argument('--mode', choices=['shadow', 'enforce'])
    ap.add_argument('--lab', action='store_true')
    ap.add_argument('--out', default='reports/gate-status.md')
    a = ap.parse_args()
    gates = {}
    for item in a.gate:
        gid, path = item.split('=', 1)
        try: gates[gid] = json.loads(pathlib.Path(path).read_text())
        except (OSError, ValueError): gates[gid] = None
    try: code, rows, mode = verdict(gates, root=a.policy_root, requested=a.mode, lab=a.lab)
    except (OSError, ValueError, TypeError) as e:
        print(f'無法判定：{e}', file=sys.stderr); return 2
    lines = ['# VibeSec 閘門狀態', '', f'模式：`{mode}`；用途：' + ('靶場偵測驗收' if a.lab else '政策判定'), '', '| 閘門 | 狀態 | blocking | advisory | 說明 |', '|---|---|---|---|---|']
    for g in rows:
        c = g['findings_count']; reason = str(g.get('status_reason') or '').replace('|', '\\|').replace('\n', ' ')
        lines.append(f"| {g['gate']} | {g['status']} | {c['blocking']} | {c['advisory']} | {reason} |")
    text = '\n'.join(lines) + '\n'
    out = pathlib.Path(a.out); out.parent.mkdir(parents=True, exist_ok=True); out.write_text(text)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f: f.write(text)
    print(text)
    return code

if __name__ == '__main__': sys.exit(main())
