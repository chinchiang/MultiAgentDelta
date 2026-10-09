#!/usr/bin/env python3
"""將 API 探針與必要 ZAP 報告合併為 G5；缺報告不能視為完成。"""
import argparse
import datetime
import json
import pathlib
from vibesec_policy import Policy
from jsonschema import Draft202012Validator

ROOT = pathlib.Path(__file__).resolve().parents[1]


def merge(probes, reports, policy=None, outcomes=None):
    policy = policy or Policy(ROOT)
    validator = Draft202012Validator(json.loads((ROOT / "schemas/gate-result.schema.json").read_text()))
    if not isinstance(probes, dict) or list(validator.iter_errors(probes)) or probes.get("gate") != "G5": probes = None
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    gate = json.loads(json.dumps(probes)) if isinstance(probes, dict) else {
        'gate': 'G5', 'mode': 'shadow', 'status': 'incomplete', 'status_reason': 'API 探針報告缺席',
        'scope': 'full', 'started_at': now, 'finished_at': now, 'tools': [], 'coverage': [],
        'findings_count': {'blocking': 0, 'advisory': 0}}
    problems = [gate['status_reason']] if gate['status'] == 'incomplete' else []
    for name in ('zap-api', 'zap-baseline'):
        path = reports.get(name)
        row = {'name': name, 'state': 'error', 'output_ref': str(path) if path else None}
        alerts = []
        try:
            if outcomes is not None and outcomes.get(name) != 'success': raise ValueError('ZAP 步驟未完成')
            data = json.loads(pathlib.Path(path).read_text()) if path else None
            sites = data.get('site') if isinstance(data, dict) else None
            if not isinstance(sites, list) or not sites: raise ValueError('沒有已掃描的 site')
            for site in sites:
                if not isinstance(site.get('alerts'), list): raise ValueError('缺少 alerts 清單')
                alerts.extend(site['alerts'])
            for alert in alerts:
                if not isinstance(alert, dict) or not str(alert.get('pluginid', '')).isdigit(): raise ValueError('alert 缺少 pluginid')
            row['state'] = 'ran'
        except (OSError, ValueError, TypeError, AttributeError) as e:
            problems.append(f'{name} 未完成：{type(e).__name__}')
            gate['coverage'].append({'control_id': 'ASVS5-V1.2', 'state': 'untested', 'reason': problems[-1]})
        else:
            for alert in alerts:
                gate['findings_count'][policy.tier('zap:' + str(alert['pluginid']))] += 1
            gate['coverage'].append({'control_id': 'ASVS5-V1.2', 'state': 'fail' if alerts else 'pass', 'reason': name})
        gate['tools'].append(row)
    gate['status'] = 'fail' if gate['findings_count']['blocking'] else 'incomplete' if problems else 'pass'
    gate['status_reason'] = '；'.join(problems) or None
    gate['finished_at'] = now
    return gate


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--probes', required=True); ap.add_argument('--zap-api', required=True); ap.add_argument('--zap-baseline', required=True); ap.add_argument('--out', required=True)
    ap.add_argument('--zap-api-outcome', required=True); ap.add_argument('--zap-baseline-outcome', required=True)
    a = ap.parse_args()
    try: probes = json.loads(pathlib.Path(a.probes).read_text())
    except (OSError, ValueError): probes = None
    gate = merge(probes, {'zap-api': a.zap_api, 'zap-baseline': a.zap_baseline}, outcomes={'zap-api': a.zap_api_outcome, 'zap-baseline': a.zap_baseline_outcome})
    pathlib.Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(a.out).write_text(json.dumps(gate, ensure_ascii=False, indent=2))
    return 0  # 政策退出碼由 gate_verdict 統一判定

if __name__ == '__main__': raise SystemExit(main())
