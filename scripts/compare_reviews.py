#!/usr/bin/env python3
"""比較單模型、同家族多代理、跨家族多代理；缺資料不宣稱增益。"""
import argparse
import hashlib
import json
import math
import pathlib
import yaml

ARMS = ('single', 'same_family', 'cross_family')


def interval(hits, n):
    if not n: return None
    z = 1.96; p = hits / n; d = 1 + z*z/n
    mid = (p + z*z/(2*n))/d
    half = z*math.sqrt(p*(1-p)/n + z*z/(4*n*n))/d
    return [round(mid-half, 4), round(mid+half, 4)]


def compare(cases, records, root):
    expected = {c['id']: c for c in cases if c.get('held_out') and not c['expected'].get('gate_status')}
    groups = {arm: {} for arm in ARMS}; problems = []
    for r in records:
        if not isinstance(r, dict): problems.append("紀錄不是物件"); continue
        arm, cid = r.get('arm'), r.get('case_id')
        if arm not in groups or cid not in expected:
            problems.append('不明組別或非保留集案例'); continue
        if cid in groups[arm]: problems.append(f'{arm}/{cid} 重複'); continue
        members = r.get('reviewers') or []
        if not isinstance(members, list) or not all(isinstance(m, dict) and isinstance(m.get('family'), str) for m in members):
            problems.append(f'{arm}/{cid} 審查者格式錯誤'); continue
        families = {m.get('family') for m in members}
        shape = (len(members) == 1 if arm == 'single' else len(members) >= 2 and len(families) == 1 if arm == 'same_family' else len(members) >= 2 and len(families) >= 2)
        valid = shape and all(m.get('model') and m.get('family') and m.get('state') == 'ran' and m.get('round1_independent') is True for m in members)
        if not valid: problems.append(f'{arm}/{cid} 缺獨立審查、模型版本或家族證據'); continue
        if r.get('requires_human') or r.get('decision') not in ('flag', 'clear'):
            problems.append(f'{arm}/{cid} 未裁決，不採多數決補結論'); continue
        if any(type(r.get(k)) not in (int, float) or not math.isfinite(r[k]) or r[k] < 0 for k in ('cost_usd', 'human_seconds')):
            problems.append(f'{arm}/{cid} 缺成本或人工時間'); continue
        try:
            ref = pathlib.Path(r['evidence_ref'])
            if ref.is_absolute() or '..' in ref.parts: raise ValueError('證據路徑超出輸入目錄')
            evidence = (root / ref).resolve()
            if not evidence.is_relative_to(root.resolve()): raise ValueError('證據 symlink 超出目錄')
            if hashlib.sha256(evidence.read_bytes()).hexdigest() != r['evidence_sha256']: raise ValueError('證據指紋不符')
        except (KeyError,OSError,ValueError):
            problems.append(f'{arm}/{cid} 缺可核對的原始證據'); continue
        groups[arm][cid] = r
    summaries = {}
    misses = {}
    for arm, rows in groups.items():
        missing = sorted(set(expected) - set(rows))
        if missing: problems.append(f'{arm} 尚缺 {len(missing)} 個保留集案例')
        tp=fp=fn=tn=0; misses[arm]=set()
        for cid, r in rows.items():
            truth=expected[cid]['expected']['should_flag']; flag=r['decision']=='flag'
            if truth and flag: tp+=1
            elif truth: fn+=1; misses[arm].add(cid)
            elif flag: fp+=1
            else: tn+=1
        summaries[arm]={'executed':len(rows),'expected':len(expected),'TP':tp,'FP':fp,'FN':fn,'TN':tn,
                        'recall':tp/(tp+fn) if tp+fn else None,'recall_95_interval':interval(tp,tp+fn),
                        'precision':tp/(tp+fp) if tp+fp else None,'precision_95_interval':interval(tp,tp+fp),
                        'cost_usd':sum(r['cost_usd'] for r in rows.values()),'human_seconds':sum(r['human_seconds'] for r in rows.values())}
    if not expected: problems.append('沒有適用的保留集')
    return {'status':'incomplete' if problems else 'complete','problems':problems,'arms':summaries,
            'common_false_negatives':sorted(set.intersection(*misses.values())),
            'cross_family_additional_valid_cases':sorted(misses['single']-misses['cross_family']) if not problems else [],
            'note':'召回率差異只在三組使用完整相同保留集時解讀；模型回應與合成靶場不等於全面安全。'}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--records',required=True);ap.add_argument('--cases',default='evals/cases');ap.add_argument('--out',required=True)
    a=ap.parse_args();path=pathlib.Path(a.records)
    cases=[yaml.safe_load(p.read_text()) for p in sorted(pathlib.Path(a.cases).glob('**/*.yaml'))]
    records=[json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    report=compare(cases,records,path.parent)
    report['inputs_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
    report['dataset_sha256']=hashlib.sha256(json.dumps(cases,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
    out=pathlib.Path(a.out);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,ensure_ascii=False,indent=2))
    print(report['status']);return 0 if report['status']=='complete' else 2

if __name__=='__main__':raise SystemExit(main())
