#!/usr/bin/env python3
"""離線定向突變測試。 / Offline targeted mutation testing."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def classify(result, baseline):
    if result['errors'] or result['tests'] != baseline['tests'] or result['skipped'] != baseline['skipped']:
        return 'invalid'
    return 'killed' if result['failures'] else 'survived'


def run_test(root, test, timeout):
    output = root / '_mutation_result.json'
    output.unlink(missing_ok=True)
    env = {'PATH': os.defpath, 'HOME': str(root), 'LANG': 'C.UTF-8',
           'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONHASHSEED': '0'}
    try:
        result = subprocess.run([sys.executable, '-B', str(root/'scripts/mutation_worker.py'),
                                 test, str(output)], cwd=root, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {'state': 'timeout'}
    if result.returncode or not output.exists():
        return {'state': 'invalid'}
    try:
        return json.loads(output.read_text())
    except (ValueError, OSError):
        return {'state': 'invalid'}


def run(profile, timeout):
    manifest = ROOT/'config/mutations.json'
    entries = json.loads(manifest.read_text())
    selected = [m for m in entries if profile == 'full' or m['core']]
    if not selected or len({m['id'] for m in selected}) != len(selected):
        raise ValueError('Empty or duplicate mutations / 突變清單為空或重複')
    report = {'profile': profile, 'manifest_sha256': hashlib.sha256(manifest.read_bytes()).hexdigest(),
              'baseline': {}, 'mutations': [], 'status': 'incomplete'}
    with tempfile.TemporaryDirectory(prefix='vibesec-mutation-') as directory:
        root = Path(directory)
        # 複製測試所需資料；不複製憑證、Git 設定或模型實測證據。 / Copy fixtures, never credentials or Git config.
        for name in ('scripts', 'tests', 'schemas', 'config', 'docs/templates', 'evals', 'rulings'):
            shutil.copytree(ROOT/name, root/name, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        shutil.copyfile(ROOT/'vibesec.yaml', root/'vibesec.yaml')
        for test in sorted({m['test'] for m in selected}):
            baseline = run_test(root, test, timeout)
            report['baseline'][test] = baseline
            if baseline.get('state') or baseline['errors'] or baseline['failures'] or baseline['tests'] <= baseline['skipped']:
                return report
        for mutation in selected:
            path = root/mutation['file']
            if not path.resolve().is_relative_to(root/'scripts'):
                raise ValueError('Invalid mutation path / 突變路徑不合法')
            source = path.read_text()
            row = {k: mutation[k] for k in ('id', 'file', 'before', 'after', 'test')}
            row['source_sha256'] = hashlib.sha256(source.encode()).hexdigest()
            if source.count(mutation['before']) != 1 or mutation['before'] == mutation['after']:
                row['state'] = 'invalid'
            else:
                changed = source.replace(mutation['before'], mutation['after'], 1)
                try:
                    compile(changed, str(path), 'exec')
                    path.write_text(changed)
                    result = run_test(root, mutation['test'], timeout)
                    row['result'] = result
                    row['state'] = result.get('state') or classify(result, report['baseline'][mutation['test']])
                except SyntaxError:
                    row['state'] = 'invalid'
                finally:
                    path.write_text(source)
            report['mutations'].append(row)
            print(f"{row['id']}: {row['state']}", flush=True)
    counts = Counter(m['state'] for m in report['mutations'])
    report['counts'] = dict(counts)
    report['score'] = counts['killed'] / len(selected)
    report['status'] = 'pass' if counts['killed'] == len(selected) else 'fail'
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=('core', 'full'), default='core')
    parser.add_argument('--timeout', type=float, default=30)
    parser.add_argument('--out', type=Path, default=Path('reports/mutations.json'))
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('timeout must be positive / 逾時秒數必須大於零')
    try:
        report = run(args.profile, args.timeout)
    except (ValueError, OSError, KeyError) as error:
        report = {'status': 'incomplete', 'reason': str(error)}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False)+'\n')
    print(json.dumps({k: report[k] for k in ('status', 'counts', 'score') if k in report}))
    return 0 if report['status'] == 'pass' else 1


if __name__ == '__main__':
    sys.exit(main())
