#!/usr/bin/env python3
"""逐項驗證 GitHub 保護；--apply 僅建立缺少的分支保護，不購買付費功能。
Audit GitHub protection; --apply only creates missing branch protection, never purchases paid features.
"""
import argparse
import json
import pathlib
import re
import subprocess
import time
from urllib.parse import quote

REQUIRED_CHECKS = ['VibeSec Summary', '倉庫驗證（validate.py）', '外部 G4 紀錄不得自證']


class ApiError(RuntimeError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def api(path, method='GET', body=None):
    if method == 'GET':
        path += ('&' if '?' in path else '?') + 'audit=' + str(time.time_ns())
    cmd = ['gh', 'api', path, '--method', method]
    if body is not None:
        cmd += ['--input', '-']
    try:
        result = subprocess.run(cmd, input=json.dumps(body) if body is not None else None,
                                text=True, capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ApiError(f'GitHub API 無法完成 / API unavailable: {type(e).__name__}') from None
    if result.returncode:
        match = re.search(r'HTTP (\d{3})', result.stderr)
        status = int(match[1]) if match else None
        raise ApiError(f'GitHub API HTTP {status or "unknown"}: {path.split("?")[0]}', status)
    try:
        return json.loads(result.stdout) if result.stdout.strip() else None
    except json.JSONDecodeError:
        raise ApiError('API 回應不是 JSON / API response is not JSON') from None


def desired_protection():
    return {'required_status_checks': {'strict': True, 'contexts': REQUIRED_CHECKS.copy()},
            'enforce_admins': True,
            'required_pull_request_reviews': {'dismiss_stale_reviews': True, 'require_code_owner_reviews': True,
                                              'required_approving_review_count': 1},
            'restrictions': None, 'required_conversation_resolution': True,
            'allow_force_pushes': False, 'allow_deletions': False}


def protection_gaps(current):
    """檢查必要條件，保留額外要求。 / Check minimums without removing stricter requirements."""
    if not isinstance(current, dict):
        return ['缺少分支保護 / Missing branch protection']
    gaps = []
    status = current.get('required_status_checks') or {}
    contexts = set(status.get('contexts') or []) | {c.get('context') for c in status.get('checks') or [] if isinstance(c, dict)}
    missing = sorted(set(REQUIRED_CHECKS) - contexts)
    if missing:
        gaps.append('缺少必要檢查 / Missing required checks: ' + ', '.join(missing))
    if status.get('strict') is not True:
        gaps.append('未要求分支保持最新 / Branch must be up to date')
    reviews = current.get('required_pull_request_reviews') or {}
    if type(reviews.get('required_approving_review_count')) is not int or reviews['required_approving_review_count'] < 1:
        gaps.append('缺少必要核准 / At least one approval required')
    for key in ('dismiss_stale_reviews', 'require_code_owner_reviews'):
        if reviews.get(key) is not True:
            gaps.append('審查保護未啟用 / Review protection missing: ' + key)
    for key in ('enforce_admins', 'required_conversation_resolution'):
        if (current.get(key) or {}).get('enabled') is not True:
            gaps.append('保護未啟用 / Protection missing: ' + key)
    for key in ('allow_force_pushes', 'allow_deletions'):
        if (current.get(key) or {}).get('enabled') is not False:
            gaps.append('須禁止或確認設定 / Must explicitly prohibit: ' + key)
    bypass = reviews.get('bypass_pull_request_allowances') or {}
    if any(bypass.get(k) for k in ('users', 'teams', 'apps')):
        gaps.append('存在審查繞過名單 / Review bypass allowances exist')
    return gaps


def audit(repo, apply=False, request=api):
    report = {'repo': repo, 'branch': None, 'status': 'incomplete', 'checks': {},
              'desired_protection': desired_protection(), 'applied': False,
              'note': 'CODEOWNERS 資格與獨立審查者須另行確認；此報告不核准合併。 / Verify eligible independent CODEOWNERS separately; this report does not authorize merging.'}
    checks = report['checks']
    try:
        metadata = request('repos/' + repo)
        branch = metadata['default_branch']
        if not isinstance(branch, str) or not branch:
            raise ValueError('缺少預設分支 / Missing default branch')
        report['branch'] = branch
    except (ApiError, KeyError, TypeError, ValueError) as e:
        checks['repository'] = {'status': 'incomplete', 'reason': str(e)}
        return report
    path = f'repos/{repo}/branches/{quote(branch, safe="")}'
    current = None
    try:
        branch_metadata = request(path)
        try:
            current = request(path + '/protection')
        except ApiError as e:
            # 404 只有在分支明確未受保護時才代表可以新增。 / Only explicit unprotected metadata plus 404 permits creation.
            if e.status != 404 or branch_metadata.get('protected') is not False:
                raise
        if apply and current is None:
            if branch_metadata.get('protected') is not False:
                raise ValueError('既有保護未知，不覆寫 / Existing protection unknown; refusing overwrite')
            request(path + '/protection', 'PUT', desired_protection())
            report['applied'] = True
            current = request(path + '/protection')
        gaps = protection_gaps(current)
        checks['branch_protection'] = {'status': 'fail' if gaps else 'pass', 'gaps': gaps}
        if apply and current is not None and gaps:
            checks['branch_protection']['reason'] = '保留既有設定；需人工合併較嚴格要求。 / Existing settings preserved; manually merge stronger requirements.'
    except (ApiError, ValueError, TypeError, AttributeError) as e:
        checks['branch_protection'] = {'status': 'incomplete', 'reason': str(e)}
    # 獨立查詢，不讓管理 API 失敗掩蓋掃描狀態。 / Audit scanning even when administration is inaccessible.
    try:
        analyses = request(f'repos/{repo}/code-scanning/analyses?per_page=100&ref={quote("refs/heads/" + branch, safe="")}')
        if not isinstance(analyses, list):
            raise ValueError('分析列表格式錯誤 / Invalid analysis list')
        if not analyses:
            checks['code_scanning'] = {'status': 'incomplete', 'reason': 'API 可用但沒有預設分支分析 / API reachable but no default-branch analysis'}
        else:
            checks['code_scanning'] = {'status': 'pass', 'analysis_count': len(analyses),
                                       'reason': 'API 可用且已有分析；不代表目前提交無弱點。 / API available with analyses; not a clean verdict for the current commit.'}
    except (ApiError, ValueError) as e:
        checks['code_scanning'] = {'status': 'incomplete', 'reason': str(e)}
    states = {c['status'] for c in checks.values()}
    report['status'] = 'incomplete' if 'incomplete' in states else 'fail' if 'fail' in states else 'pass'
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', default='chinchiang/MultiAgentDelta')
    parser.add_argument('--apply', action='store_true', help='建立缺少的保護 / Create missing protection')
    parser.add_argument('--json', type=pathlib.Path, help='儲存驗證報告 / Save audit report')
    args = parser.parse_args()
    if not re.fullmatch(r'[\w.-]+/[\w.-]+', args.repo):
        parser.error('--repo 必須為 owner/repo / Expected owner/repo')
    report = audit(args.repo, args.apply)
    output = json.dumps(report, ensure_ascii=False, indent=2)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(output + '\n', encoding='utf-8')
    print(output)
    return {'pass': 0, 'fail': 1, 'incomplete': 2}[report['status']]


if __name__ == '__main__':
    raise SystemExit(main())
