#!/usr/bin/env python3
"""檢查 GitHub 管理設定；--apply 以管理者憑證設定必要檢查，不會購買付費功能。"""
import argparse
import json
import subprocess
import sys


def api(path, method='GET', body=None):
    cmd=['gh','api',path,'--method',method]
    if body is not None: cmd += ['--input','-']
    result=subprocess.run(cmd,input=json.dumps(body) if body is not None else None,text=True,capture_output=True)
    if result.returncode: raise RuntimeError(result.stderr.strip())
    return json.loads(result.stdout) if result.stdout.strip() else None


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--repo',default='chinchiang/MultiAgentDelta');ap.add_argument('--apply',action='store_true');a=ap.parse_args()
    try:
        repo=api('repos/'+a.repo);branch=repo['default_branch']
        path=f'repos/{a.repo}/branches/{branch}/protection'
        desired={'required_status_checks':{'strict':True,'contexts':['VibeSec Summary','倉庫驗證（validate.py）','外部 G4 紀錄不得自證']},
                 'enforce_admins':True,'required_pull_request_reviews':{'dismiss_stale_reviews':True,'require_code_owner_reviews':True,'required_approving_review_count':1},
                 'restrictions':None,'required_conversation_resolution':True,'allow_force_pushes':False,'allow_deletions':False}
        if a.apply:
            # 先讀舊設定；未知既有保護時不得整組覆寫。
            metadata=api(f'repos/{a.repo}/branches/{branch}')
            current=api(path) if metadata.get('protected') else None
            if current:
                print('已存在保護設定；請保留現有較嚴格規則，人工合併以下必要設定。')
                print(json.dumps(desired,ensure_ascii=False,indent=2));return 2
            api(path,'PUT',desired)
        else:
            print(json.dumps({'branch':branch,'desired_protection':desired},ensure_ascii=False,indent=2))
        api(f'repos/{a.repo}/code-scanning/analyses?per_page=1')
        print('Code Scanning API 可用；分支保護需另確認管理介面。')
    except RuntimeError as e:
        print(str(e),file=sys.stderr)
        print('需要具 Administration 權限的管理者憑證；私有儲存庫另需支援並啟用 Code Scanning。',file=sys.stderr)
        return 2
    return 0

if __name__=='__main__':raise SystemExit(main())
