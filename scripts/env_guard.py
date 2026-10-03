#!/usr/bin/env python3
"""G2 .env 防護 — 確保機密檔不入版控。對應 vibesec.yaml g2_secrets.require_env_in_gitignore。

檢查：(1) 無已追蹤的 .env / .env.* 檔（.env.example / .env.sample 除外）；
      (2) .gitignore 含 .env 規則。
退出碼：0 通過；1 阻擋。
"""
from __future__ import annotations
import sys, re, subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALLOW = re.compile(r'\.env\.(example|sample|template)$')
ENV_RE = re.compile(r'(^|/)\.env(\.[^/]*)?$')

def tracked():
    try:
        r = subprocess.run(["git", "ls-files"], capture_output=True, text=True, cwd=ROOT)
        return r.stdout.splitlines()
    except Exception:
        return []

def main():
    bad = [f for f in tracked() if ENV_RE.search(f) and not ALLOW.search(f)]
    errs = []
    if bad:
        errs.append("已追蹤的機密檔（應移出版控並撤銷其中憑證）：\n  - " + "\n  - ".join(bad))
    gi = ROOT / ".gitignore"
    gi_text = gi.read_text() if gi.exists() else ""
    if not re.search(r'^\s*\.env', gi_text, re.M):
        errs.append(".gitignore 未包含 .env 規則（新建的 .env 可能被誤加入）。")
    if errs:
        print("⛔ G2 .env 防護阻擋：\n" + "\n".join(errs), file=sys.stderr)
        return 1
    print("✅ G2 .env 防護通過。")
    return 0

if __name__ == "__main__":
    sys.exit(main())
