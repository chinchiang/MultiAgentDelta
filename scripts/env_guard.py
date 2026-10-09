#!/usr/bin/env python3
"""G2 .env 防護 — 確保機密檔不入版控。對應 vibesec.yaml g2_secrets.require_env_in_gitignore。

檢查：(1) 無已追蹤的 .env / .env.* 檔（.env.example / .env.sample 除外）；
      (2) .gitignore 含 .env 規則。
用法：python3 scripts/env_guard.py [--target <dir>]（預設本 repo；scripts/g2_secrets.py 以 check() 檢查被測專案）
退出碼：0 通過；1 阻擋。
"""
from __future__ import annotations
import sys, re, subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALLOW = re.compile(r'\.env\.(example|sample|template)$')
ENV_RE = re.compile(r'(^|/)\.env(\.[^/]*)?$')

def tracked(root=ROOT):
    """已追蹤的檔案路徑；不是 git repo 或 git 失敗 → None（不是空清單：查不到不等於沒有）。
    -z 與 core.quotepath=false：含非 ASCII 的路徑（設定/.env）否則會被加引號跳脫，規則比對不到（第四次審視 S-7）。"""
    try:
        r = subprocess.run(["git", "-c", "core.quotepath=false", "ls-files", "-z"], capture_output=True, text=True, cwd=root)
    except Exception:
        return None
    if r.returncode != 0:
        return None
    return [f for f in r.stdout.split("\0") if f]

def check(root=ROOT):
    """回傳錯誤訊息清單；空清單 = 通過。"""
    root = Path(root)
    files = tracked(root)
    errs = []
    if files is None:
        errs.append("無法列出已追蹤檔案（不是 git repo 或 git 失敗）：無法確認 .env 未入版控（incomplete ≠ pass）。")
        files = []
    bad = [f for f in files if ENV_RE.search(f) and not ALLOW.search(f)]
    if bad:
        errs.append("已追蹤的機密檔（應移出版控並撤銷其中憑證）：\n  - " + "\n  - ".join(bad))
    gi = root / ".gitignore"
    gi_text = gi.read_text() if gi.exists() else ""
    if not re.search(r'^\s*\.env', gi_text, re.M):
        errs.append(".gitignore 未包含 .env 規則（新建的 .env 可能被誤加入）。")
    return errs

def selftest():
    import tempfile
    fails = []
    with tempfile.TemporaryDirectory() as d:
        D = Path(d)
        if not any("無法列出" in e for e in check(D)):
            fails.append("非 git 目錄應回報無法確認（fail closed）")
        env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@x", "HOME": d, "PATH": __import__("os").environ.get("PATH", "")}
        subprocess.run(["git", "init", "-q", "."], cwd=D, check=True, env=env)
        (D / ".gitignore").write_text(".env\n")
        (D / "設定").mkdir(); (D / "設定/.env").write_text("X=1\n"); (D / ".env.example").write_text("X=\n")
        subprocess.run(["git", "add", "-f", "."], cwd=D, check=True, env=env)
        errs = check(D)
        if not any("設定/.env" in e for e in errs) or any(".env.example" in e for e in errs):
            fails.append(f"含非 ASCII 路徑的已追蹤 .env 應被抓到，.env.example 不算（得到 {errs}）")
        subprocess.run(["git", "rm", "-q", "--cached", "設定/.env"], cwd=D, check=True, env=env)
        if check(D):
            fails.append(f"移出版控後應通過（得到 {check(D)}）")
    return fails

def main(argv):
    if argv[:1] == ["selftest"]:
        fails = selftest()
        for f in fails:
            print(f"FAIL {f}")
        print("selftest " + ("通過" if not fails else f"失敗 {len(fails)} 項"))
        return 1 if fails else 0
    root = Path(argv[argv.index("--target") + 1]) if "--target" in argv[:-1] else ROOT
    errs = check(root)
    if errs:
        print("⛔ G2 .env 防護阻擋：\n" + "\n".join(errs), file=sys.stderr)
        return 1
    print("✅ G2 .env 防護通過。")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
