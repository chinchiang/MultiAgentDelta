#!/usr/bin/env python3
"""Git 接縫：快篩對 git 的三個需求收在這裡（#265，#260 的 S4）。

介面（Git）有三個方法，工作目錄是建構時給的被掃描目標專案：
  staged()         -> list[str] | GitFailure   暫存區中新增／修改／改名的檔（--diff-filter=d：刪除的檔沒有內容可查），
                                                路徑相對於工作目錄。git 取不到（非 git 目錄、git 缺席）→ GitFailure：
                                                不知道改了什麼 ≠ 沒有變更，呼叫端必須記未完成（AGENTS.md 規則 2）
  tracked_files()  -> list[str] | None         git 追蹤中的檔（含已 git add 還沒提交的）。None＝git 說不出來（不是 git
                                                工作樹、git 缺席）：呼叫端退回走訪目錄，掃得更多、不是更少
  show(ref, path)  -> str | None               ref 版本的檔案內容；path 相對於工作目錄。檔案不存在（新檔）與 git 失敗都回 None
                                                （沿用重構前的語意）：呼叫端把 None 當成「base 查不到」，朝較嚴的一側走
HEAD 的 commit 只用來填閘門結果，不在接縫內：head_commit(cwd) 是獨立的函式，由命令列入口取得後傳給閘門結果。

生產轉接器是 SubprocessGit；記憶體內的替身 FakeGit 放在 tests/fakes.py。旗標（--relative、--diff-filter=d、ref:./path、-z）
與「只取追蹤檔」是轉接器的邏輯，替身驗證不了，由 tests/test_g1_git.py 的真 git 契約測試把關。
只用標準函式庫、沒有全域狀態。
"""
from __future__ import annotations
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class GitFailure:
    reason: str          # 例如「git diff --cached 失敗（exit 129：…）」；呼叫端把它組進未完成原因


class SubprocessGit:
    def __init__(self, cwd):
        self.cwd = cwd

    def staged(self):
        # 沿用重構前的寫法：沒有用 -z，所以非 ASCII 的路徑會被 git 加引號跳脫（"\344\270\255…"），之後的分類認不得它而略過。
        # 這是既有的限制，不是這個切片引入的；要修需要改成 -z，會讓檢查變嚴，屬於獨立的變嚴變更。
        try:
            r = subprocess.run(["git", "diff", "--cached", "--name-only", "--relative", "--diff-filter=d"],
                               capture_output=True, text=True, cwd=self.cwd)
        except Exception as e:
            return GitFailure(f"git 無法執行（{type(e).__name__}）")
        if r.returncode != 0:
            return GitFailure(f"git diff --cached 失敗（exit {r.returncode}：{(r.stderr.strip().splitlines() or ['?'])[0][:120]}）")
        return [l for l in r.stdout.splitlines() if l.strip()]

    def tracked_files(self):
        try:
            r = subprocess.run(["git", "ls-files", "-z"], capture_output=True, text=True, cwd=self.cwd)
        except OSError:
            return None
        return [f for f in r.stdout.split("\0") if f] if r.returncode == 0 else None

    def show(self, ref, path):
        try:
            r = subprocess.run(["git", "show", f"{ref}:./{path}"], capture_output=True, text=True, cwd=self.cwd)
            return r.stdout if r.returncode == 0 else None
        except Exception:
            return None


def head_commit(cwd):
    """目標專案 HEAD 的 commit；不是 git 工作樹、還沒有任何提交、git 缺席都回 None。
    要看退出碼：還沒有任何提交的庫裡 git rev-parse HEAD 會把字面上的 HEAD 印在標準輸出並以 exit 128 結束，
    重構前只取標準輸出，閘門結果的 commit 因此被寫成 "HEAD"，不合 gate-result.schema.json 的 ^[0-9a-f]{7,40}$。"""
    try:
        r = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=cwd)
    except Exception:
        return None
    return (r.stdout.strip() or None) if r.returncode == 0 else None
