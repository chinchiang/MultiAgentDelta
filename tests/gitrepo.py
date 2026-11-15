"""建暫存 git 庫的測試輔助。

固定使用者名稱與信箱、關閉簽章，並清掉 GIT_DIR、GIT_INDEX_FILE 等環境變數（在 git hook 裡跑測試時這些變數會指向外層的庫，
讓暫存庫的指令打到錯的地方）。供 G1 的 Git 契約測試使用，其他閘門的 selftest 之後被動到時再遷移過來（#265）。
"""
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"]


def clean_environ():
    """目前環境去掉所有 GIT_* 變數；測試用 mock.patch.dict(os.environ, clean_environ(), clear=True) 套用。"""
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def git(cwd, *args, check=True):
    return subprocess.run([*GIT, *args], cwd=cwd, capture_output=True, text=True, check=check, env=clean_environ())


def write_raw(directory, rel_bytes, data=b"x\n"):
    """以位元組建立檔案（檔名不是合法 UTF-8 時只能這樣建），並關檔；檔案系統不接受這種檔名時略過整個測試。"""
    raw = os.fsencode(directory) + b"/" + rel_bytes
    try:
        os.makedirs(os.path.dirname(raw), exist_ok=True)
        with open(raw, "wb") as f:
            f.write(data)
    except OSError:
        raise unittest.SkipTest("檔案系統不接受非 UTF-8 的檔名") from None


class TempRepo:
    """context manager：一個 init 過的空 git 庫（在暫存目錄）。dir 是它的絕對路徑。"""

    def __enter__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self._tmp.name).resolve()
        git(self.dir, "init", "-q")
        return self

    def __exit__(self, *exc):
        self._tmp.cleanup()
        return False

    def write_raw(self, rel_bytes, data=b"x\n"):
        write_raw(self.dir, rel_bytes, data)

    def write(self, rel, text="x\n"):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return p

    def git(self, *args, check=True):
        return git(self.dir, *args, check=check)

    def commit(self, message="t"):
        """git add -A 並提交；回傳新的 HEAD。"""
        self.git("add", "-A")
        self.git("commit", "-qm", message)
        return self.head()

    def head(self):
        return self.git("rev-parse", "HEAD").stdout.strip()


def isolated_git_environment(testcase):
    """讓一個 TestCase 在乾淨的 git 環境裡執行（沒有外層 GIT_DIR 等）；測試結束自動還原。"""
    patcher = mock.patch.dict(os.environ, clean_environ(), clear=True)
    patcher.start()
    testcase.addCleanup(patcher.stop)


def open_pull_request(r, files):
    """base 提交只有 keep.txt、origin/main 指向它（與 pull_request 事件的形狀相同）；第二個提交新增 files。
    files 是 {路徑: 內容}；路徑是 bytes 時用位元組建立（檔名不是合法 UTF-8 只能這樣建）。"""
    r.write("keep.txt")
    base = r.commit()
    r.git("update-ref", "refs/remotes/origin/main", base)
    for name, text in files.items():
        if isinstance(name, bytes):
            r.write_raw(name, text.encode("utf-8"))
        else:
            r.write(name, text)
    return r.commit()
