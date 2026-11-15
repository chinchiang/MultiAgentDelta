"""pr-gates.yml「偵測變更的 manifest 檔」步驟（#282）。

持續整合在這一步用 git diff 產生 reports/_changed-files.txt，再交給 G1 的 --changed-files。沒用 -z 時，git 的 core.quotePath
會把非 ASCII、含雙引號等的路徑加引號跳脫，G1 認不得而整個略過（fail-open，AGENTS.md 規則 2）。

測試直接解析 .github/workflows/pr-gates.yml、取出 id 為 diff 的步驟的 run 腳本，在暫存 git 庫裡以 GitHub Actions 的 bash 預設
（bash -eo pipefail）執行；不另寫一份模擬，workflow 改了這裡就跟著測。兩組測試：
  ChangedFilesList  步驟產出的清單：路徑逐字、_trusted/ 被排除、BASE_REF 缺席或取不到的退路、git／tr／grep 出錯時步驟失敗
                    （不是空清單：空清單會讓 G1 回報「無變更，略過」）。
  ListReachesG1     把清單交給 G1 的 --changed-files（假登錄庫、真 git）：中文目錄的清單必須被掃到；G1 解不開的路徑
                    （含換行、前後空白）要記 incomplete，不是通過。
"""
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import g1_registry as gr  # noqa: E402
from fakes import run_screen  # noqa: E402
from gitrepo import TempRepo, isolated_git_environment  # noqa: E402

WORKFLOW = pathlib.Path(__file__).resolve().parents[1] / ".github" / "workflows" / "pr-gates.yml"


def diff_step():
    wf = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = [s for job in wf["jobs"].values() for s in job.get("steps", []) if s.get("id") == "diff"]
    assert len(steps) == 1, f"pr-gates.yml 應該剛好有一個 id 為 diff 的步驟，實際 {len(steps)}"
    return steps[0]


def fake_command(directory, name, exit_code):
    """在 directory 放一個永遠以 exit_code 結束的假指令，讓步驟用到它（模擬 grep、tr 本身出錯）。"""
    path = pathlib.Path(directory, name)
    path.write_text(f"#!/bin/sh\nexit {exit_code}\n", encoding="utf-8")
    path.chmod(0o755)


def run_step(repo, base_ref, *, broken=None):
    """在 repo 裡執行 diff 步驟的 run 腳本；回傳（退出碼、清單的各行、標準錯誤）。清單檔不存在 → 行為 None。
    broken={"grep": 2}：讓步驟裡的 grep 以退出碼 2 結束。"""
    step = diff_step()
    assert step.get("shell") == "bash", "GitHub Actions 的 shell: bash 預設是 -eo pipefail，這裡的測試以此為前提"
    with tempfile.TemporaryDirectory() as tmp:
        output = pathlib.Path(tmp, "github-output")
        output.touch()
        env = {**os.environ, "BASE_REF": base_ref, "GITHUB_OUTPUT": str(output), "RUNNER_TEMP": tmp}
        if broken:
            fake_bin = pathlib.Path(tmp, "fake-bin")
            fake_bin.mkdir()
            for name, code in broken.items():
                fake_command(fake_bin, name, code)
            env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
        r = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", step["run"]],
                           cwd=repo, env=env, capture_output=True)
    listing = pathlib.Path(repo, "reports", "_changed-files.txt")
    lines = None
    if listing.exists():
        text = listing.read_bytes().decode("utf-8", "surrogateescape")
        lines = text.split("\n")[:-1] if text.endswith("\n") else text.split("\n") if text else []
    return r.returncode, lines, r.stderr.decode("utf-8", "replace")


def open_pull_request(r, files):
    """base 提交只有 keep.txt、origin/main 指向它（與 pull_request 事件的形狀相同）；第二個提交新增 files。
    files 是 {路徑: 內容}；路徑是 bytes 時用位元組建立（檔名不是合法 UTF-8 只能這樣建）。"""
    r.write("keep.txt")
    base = r.commit()
    r.git("update-ref", "refs/remotes/origin/main", base)
    for name, text in files.items():
        if isinstance(name, bytes):
            raw = os.fsencode(r.dir) + b"/" + name
            os.makedirs(os.path.dirname(raw), exist_ok=True)
            pathlib.Path(os.fsdecode(raw)).write_text(text, encoding="utf-8", errors="surrogateescape")
        else:
            r.write(name, text)
    return r.commit()


class ChangedFilesList(unittest.TestCase):
    def setUp(self):
        isolated_git_environment(self)

    def changed(self, names, *, base_ref="main", broken=None):
        """第二個提交新增 names（內容不重要）。"""
        with TempRepo() as r:
            open_pull_request(r, {n: "x\n" for n in names})
            return run_step(r.dir, base_ref, broken=broken)

    def test_ascii_names_are_listed_one_per_line(self):
        code, lines, _ = self.changed(["requirements.txt", "docs/package.json"])
        self.assertEqual((code, sorted(lines)), (0, ["docs/package.json", "requirements.txt"]))

    def test_non_ascii_spaced_and_quoted_names_are_verbatim(self):
        # 沒有 -z 時，git 的 core.quotePath 會把這些路徑加引號跳脫（"\344\270\255…"），G1 認不得而略過
        names = ["中文/requirements.txt", "a b/requirements.txt", 'q"uote/requirements.txt', "tab\tdir/package.json",
                 "requirements.txt"]
        code, lines, err = self.changed(names)
        self.assertEqual(code, 0, err)
        self.assertEqual(sorted(lines), sorted(names))

    def test_the_trusted_tree_is_left_out_of_the_list(self):
        code, lines, _ = self.changed(["_trusted/scripts/x.py", "requirements.txt", "docs/_trusted/y.txt"])
        self.assertEqual((code, sorted(lines)), (0, ["docs/_trusted/y.txt", "requirements.txt"]))

    def test_only_the_trusted_tree_changed_gives_an_empty_list_and_the_step_succeeds(self):
        code, lines, _ = self.changed(["_trusted/scripts/x.py"])
        self.assertEqual((code, lines), (0, []))

    def test_without_a_base_ref_the_previous_commit_is_the_base(self):
        # workflow_dispatch 等沒有 base_ref 的事件：BASE=HEAD~1
        code, lines, _ = self.changed(["中文/requirements.txt"], base_ref="")
        self.assertEqual((code, lines), (0, ["中文/requirements.txt"]))

    def test_an_unavailable_base_ref_falls_back_to_the_previous_commit(self):
        code, lines, _ = self.changed(["中文/requirements.txt"], base_ref="no-such-branch")
        self.assertEqual((code, lines), (0, ["中文/requirements.txt"]))

    def test_the_step_fails_when_git_cannot_diff_at_all(self):
        # 兩個 git diff 都失敗（只有一個提交、沒有 HEAD~1）→ 步驟失敗，不是空清單：空清單會讓 G1 回報「無變更，略過」
        with TempRepo() as r:
            r.write("requirements.txt")
            r.commit()
            code, lines, _ = run_step(r.dir, "")
        self.assertNotEqual(code, 0)
        self.assertNotEqual(lines, [], "不能留下一份空的清單當成「沒有變更」")

    def test_a_name_that_is_not_valid_utf8_stays_in_the_list(self):
        # GNU grep 對含非法 UTF-8 的行會當成二進位、只在標準錯誤印 "binary file matches" 就丟掉那一行：沒有 -a 時，
        # 這個路徑會悄悄從清單消失，G1 完全看不到（新的 fail-open）。清單裡必須原樣保留，其他路徑也不受影響。
        code, lines, err = self.changed([b"\xff-dir/package.json", "requirements.txt"])
        self.assertEqual(code, 0, err)
        self.assertEqual(sorted(lines), sorted(["requirements.txt", os.fsdecode(b"\xff-dir/package.json")]))

    def test_names_with_leading_or_trailing_spaces_are_verbatim(self):
        names = [" lead/requirements.txt", "trail /requirements.txt", "requirements.txt "]
        code, lines, err = self.changed(names)
        self.assertEqual(code, 0, err)
        self.assertEqual(sorted(lines), sorted(names))

    def test_the_step_fails_when_grep_itself_errors(self):
        # grep 的退出碼 1（沒有任何行被選中）可以繼續；退出碼 2（出錯）不行，否則變成空清單，G1 回報「無變更，略過」
        code, _, _ = self.changed(["requirements.txt"], broken={"grep": 2})
        self.assertNotEqual(code, 0)

    def test_the_step_fails_when_tr_itself_errors(self):
        code, _, _ = self.changed(["requirements.txt"], broken={"tr": 1})
        self.assertNotEqual(code, 0)

    def test_a_name_with_a_newline_is_split_in_two_lines(self):
        # 已知限制（見 #282）：G1 的 --changed-files 是逐行讀取。多出來的那一行不是真的檔案，G1 會因找不到而記 incomplete
        code, lines, _ = self.changed(["line\nbreak/requirements.txt"])
        self.assertEqual((code, lines), (0, ["line", "break/requirements.txt"]))


class ListReachesG1(unittest.TestCase):
    """步驟的產出直接交給 G1（假登錄庫、真 git）：中文目錄的清單必須被掃到；G1 解不開的路徑要記 incomplete。"""

    def setUp(self):
        isolated_git_environment(self)

    def scan(self, rel):
        with TempRepo() as r:
            open_pull_request(r, {rel: "requests==2.0.0\n"})
            code, lines, err = run_step(r.dir, "main")
            self.assertEqual(code, 0, err)
            with tempfile.TemporaryDirectory() as tmp:
                listing = pathlib.Path(tmp, "changed.txt")
                listing.write_bytes(("\n".join(lines) + "\n").encode("utf-8", "surrogateescape"))
                facts = gr.Found(gr.Facts("pypi", "requests", "2.0.0", "2020-01-01T00:00:00Z", None, None))
                reg = gr.FakeRegistry({("pypi", "requests", "2.0.0"): facts})
                return run_screen(r.dir, "--changed-files", str(listing), "--base", "origin/main", registry=reg)

    def test_a_manifest_under_a_non_ascii_directory_is_scanned(self):
        code, g, reg = self.scan("中文/requirements.txt")
        self.assertEqual(reg.calls, [("pypi", "requests", "2.0.0")], "必須被掃到，不是「無變更，略過」")
        self.assertEqual(g["scope"], "diff")

    def test_the_same_manifest_under_an_ascii_directory_is_scanned_the_same_way(self):
        code_a, g_a, reg_a = self.scan("docs/requirements.txt")
        code_c, g_c, reg_c = self.scan("中文/requirements.txt")
        self.assertEqual(reg_c.calls, reg_a.calls)
        self.assertEqual((code_c, g_c["status"], g_c["scope"]), (code_a, g_a["status"], g_a["scope"]))

    def test_names_that_g1_cannot_resolve_are_incomplete_not_pass(self):
        # 含換行的檔名被切成兩行；含前後空白的檔名在 G1 讀清單時被 strip。兩者都對不到真的檔案，G1 記 incomplete（退出碼 2）
        for rel in ("line\nbreak/requirements.txt", " lead/requirements.txt"):
            with self.subTest(rel=rel):
                code, g, reg = self.scan(rel)
                self.assertEqual((code, g["status"], reg.calls), (2, "incomplete", []))


if __name__ == "__main__":
    unittest.main()
