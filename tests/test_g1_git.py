"""Git 接縫（scripts/g1_git.py）。 / Git seam.

#265（#260 的 S4）：快篩對 git 的三個需求——暫存區清單、追蹤檔清單、某個 ref 上的檔案內容——收進接縫；HEAD 的 commit 只用來填
閘門結果，不在接縫內（head_commit 是獨立的函式）。生產轉接器 SubprocessGit 包住現有的 git 呼叫，旗標與失敗語意原樣沿用；
記憶體內的替身 FakeGit 放在 tests/fakes.py。

兩組測試：
  SubprocessGitContract  真 git、真暫存庫。旗標（--relative、--diff-filter=d、ref:./path、-z）與「只取追蹤檔」是轉接器的邏輯，
                         替身驗證不了，只有真 git 看得出來。
  FailClosedPaths        用 FakeGit 驅動快篩的 main：git 取不到暫存區、base 找不到、非 git 目錄這些失敗路徑，不必真的建庫。
"""
import contextlib
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import g1_git as gg  # noqa: E402
import g1_registry as gr  # noqa: E402
import g1_slopcheck as sc  # noqa: E402
from fakes import FakeGit  # noqa: E402
from gitrepo import TempRepo, isolated_git_environment  # noqa: E402

NO_GIT = {"PATH": "/nonexistent-dir-for-test"}      # 找不到 git 執行檔


class SubprocessGitContract(unittest.TestCase):
    def setUp(self):
        isolated_git_environment(self)

    # ---- staged ----
    def test_staged_lists_added_modified_and_renamed_but_not_deleted(self):
        # --diff-filter=d：刪除的檔沒有內容可查；改名只列新名稱
        with TempRepo() as r:
            r.write("a.txt", "1\n"); r.write("rm.txt", "gone\n"); r.write("mv.txt", "same content\n" * 4)
            r.commit()
            r.write("a.txt", "2\n"); r.write("new.txt", "n\n")
            r.git("rm", "-q", "rm.txt"); r.git("mv", "mv.txt", "moved.txt"); r.git("add", "a.txt", "new.txt")
            self.assertEqual(sorted(gg.SubprocessGit(r.dir).staged()), ["a.txt", "moved.txt", "new.txt"])

    def test_staged_ignores_unstaged_and_untracked_changes(self):
        with TempRepo() as r:
            r.write("a.txt", "1\n"); r.commit()
            r.write("a.txt", "changed but not staged\n"); r.write("untracked.txt")
            self.assertEqual(gg.SubprocessGit(r.dir).staged(), [])

    def test_nothing_staged_is_an_empty_list_not_a_failure(self):
        # 「沒有暫存的變更」與「取不到暫存區」是兩回事：前者是 []、後者是 GitFailure（不知道改了什麼 ≠ 沒有變更）
        with TempRepo() as r:
            r.write("a.txt"); r.commit()
            self.assertEqual(gg.SubprocessGit(r.dir).staged(), [])

    def test_staged_is_relative_to_the_working_directory(self):
        # --relative：在子目錄裡只看子目錄內的變更，路徑相對於子目錄
        with TempRepo() as r:
            r.write("sub/keep.txt"); r.write("top.txt"); r.commit()
            r.write("sub/x.txt"); r.write("outside.txt"); r.git("add", "sub/x.txt", "outside.txt")
            self.assertEqual(gg.SubprocessGit(r.dir / "sub").staged(), ["x.txt"])

    def test_staged_keeps_non_ascii_spaced_and_quoted_names_verbatim(self):
        # -z：路徑逐字，不被 git 加引號跳脫（core.quotePath 預設會把非 ASCII 變成 "\\344\\270…"），也不被空白或換行切錯
        names = ["中文/requirements.txt", "sub/b c.txt", " lead.txt", "trail.txt ", 'q"uote.txt', "tab\tname.txt", "line\nbreak.txt"]
        with TempRepo() as r:
            r.write("keep.txt"); r.commit()
            for n in names:
                r.write(n)
            r.git("add", "--", *names)
            self.assertEqual(sorted(gg.SubprocessGit(r.dir).staged()), sorted(names))

    def test_staged_keeps_a_name_that_is_not_valid_utf8(self):
        # -z 輸出是原始位元組：一個舊編碼的檔名不得讓整個 --staged 失敗（以前引號跳脫是純 ASCII，不會遇到解碼問題）
        with TempRepo() as r:
            r.write("keep.txt"); r.commit()
            raw = os.fsencode(r.dir) + b"/dir/\xff\xfe.txt"
            try:
                os.makedirs(os.path.dirname(raw))
                open(raw, "wb").close()
            except OSError:
                self.skipTest("檔案系統不接受非 UTF-8 的檔名")
            r.git("add", "-A")
            got = gg.SubprocessGit(r.dir).staged()
            self.assertEqual([os.fsencode(n) for n in got], [b"dir/\xff\xfe.txt"])

    def test_staged_failure_outside_a_repository(self):
        with tempfile.TemporaryDirectory() as d:
            r = gg.SubprocessGit(pathlib.Path(d)).staged()
        self.assertIsInstance(r, gg.GitFailure)
        self.assertTrue(r.reason.startswith("git diff --cached 失敗（exit "), r.reason)

    def test_staged_failure_when_git_is_missing(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, NO_GIT):
            r = gg.SubprocessGit(pathlib.Path(d)).staged()
        self.assertEqual(r, gg.GitFailure("git 無法執行（FileNotFoundError）"))

    # ---- tracked_files ----
    def test_tracked_files_are_only_what_git_tracks(self):
        # 只取追蹤中的檔案：未追蹤的、被 .gitignore 忽略的都不算；已 git add 還沒提交的算（在索引裡）
        with TempRepo() as r:
            r.write(".gitignore", "ignored/\n"); r.write("a.txt"); r.write("deep/er/b.txt"); r.commit()
            r.write("untracked.txt"); r.write("ignored/x.txt"); r.write("added.txt"); r.git("add", "added.txt")
            self.assertEqual(sorted(gg.SubprocessGit(r.dir).tracked_files()), [".gitignore", "a.txt", "added.txt", "deep/er/b.txt"])

    def test_tracked_files_keeps_spaces_and_non_ascii_names_verbatim(self):
        with TempRepo() as r:
            r.write("sub/b c.txt"); r.write("中文/requirements.txt"); r.commit()
            self.assertEqual(sorted(gg.SubprocessGit(r.dir).tracked_files()), ["sub/b c.txt", "中文/requirements.txt"])

    def test_tracked_files_in_a_subdirectory_are_relative_to_it(self):
        with TempRepo() as r:
            r.write("sub/x.txt"); r.write("top.txt"); r.commit()
            self.assertEqual(gg.SubprocessGit(r.dir / "sub").tracked_files(), ["x.txt"])

    def test_tracked_files_of_an_empty_repository(self):
        with TempRepo() as r:
            self.assertEqual(gg.SubprocessGit(r.dir).tracked_files(), [])

    def test_tracked_files_is_none_when_git_cannot_tell(self):
        # None＝git 說不出來（不是 git 工作樹、git 缺席）：呼叫端退回走訪目錄，掃得更多、不是更少
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(gg.SubprocessGit(pathlib.Path(d)).tracked_files())
            with mock.patch.dict(os.environ, NO_GIT):
                self.assertIsNone(gg.SubprocessGit(pathlib.Path(d)).tracked_files())

    # ---- show ----
    def test_show_returns_the_content_at_a_ref(self):
        with TempRepo() as r:
            r.write("a.txt", "old\n"); first = r.commit()
            r.write("a.txt", "new\n"); r.write("later.txt", "added later\n"); r.commit()
            git = gg.SubprocessGit(r.dir)
            self.assertEqual(git.show("HEAD", "a.txt"), "new\n")
            self.assertEqual(git.show(first, "a.txt"), "old\n")
            self.assertEqual(git.show("HEAD", "later.txt"), "added later\n")

    def test_show_is_none_when_the_file_did_not_exist_at_the_ref(self):
        with TempRepo() as r:
            r.write("a.txt"); first = r.commit()
            r.write("later.txt"); r.commit()
            self.assertIsNone(gg.SubprocessGit(r.dir).show(first, "later.txt"))

    def test_show_conflates_a_missing_file_with_a_git_failure(self):
        # 現狀（#265 明載維持）：「檔案不存在」與「git 失敗」都回 None。呼叫端把 None 當成「base 查不到」，
        # 朝較嚴的一側走（給了 --base 卻查不到 → 未完成；diff-aware 查不到 → 當成新檔、全部套件都查）
        with TempRepo() as r:
            r.write("a.txt"); r.commit()
            git = gg.SubprocessGit(r.dir)
            self.assertIsNone(git.show("HEAD", "nonexistent.txt"))
            self.assertIsNone(git.show("no-such-ref", "a.txt"))
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(gg.SubprocessGit(pathlib.Path(d)).show("HEAD", "a.txt"))
            with mock.patch.dict(os.environ, NO_GIT):
                self.assertIsNone(gg.SubprocessGit(pathlib.Path(d)).show("HEAD", "a.txt"))

    def test_show_paths_are_relative_to_the_working_directory(self):
        # ref:./path：路徑相對於工作目錄（被掃描的目標專案），不是 repo 根目錄
        with TempRepo() as r:
            r.write("sub/b c.txt", "inner\n"); r.write("top.txt", "outer\n"); r.commit()
            git = gg.SubprocessGit(r.dir / "sub")
            self.assertEqual(git.show("HEAD", "b c.txt"), "inner\n")
            self.assertIsNone(git.show("HEAD", "top.txt"))

    # ---- head_commit ----
    def test_head_commit(self):
        with TempRepo() as r:
            self.assertIsNone(gg.head_commit(r.dir), "還沒有任何提交")
            r.write("a.txt")
            head = r.commit()
            self.assertEqual(gg.head_commit(r.dir), head)
            self.assertRegex(head, r"^[0-9a-f]{40}$")
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(gg.head_commit(pathlib.Path(d)))
            with mock.patch.dict(os.environ, NO_GIT):
                self.assertIsNone(gg.head_commit(pathlib.Path(d)))


OLD = "2020-01-01T00:00:00Z"
PYPI_OK = gr.Found(gr.Facts("pypi", "requests", "2.0.0", OLD, None, None))
NPM_OK = lambda name: gr.Found(gr.Facts("npm", name, "1.0.0", OLD, {}, 5000))  # noqa: E731


def run_screen(D, *argv, git=None, registry=None):
    """以假登錄庫跑快篩的 main，回傳（退出碼、閘門結果、登錄庫）；git=None 時用生產的 SubprocessGit。"""
    gate = D.parent / f"{D.name}-gate.json"
    reg = registry or gr.FakeRegistry()
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(sc, "GIT", git), mock.patch.object(sc, "REGISTRY", reg), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = sc.main(["g1_slopcheck.py", "--target", str(D), *argv, "--gate", str(gate)])
        finally:
            sc.TARGET = sc.ROOT
    g = json.loads(gate.read_text(encoding="utf-8")) if gate.exists() else {}
    if gate.exists():
        gate.unlink()
    return code, g, reg


class FailClosedPaths(unittest.TestCase):
    """用 FakeGit 與 FakeRegistry 驅動快篩的 main（不連網、不建 git 庫）。"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.D = pathlib.Path(self._tmp.name).resolve()

    def write(self, rel, text):
        p = self.D / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def run_main(self, *argv, git=None, registry=None):
        return run_screen(self.D, *argv, git=git, registry=registry)

    def test_staged_failure_is_incomplete_not_no_changes(self):
        # 不知道改了什麼 ≠ 沒有變更：取不到暫存區 → 未完成（exit 2），不查任何套件
        fake = FakeGit(staged=gg.GitFailure("git diff --cached 失敗（exit 129：測試）"))
        code, g, reg = self.run_main("--staged", git=fake)
        self.assertEqual((code, g["status"], g["scope"]), (2, "incomplete", "diff"))
        self.assertIn("--staged 取不到暫存區變更：git diff --cached 失敗（exit 129：測試）", g["status_reason"])
        self.assertEqual(reg.calls, [])

    def test_only_the_staged_files_are_scanned(self):
        self.write("requirements.txt", "requests==2.0.0\n")
        self.write("other/requirements.txt", "flask==3.0.0\n")
        reg = gr.FakeRegistry({("pypi", "requests", "2.0.0"): PYPI_OK})
        _, g, reg = self.run_main("--staged", git=FakeGit(staged=["requirements.txt"]), registry=reg)
        self.assertEqual(reg.calls, [("pypi", "requests", "2.0.0")])
        self.assertEqual(g["scope"], "diff")

    def test_a_listed_file_missing_at_head_and_at_base_is_incomplete(self):
        # diff 清單與 base 對不上：HEAD 沒有、base 也查不到 → 未完成（不是靜默略過）
        self.write("changed.txt", "ghost/requirements.txt\n")
        fake = FakeGit()
        code, g, reg = self.run_main("--changed-files", str(self.D / "changed.txt"), "--base", "abc123", git=fake)
        self.assertEqual((code, g["status"]), (2, "incomplete"))
        self.assertIn("ghost/requirements.txt", g["status_reason"])
        self.assertIn("abc123", g["status_reason"])
        self.assertEqual(fake.shown, [("abc123", "ghost/requirements.txt")], "路徑相對於被掃描的目標專案")
        self.assertEqual(reg.calls, [])

    def test_a_file_deleted_by_the_diff_is_skipped_with_a_note(self):
        # HEAD 沒有、base 有 ＝ 這次 diff 刪掉的檔，正常略過並註記
        self.write("changed.txt", "requirements.txt\n")
        fake = FakeGit(files={("abc123", "requirements.txt"): "requests==2.0.0\n"})
        code, g, reg = self.run_main("--changed-files", str(self.D / "changed.txt"), "--base", "abc123", git=fake)
        self.assertEqual((code, g["status"]), (0, "pass"))
        self.assertIn("requirements.txt", g["status_reason"])
        self.assertEqual(reg.calls, [])

    def test_with_a_base_only_new_or_changed_packages_are_checked(self):
        self.write("package.json", json.dumps({"dependencies": {"left-pad": "1.0.0", "axois": "1.0.0"}}))
        before = json.dumps({"dependencies": {"left-pad": "1.0.0"}})
        reg = gr.FakeRegistry({("npm", "axois", "1.0.0"): NPM_OK("axois"), ("npm", "left-pad", "1.0.0"): NPM_OK("left-pad")})
        fake = FakeGit(files={("abc123", "package.json"): before})
        self.run_main("--manifest", "package.json", "--base", "abc123", git=fake, registry=reg)
        self.assertEqual(reg.calls, [("npm", "axois", "1.0.0")], "base 已有的 left-pad 不再查")
        self.assertEqual(fake.shown, [("abc123", "package.json")])

    def test_when_the_file_is_not_at_the_base_every_package_is_checked(self):
        # 新檔（或 git 取不到 base）→ 全部套件都查：朝較嚴的一側走
        self.write("package.json", json.dumps({"dependencies": {"left-pad": "1.0.0", "axois": "1.0.0"}}))
        reg = gr.FakeRegistry({("npm", "axois", "1.0.0"): NPM_OK("axois"), ("npm", "left-pad", "1.0.0"): NPM_OK("left-pad")})
        self.run_main("--manifest", "package.json", "--base", "abc123", git=FakeGit(), registry=reg)
        self.assertEqual(sorted(reg.calls), [("npm", "axois", "1.0.0"), ("npm", "left-pad", "1.0.0")])

    def test_a_full_scan_uses_only_the_tracked_files(self):
        self.write("requirements.txt", "requests==2.0.0\n")
        self.write("vendor/requirements.txt", "flask==3.0.0\n")
        reg = gr.FakeRegistry({("pypi", "requests", "2.0.0"): PYPI_OK})
        self.run_main(git=FakeGit(tracked=["requirements.txt"]), registry=reg)
        self.assertEqual(reg.calls, [("pypi", "requests", "2.0.0")])

    def test_a_full_scan_outside_a_git_work_tree_walks_the_directory(self):
        # git 說不出追蹤檔（None）→ 走訪目錄，略過安裝產物與快取；掃得更多、不是更少
        self.write("requirements.txt", "requests==2.0.0\n")
        self.write("sub/requirements.txt", "flask==3.0.0\n")
        self.write("node_modules/x/package.json", json.dumps({"dependencies": {"evil": "1.0.0"}}))
        reg = gr.FakeRegistry({("pypi", "requests", "2.0.0"): PYPI_OK,
                               ("pypi", "flask", "3.0.0"): gr.Found(gr.Facts("pypi", "flask", "3.0.0", OLD, None, None))})
        self.run_main(git=FakeGit(tracked=None), registry=reg)
        self.assertEqual(sorted(reg.calls), [("pypi", "flask", "3.0.0"), ("pypi", "requests", "2.0.0")])

    def test_without_an_injected_git_the_production_one_runs_in_the_scanned_project(self):
        seen = []

        def factory(cwd):
            seen.append(pathlib.Path(cwd).resolve())
            return FakeGit(staged=["requirements.txt"])
        self.write("requirements.txt", "requests==2.0.0\n")
        reg = gr.FakeRegistry({("pypi", "requests", "2.0.0"): PYPI_OK})
        with mock.patch.object(sc, "SubprocessGit", factory):
            self.run_main("--staged", git=None, registry=reg)
        self.assertEqual(seen, [self.D], "沒有注入時，用生產的 SubprocessGit，工作目錄是被掃描的目標專案")
        self.assertEqual(reg.calls, [("pypi", "requests", "2.0.0")])


class StagedNonAsciiPathsAreScanned(unittest.TestCase):
    """#280：--staged 對非 ASCII 路徑的清單不得悄悄略過（真 git、假登錄庫）。"""

    def setUp(self):
        isolated_git_environment(self)

    def scan_staged(self, rel):
        with TempRepo() as r:
            r.write("keep.txt"); r.commit()
            r.write(rel, "requests==2.0.0\n"); r.git("add", "--", rel)
            reg = gr.FakeRegistry({("pypi", "requests", "2.0.0"): PYPI_OK})
            return run_screen(r.dir, "--staged", registry=reg)

    def test_a_manifest_under_a_non_ascii_directory_is_scanned(self):
        code, g, reg = self.scan_staged("中文/requirements.txt")
        self.assertEqual(reg.calls, [("pypi", "requests", "2.0.0")], "暫存的清單必須被掃到，不是「無變更，略過」")
        self.assertEqual(g["scope"], "diff")

    def test_the_same_manifest_under_an_ascii_directory_is_scanned_the_same_way(self):
        # 對照：目錄名稱不同、內容相同，結果必須一致
        code_ascii, g_ascii, reg_ascii = self.scan_staged("docs/requirements.txt")
        code_cjk, g_cjk, reg_cjk = self.scan_staged("中文/requirements.txt")
        self.assertEqual(reg_cjk.calls, reg_ascii.calls)
        self.assertEqual((code_cjk, g_cjk["status"], g_cjk["scope"]), (code_ascii, g_ascii["status"], g_ascii["scope"]))


if __name__ == "__main__":
    unittest.main()
