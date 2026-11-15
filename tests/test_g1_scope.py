"""快篩的範圍解析（scripts/g1_screen.py，#266 的前半）。

Request 是命令列參數解析後的純值；Env 是外部依賴（Git、登錄庫、政策、設定根目錄、日期、並行數）。resolve_scope(request, env)
只決定「要掃哪些檔」：暫存區、變更清單、全量探索、指定檔、分類成清單或規則檔、base 查不到。它不查登錄庫、不寫任何輸出，
所有預期的失敗（--staged 取不到、變更清單讀不到、指定的檔不存在）都以未完成原因表達，不丟例外。
測試用 FakeGit 與暫存目錄驅動，不建 git 庫、不連網。
"""
import dataclasses
import datetime
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import g1_git as gg  # noqa: E402
import g1_registry as gr  # noqa: E402
import g1_screen as gs  # noqa: E402
from fakes import FakeGit  # noqa: E402
from vibesec_policy import Policy  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]


class RequestAndEnv(unittest.TestCase):
    def test_a_request_is_a_frozen_value_with_defaults(self):
        r = gs.Request()
        self.assertEqual((r.target, r.manifests, r.rule_files, r.changed_lists, r.staged, r.base), (None, (), (), (), False, None))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            r.staged = True

    def test_the_scope_kind_is_diff_when_only_changes_are_looked_at(self):
        # 以前：給了 --base、--staged 或 --changed-files 任一個就記 diff；只給 --target 或 --manifest 是 full
        self.assertEqual(gs.Request().kind, "full")
        self.assertEqual(gs.Request(target=ROOT, manifests=("a",)).kind, "full")
        self.assertEqual(gs.Request(staged=True).kind, "diff")
        self.assertEqual(gs.Request(base="abc").kind, "diff")
        self.assertEqual(gs.Request(changed_lists=("x.txt",)).kind, "diff")

    def test_build_env_derives_the_config_paths_from_the_config_root(self):
        env = gs.build_env(Policy(ROOT, project_root=None), git=FakeGit(), registry=gr.FakeRegistry())
        self.assertEqual(env.config_root, ROOT)
        self.assertEqual(env.config_dir, ROOT / "config" / "slopsquat")
        self.assertEqual(env.vibesec_file, ROOT / "vibesec.yaml")
        self.assertEqual(env.workers, 8)
        globs, rx = env.rule_cfg
        self.assertIn("AGENTS.md", globs)

    def test_build_env_takes_the_date_the_workers_and_the_config_root_as_given(self):
        # 今天的日期與並行數由呼叫端決定（allowlist 的到期判斷、登錄庫查詢的並行度），不是偷偷讀系統時鐘或寫死
        env = gs.build_env(Policy(ROOT, project_root=None), git=FakeGit(), registry=gr.FakeRegistry(),
                           today=datetime.date(2020, 1, 2), workers=3, config_root=ROOT)
        self.assertEqual((env.today, env.workers), (datetime.date(2020, 1, 2), 3))
        self.assertEqual(gs.build_env(Policy(ROOT, project_root=None), git=FakeGit(), registry=gr.FakeRegistry()).today, datetime.date.today())

    def test_the_rule_file_globs_are_read_from_the_config_root_once_per_env(self):
        # 規則檔的 glob 取 vibesec.yaml scan_agent_rule_files 與 cooldown.yaml agent_rule_files 的聯集；兩者都缺席時用內建預設
        with tempfile.TemporaryDirectory() as d:
            env = gs.build_env(Policy(ROOT, project_root=None), git=FakeGit(), registry=gr.FakeRegistry(), config_root=pathlib.Path(d))
        self.assertEqual(env.rule_cfg, (list(gs.RULE_FILE_DEFAULTS), None))

    def test_an_env_is_a_frozen_value_and_can_be_replaced_field_by_field(self):
        env = gs.build_env(Policy(ROOT, project_root=None), git=FakeGit(), registry=gr.FakeRegistry())
        other = dataclasses.replace(env, workers=2)
        self.assertEqual((env.workers, other.workers), (8, 2))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            env.workers = 3


class ResolveScope(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.D = pathlib.Path(self._tmp.name).resolve()

    def write(self, rel, text="x\n"):
        p = self.D / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def env(self, git=None, this_repo=False):
        """this_repo=True：政策的 root 就是被掃描的目錄（本 repo）；否則是外部專案。"""
        policy = Policy(ROOT, project_root=self.D if this_repo else None)
        return gs.build_env(policy, git=git or FakeGit(), registry=gr.FakeRegistry())

    def scope(self, request, **kw):
        return gs.resolve_scope(request, self.env(**kw))

    # ---- 全量探索 ----
    def test_a_target_with_nothing_selected_scans_the_tracked_files(self):
        for rel in ("requirements.txt", "AGENTS.md", "app/main.py", "sub/package.json"):
            self.write(rel)
        git = FakeGit(tracked=["requirements.txt", "AGENTS.md", "app/main.py", "sub/package.json", "untracked-in-list.txt"])
        s = self.scope(gs.Request(target=self.D), git=git)
        self.assertEqual(sorted(s.manifests), [self.D / "requirements.txt", self.D / "sub/package.json"])
        self.assertEqual(s.rule_files, (self.D / "AGENTS.md",))
        self.assertEqual((s.kind, s.problems, s.notes, s.failure), ("full", (), (), None))

    def test_outside_a_git_work_tree_the_directory_is_walked(self):
        self.write("requirements.txt"); self.write("node_modules/x/package.json"); self.write("sub/requirements.txt")
        s = self.scope(gs.Request(target=self.D), git=FakeGit(tracked=None))
        self.assertEqual(sorted(s.manifests), [self.D / "requirements.txt", self.D / "sub/requirements.txt"])

    def test_without_a_target_nothing_is_discovered(self):
        # 沒有 --target 也沒有選任何檔：不做全量探索（以前的行為），範圍是空的
        s = self.scope(gs.Request(), git=FakeGit(tracked=["requirements.txt"]))
        self.assertEqual((s.manifests, s.rule_files, s.problems, s.failure), ((), (), (), None))

    # ---- 指定的清單與規則檔 ----
    def test_explicit_manifests_are_the_only_thing_scanned(self):
        self.write("requirements.txt"); self.write("other/requirements.txt")
        git = FakeGit(tracked=["requirements.txt", "other/requirements.txt"])
        s = self.scope(gs.Request(target=self.D, manifests=("requirements.txt",)), git=git)
        self.assertEqual(s.manifests, (self.D / "requirements.txt",))

    def test_an_explicit_file_that_does_not_exist_is_an_incomplete_reason_not_a_silent_drop(self):
        self.write("requirements.txt")
        s = self.scope(gs.Request(target=self.D, manifests=("requirements.txt", "ghost/requirements.txt"), rule_files=("GHOST.md",)))
        self.assertEqual(s.manifests, (self.D / "requirements.txt",))
        self.assertEqual(s.problems, ("指定的檔案不存在，未檢查：ghost/requirements.txt, GHOST.md",))

    def test_the_same_file_named_twice_is_scanned_once_in_order(self):
        self.write("a/requirements.txt"); self.write("b/requirements.txt")
        s = self.scope(gs.Request(target=self.D, manifests=("b/requirements.txt", "a/requirements.txt", "b/requirements.txt")))
        self.assertEqual(s.manifests, (self.D / "b/requirements.txt", self.D / "a/requirements.txt"))

    # ---- --staged ----
    def test_staged_files_are_classified_and_the_rest_ignored(self):
        for rel in ("requirements.txt", "AGENTS.md", "app/main.py"):
            self.write(rel)
        s = self.scope(gs.Request(target=self.D, staged=True), git=FakeGit(staged=["requirements.txt", "AGENTS.md", "app/main.py"]))
        self.assertEqual((s.manifests, s.rule_files, s.kind), ((self.D / "requirements.txt",), (self.D / "AGENTS.md",), "diff"))

    def test_staged_with_nothing_staged_does_not_fall_back_to_a_full_scan(self):
        self.write("requirements.txt")
        s = self.scope(gs.Request(target=self.D, staged=True), git=FakeGit(staged=[], tracked=["requirements.txt"]))
        self.assertEqual((s.manifests, s.failure), ((), None))

    def test_staged_failure_is_a_scope_failure_with_the_original_messages(self):
        git = FakeGit(staged=gg.GitFailure("git diff --cached 失敗（exit 129：測試）"))
        s = self.scope(gs.Request(target=self.D, staged=True), git=git)
        self.assertEqual(s.failure, gs.ScopeFailure(
            problem="--staged 取不到暫存區變更：git diff --cached 失敗（exit 129：測試）",
            message="⚠️ G1 無法完成檢查：--staged 取不到暫存區變更（git diff --cached 失敗（exit 129：測試））→ incomplete。"))
        self.assertEqual((s.manifests, s.rule_files), ((), ()))

    # ---- --changed-files ----
    def listing(self, text):
        p = self.D / "changed.txt"
        p.write_text(text, encoding="utf-8")
        return str(p)

    def test_changed_files_come_from_the_list_with_blank_lines_and_padding_dropped(self):
        self.write("requirements.txt"); self.write("AGENTS.md")
        lst = self.listing("\n  requirements.txt  \n\nAGENTS.md\napp/main.py\n")
        s = self.scope(gs.Request(target=self.D, changed_lists=(lst,)))
        self.assertEqual((s.manifests, s.rule_files, s.kind), ((self.D / "requirements.txt",), (self.D / "AGENTS.md",), "diff"))

    def test_an_unreadable_list_is_a_scope_failure(self):
        s = self.scope(gs.Request(target=self.D, changed_lists=(str(self.D / "nope.txt"),)))
        self.assertIsNotNone(s.failure)
        self.assertEqual(s.failure.problem, f"變更檔清單讀不到：{self.D / 'nope.txt'}")
        self.assertTrue(s.failure.message.startswith(f"⚠️ G1 無法完成檢查：--changed-files {self.D / 'nope.txt'} 讀不到（"), s.failure.message)
        self.assertTrue(s.failure.message.endswith("）→ incomplete。"))

    def test_a_deleted_manifest_is_skipped_with_a_note_when_it_was_at_the_base(self):
        # HEAD 沒有、base 有 ＝ 這次 diff 刪掉的檔，正常略過並註記
        lst = self.listing("requirements.txt\n")
        git = FakeGit(files={("abc123", "requirements.txt"): "requests==2.0.0\n"})
        s = self.scope(gs.Request(target=self.D, changed_lists=(lst,), base="abc123"), git=git)
        self.assertEqual((s.manifests, s.problems, s.notes), ((), (), ("變更清單中已刪除的檔（略過）：requirements.txt",)))
        self.assertEqual(git.shown, [("abc123", "requirements.txt")], "路徑相對於被掃描的目標專案")

    def test_a_listed_file_missing_at_head_and_at_the_base_is_an_incomplete_reason(self):
        lst = self.listing("ghost/requirements.txt\n")
        s = self.scope(gs.Request(target=self.D, changed_lists=(lst,), base="abc123"), git=FakeGit())
        self.assertEqual(s.problems, ("變更清單中的檔案不存在，且不在 base abc123：ghost/requirements.txt",))
        self.assertEqual(s.notes, ())

    def test_without_a_base_a_missing_listed_file_is_just_a_deleted_file(self):
        lst = self.listing("requirements.txt\n")
        s = self.scope(gs.Request(target=self.D, changed_lists=(lst,)))
        self.assertEqual((s.problems, s.notes), ((), ("變更清單中已刪除的檔（略過）：requirements.txt",)))

    def test_an_empty_changed_list_is_not_a_reason_to_scan_everything(self):
        self.write("requirements.txt")
        lst = self.listing("\n")
        s = self.scope(gs.Request(target=self.D, changed_lists=(lst,)), git=FakeGit(tracked=["requirements.txt"]))
        self.assertEqual((s.manifests, s.kind), ((), "diff"))

    # ---- 規則檔的例外 ----
    def test_the_slopsquat_config_is_not_a_rule_file_in_this_repo_but_is_in_an_external_project(self):
        self.write("config/slopsquat/notes.md")
        req = gs.Request(target=self.D, staged=True)
        git = FakeGit(staged=["config/slopsquat/notes.md"])
        self.assertEqual(self.scope(req, git=git, this_repo=True).rule_files, ())
        self.assertEqual(self.scope(req, git=git, this_repo=False).rule_files, (self.D / "config/slopsquat/notes.md",))


if __name__ == "__main__":
    unittest.main()
