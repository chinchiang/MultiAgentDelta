#!/usr/bin/env python3
"""受驗樹 Git 列檔、copy_tracked 與 env_guard 的 fail-closed 測試（#310）。"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import env_guard  # noqa: E402
import g0_threat_model  # noqa: E402
import g3_sast  # noqa: E402
import g4_access  # noqa: E402
import g4_review  # noqa: E402
import sarif_gate  # noqa: E402
from gitrepo import TempRepo, isolated_git_environment  # noqa: E402
from jsonschema import Draft202012Validator  # noqa: E402
from vibesec_policy import Policy, temp_policy_root, tree_copy  # noqa: E402

# #374：g3_sast 會先下載 registry 規則集；測試注入假的下載，不連網
_REGISTRY_OK = lambda url: (200, b"rules:\n- id: t\n  pattern: never_matches_t()\n  message: m\n  languages: [python]\n  severity: INFO\n")

SCHEMA = Draft202012Validator(json.loads((ROOT / "schemas/gate-result.schema.json").read_text(encoding="utf-8")))


class EnvGuardFailClosedTests(unittest.TestCase):
    def setUp(self):
        isolated_git_environment(self)

    def test_unrelated_non_utf8_tracked_file_does_not_break_listing(self):
        with TempRepo() as repo:
            repo.write(".gitignore", ".env\n")
            repo.write_raw(b"docs/legacy-\x80.txt", b"ok\n")
            repo.commit()
            rec = env_guard.record(repo.dir)
            self.assertIsNone(rec["error"], f"無關的非 UTF-8 追蹤檔名不得讓列檔失效：{rec}")
            self.assertEqual(rec["committed"], [])
            self.assertEqual(rec["env_gitignore_fail"], 0)
            self.assertEqual(env_guard.check(repo.dir), [])

    def test_committed_env_under_non_utf8_dir_is_caught_and_json_safe(self):
        with TempRepo() as repo:
            repo.write(".gitignore", ".env\n")
            repo.write_raw(b"cfg-\xff/.env", b"SECRET=1\n")
            repo.git("add", "-f", ".")
            repo.git("commit", "-qm", "commit env")
            rec = env_guard.record(repo.dir)
            self.assertIsNone(rec["error"])
            self.assertEqual(rec["committed"], [r"cfg-\xff/.env"])
            p = subprocess.run(
                [sys.executable, "-I", str(ROOT / "scripts/env_guard.py"), "--target", str(repo.dir), "--json"],
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(p.returncode, 0, p.stderr.decode("utf-8", "replace"))
            cli_rec = json.loads(p.stdout.decode("utf-8"))
            self.assertEqual(cli_rec["committed"], [r"cfg-\xff/.env"])

    def test_gitignore_non_utf8_comment_and_oserror_fail_closed(self):
        with TempRepo() as repo:
            repo.write_raw(b".gitignore", b"# \xa5\xbb\xa6a\n.env\n")
            repo.commit()
            try:
                rec_ok = env_guard.record(repo.dir)
            except Exception as e:
                self.fail(f".gitignore 含非 UTF-8 註解不得拋例外：{type(e).__name__}: {e}")
            self.assertIsNone(rec_ok["error"])
            self.assertEqual(rec_ok["env_gitignore_fail"], 0)

        with TempRepo() as repo:
            (repo.dir / ".gitignore").mkdir()
            repo.write("keep.txt", "1\n")
            repo.commit()
            try:
                rec_dir = env_guard.record(repo.dir)
            except Exception as e:
                self.fail(f".gitignore 讀取 OSError 不得拋例外：{type(e).__name__}: {e}")
            self.assertTrue(rec_dir["error"], f".gitignore 為目錄無法讀取時應記 error（incomplete）：{rec_dir}")

        with TempRepo() as repo:
            (repo.dir / ".gitignore").symlink_to("missing-gitignore")
            repo.write("keep.txt", "1\n")
            repo.commit()
            rec_sym = env_guard.record(repo.dir)
            self.assertTrue(rec_sym["error"], f".gitignore 為 symlink 時不得跟隨或當不存在，應記 error：{rec_sym}")

        import os
        if os.geteuid() != 0:
            with TempRepo() as repo:
                sub = repo.dir / "locked-root"
                sub.mkdir()
                (sub / ".gitignore").write_text(".env\n", encoding="utf-8")
                sub.chmod(0o000)
                try:
                    try:
                        rec_perm = env_guard.record(sub)
                    except Exception as e:
                        self.fail(f".gitignore lstat PermissionError 不得拋例外：{type(e).__name__}: {e}")
                    self.assertIn("PermissionError", rec_perm["error"] or "", rec_perm)
                finally:
                    sub.chmod(0o755)


class G3CopyTrackedFailClosedTests(unittest.TestCase):
    def setUp(self):
        isolated_git_environment(self)

    def _make_fake_bins(self, d: pathlib.Path) -> tuple[dict[str, str], pathlib.Path]:
        bindir, log = d / "bin", d / "log.jsonl"
        bindir.mkdir(parents=True, exist_ok=True)
        for t in g3_sast.TOOLS:
            p = bindir / t
            p.write_text(g3_sast.FAKE_TOOL, encoding="utf-8")
            p.chmod(0o755)
        return {t: str(bindir / t) for t in g3_sast.TOOLS}, log

    def test_copy_tracked_preserves_non_utf8_and_leading_space_filenames(self):
        import os
        import tempfile

        with TempRepo() as repo, tempfile.TemporaryDirectory() as tmp:
            repo.write_raw(b" infra/space.tf", b'resource "aws_s3_bucket" "b" {}\n')
            repo.write_raw(b"infra/skip-\xff.tf", b"# checkov:skip=CKV_AWS_79: legacy\n")
            repo.write("deleted.tf", "x\n")
            repo.commit()
            (repo.dir / "deleted.tf").unlink()  # 工作樹已刪、尚未 git add 的一般檔應略過不報錯

            dst = pathlib.Path(tmp) / "copy"
            dst.mkdir()
            try:
                res = g3_sast.copy_tracked(repo.dir, dst)
            except Exception as e:
                self.fail(f"copy_tracked 遇非 UTF-8 檔名不得拋例外：{type(e).__name__}: {e}")
            self.assertIsInstance(res, tuple, f"copy_tracked 應回傳 (skipped, problem)，得到 {res!r}")
            skipped, problem = res
            self.assertEqual((skipped, problem), (0, None))
            self.assertTrue(os.path.isfile(os.fsencode(dst) + b"/ infra/space.tf"), "前導空白檔名應原樣複製")
            self.assertTrue(os.path.isfile(os.fsencode(dst) + b"/infra/skip-\xff.tf"), "非 UTF-8 檔名應原樣複製")

            with temp_policy_root() as pr:
                pol = sarif_gate.load_context(Policy(pr, project_root=None))
            bins, log = self._make_fake_bins(pathlib.Path(tmp))
            os.environ["FAKE_LOG"] = str(log)
            try:
                gate = g3_sast.scan(repo.dir, pathlib.Path(tmp) / "out", bins, pol=pol, registry_get=_REGISTRY_OK)
            finally:
                os.environ.pop("FAKE_LOG", None)
            self.assertEqual(gate["status"], "pass", gate)
            self.assertIn(r"infra/skip-\xff.tf", gate["status_reason"] or "")
            serialized = json.dumps(gate, ensure_ascii=False)
            serialized.encode("utf-8")
            self.assertEqual(list(SCHEMA.iter_errors(gate)), [])

            # Checkov 輸出含代理字元（\udcff）的 SARIF 時，_relativize_sarif 應將 URI 轉為百分比編碼並安全寫出 UTF-8
            raw_sarif = pathlib.Path(tmp) / "ck-surrogate.sarif"
            raw_sarif.write_text(
                json.dumps({
                    "version": "2.1.0",
                    "runs": [{
                        "tool": {"driver": {"name": "checkov"}},
                        "results": [{
                            "ruleId": "CKV2_VIBESEC_1",
                            "message": {"text": "hit in vibesec-target/infra/skip-\udcff.tf"},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "vibesec-target/infra/skip-\udcff.tf"}}}],
                        }],
                    }],
                }),
                encoding="utf-8",
            )
            try:
                g3_sast._relativize_sarif(raw_sarif, pathlib.Path(tmp) / "vibesec-target")
            except Exception as e:
                self.fail(f"_relativize_sarif 遇非 UTF-8 代理字元不得拋例外：{type(e).__name__}: {e}")
            rel_doc = json.loads(raw_sarif.read_text(encoding="utf-8"))
            self.assertEqual(
                rel_doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                "infra/skip-%FF.tf",
            )

    def test_copy_tracked_failures_turn_g3_incomplete_or_keep_blocking_fail(self):
        import os
        import shutil
        import tempfile

        with tempfile.TemporaryDirectory() as non_repo, tempfile.TemporaryDirectory() as dst_dir:
            res = g3_sast.copy_tracked(pathlib.Path(non_repo), pathlib.Path(dst_dir))
            self.assertIsInstance(res, tuple, f"非 git 目錄 copy_tracked 應回傳 (0, problem)，得到 {res!r}")
            self.assertIsNotNone(res[1], "git ls-files 失敗時 problem 不得為 None")

        with TempRepo() as repo, tempfile.TemporaryDirectory() as tmp:
            repo.write("infra/main.tf", 'resource "aws_instance" "x" {}\n')
            repo.commit()
            # 將已追蹤的一般檔換成同名目錄，模擬工作樹追蹤檔無法以一般檔案複製（root 與一般使用者皆必失敗）
            (repo.dir / "infra/main.tf").unlink()
            (repo.dir / "infra/main.tf").mkdir()

            with temp_policy_root() as pr:
                pol = sarif_gate.load_context(Policy(pr, project_root=None))
            bins, log = self._make_fake_bins(pathlib.Path(tmp))
            os.environ["FAKE_LOG"] = str(log)
            try:
                try:
                    gate = g3_sast.scan(repo.dir, pathlib.Path(tmp) / "out", bins, pol=pol, registry_get=_REGISTRY_OK)
                except Exception as e:
                    self.fail(f"g3_sast.scan 在追蹤檔無法複製時不得崩潰：{type(e).__name__}: {e}")
            finally:
                os.environ.pop("FAKE_LOG", None)
            crow = next(t for t in gate["tools"] if t["name"] == "checkov")
            self.assertEqual(crow["state"], "error")
            self.assertEqual(gate["status"], "incomplete", gate)
            self.assertIn("infra/main.tf", gate["status_reason"] or "")
            self.assertEqual(list(SCHEMA.iter_errors(gate)), [])

            # 若 semgrep 同時命中 blocking 規則，G3 仍維持 fail（blocking 優先於 incomplete）。
            # #317 之後外部受驗樹的 semgrep 也掃副本，副本建不出來時 semgrep 不執行（不退回直接掃受驗樹），
            # 所以這個子情境改在本 repo 的路徑驗證：semgrep 照舊在受驗樹裡執行，checkov 的副本照樣建不出來
            with temp_policy_root() as pr:
                pol_repo = sarif_gate.load_context(Policy(pr, project_root=repo.dir))
            os.environ["FAKE_LOG"] = str(log)
            os.environ["FAKE_SEMGREP_RULES"] = json.dumps(["vibesec.g3.command-injection"])
            try:
                gate_fail = g3_sast.scan(repo.dir, pathlib.Path(tmp) / "out-fail", bins, pol=pol_repo, registry_get=_REGISTRY_OK)
            finally:
                os.environ.pop("FAKE_LOG", None)
                os.environ.pop("FAKE_SEMGREP_RULES", None)
            self.assertEqual(gate_fail["status"], "fail", gate_fail)

            shutil.rmtree(repo.dir / "infra/main.tf")
            p = repo.write("infra/main.tf", 'resource "aws_instance" "x" {}\n')
            if os.geteuid() != 0:
                p.chmod(0o000)
                try:
                    dst2 = pathlib.Path(tmp) / "copy-perm"
                    dst2.mkdir()
                    try:
                        _, perm_problem = g3_sast.copy_tracked(repo.dir, dst2)
                    except Exception as e:
                        self.fail(f"copy_tracked 遇 PermissionError 不得拋例外：{type(e).__name__}: {e}")
                    self.assertIsNotNone(perm_problem)
                    self.assertIn("PermissionError", perm_problem)
                finally:
                    p.chmod(0o644)

                # 上層目錄無權限（lstat 拋 PermissionError）：Python 3.12+ exists() 會吞掉回傳 False，必須用 lstat 抓出
                sub = repo.dir / "locked-sub"
                repo.write("locked-sub/secret.tf", 'resource "aws_instance" "y" {}\n')
                repo.commit("add locked-sub")
                sub.chmod(0o000)
                try:
                    dst3 = pathlib.Path(tmp) / "copy-subperm"
                    dst3.mkdir()
                    try:
                        _, sub_problem = g3_sast.copy_tracked(repo.dir, dst3)
                    except Exception as e:
                        self.fail(f"copy_tracked 遇上層目錄無權限不得拋例外：{type(e).__name__}: {e}")
                    self.assertIsNotNone(sub_problem, "上層目錄無權限不得被當成已刪除而略過（fail-open）")
                    self.assertIn("PermissionError", sub_problem)
                finally:
                    sub.chmod(0o755)


class G0AndG4AccessCopyTrackedTests(unittest.TestCase):
    def setUp(self):
        isolated_git_environment(self)

    def _clean_threat_model(self) -> dict:
        import copy

        tm = copy.deepcopy(sarif_gate._yaml(ROOT / "docs/templates/threat-model.yaml"))
        tm["system"]["name"] = "clean-service"
        tm["agents"] = []
        tm["components"] = [c for c in tm["components"] if c["kind"] not in ("llm", "agent")]
        tm["flows"] = [f for f in tm["flows"] if "c-agent" not in (f["from"], f["to"])]
        return tm

    def test_g0_threat_model_fails_closed_on_copy_tracked_problem_and_handles_non_utf8(self):
        import shutil
        import tempfile
        import yaml

        with TempRepo() as repo, tempfile.TemporaryDirectory() as tmp:
            tm_file = pathlib.Path(tmp) / "tm.yaml"
            tm_file.write_text(yaml.safe_dump(self._clean_threat_model(), allow_unicode=True), encoding="utf-8")
            repo.write_raw(b"docs/legacy-\x80.md", b"ok\n")
            repo.write("src/app.py", "x = 1\n")
            repo.commit()

            g_ok = g0_threat_model.check(repo.dir, pathlib.Path(tmp) / "g0-ok", threat_model=tm_file)
            self.assertEqual(g_ok["status"], "pass", g_ok)
            self.assertEqual(list(SCHEMA.iter_errors(g_ok)), [])

            # 即使提供外部 --threat-model，受驗樹追蹤檔無法複製仍須使 G0 incomplete（不得拿殘缺副本驗 evidence）
            (repo.dir / "src/app.py").unlink()
            (repo.dir / "src/app.py").mkdir()
            try:
                g_inc = g0_threat_model.check(repo.dir, pathlib.Path(tmp) / "g0-inc", threat_model=tm_file)
            except Exception as e:
                self.fail(f"g0_threat_model.check 在追蹤檔無法複製時不得拋例外：{type(e).__name__}: {e}")
            finally:
                shutil.rmtree(repo.dir / "src/app.py")
            self.assertEqual(g_inc["status"], "incomplete", g_inc)
            self.assertEqual(g_inc["tools"][0]["state"], "error")
            self.assertIn("src/app.py", g_inc["status_reason"] or "")
            self.assertEqual(list(SCHEMA.iter_errors(g_inc)), [])

    def test_g4_access_fails_closed_on_copy_tracked_problem_and_handles_non_utf8_dirty_status(self):
        import shutil
        import tempfile
        import yaml

        with tree_copy("mode: shadow") as shadow_tree, TempRepo() as repo, tempfile.TemporaryDirectory() as tmp:
            script = shadow_tree / "scripts/g4_static.py"
            repo.write_raw(b"docs/legacy-\xff.txt", b"v1\n")
            repo.write("app.py", "x = 1\n")
            head = repo.commit()

            # 正常含非 UTF-8 追蹤檔的外部專案：不得出現 tuple 轉字串（略過 (0, None) 個 symlink）或編碼崩潰
            try:
                g_ext = g4_access.scan(repo.dir, pathlib.Path(tmp) / "g4-ext", script)
            except Exception as e:
                self.fail(f"g4_access.scan 遇非 UTF-8 追蹤檔不得拋例外：{type(e).__name__}: {e}")
            self.assertNotIn("略過 (0", g_ext.get("status_reason") or "")
            self.assertEqual(list(SCHEMA.iter_errors(g_ext)), [])

            # 受驗樹追蹤檔無法複製 → G4 靜態檢查不得對殘缺副本執行，tool state=error、status=incomplete
            (repo.dir / "app.py").unlink()
            (repo.dir / "app.py").mkdir()
            try:
                g_inc = g4_access.scan(repo.dir, pathlib.Path(tmp) / "g4-inc", script)
            except Exception as e:
                self.fail(f"g4_access.scan 在追蹤檔無法複製時不得拋例外：{type(e).__name__}: {e}")
            finally:
                shutil.rmtree(repo.dir / "app.py")
                repo.write("app.py", "x = 1\n")
            self.assertEqual(g_inc["status"], "incomplete", g_inc)
            self.assertEqual(g_inc["tools"][0]["state"], "error")
            self.assertIn("app.py", g_inc["status_reason"] or "")
            self.assertEqual(list(SCHEMA.iter_errors(g_inc)), [])

            # 本 repo 模式：有審查紀錄但工作目錄修改了非 UTF-8 追蹤檔 → _dirty_tracked 不拋 UnicodeDecodeError，判紀錄過期
            rec = g4_review._example()
            rec["commit"] = head
            (repo.dir / "reviews/g4").mkdir(parents=True)
            (repo.dir / f"reviews/g4/{head}.yaml").write_text(yaml.safe_dump(rec, allow_unicode=True), encoding="utf-8")
            repo.commit("add review")
            repo.write_raw(b"docs/legacy-\xff.txt", b"modified\n")
            saved = (g4_review.PROJECT, g4_review.REVIEWS_DIR)
            g4_review.PROJECT, g4_review.REVIEWS_DIR = repo.dir.resolve(), repo.dir.resolve() / "reviews/g4"
            try:
                try:
                    g_dirty = g4_access.scan(repo.dir, pathlib.Path(tmp) / "g4-dirty", script)
                except Exception as e:
                    self.fail(f"g4_access.scan 遇非 UTF-8 工作目錄修改不得拋例外：{type(e).__name__}: {e}")
            finally:
                g4_review.PROJECT, g4_review.REVIEWS_DIR = saved
            self.assertEqual(g_dirty["status"], "incomplete", g_dirty)
            self.assertIn("未提交的程式變更", g_dirty["status_reason"] or "")
            self.assertIn(r"docs/legacy-\xff.txt", g_dirty["status_reason"] or "")
            json.dumps(g_dirty, ensure_ascii=False).encode("utf-8")
            self.assertEqual(list(SCHEMA.iter_errors(g_dirty)), [])


if __name__ == "__main__":
    unittest.main()
