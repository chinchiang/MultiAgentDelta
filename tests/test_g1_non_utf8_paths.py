"""G1 快篩對「路徑不是合法 UTF-8」的處理（#283）。

非 UTF-8 的檔名在 Linux 上合法（檔名只是位元組）。路徑在程式內部以代理字元（surrogateescape）保留；進來的方式有
git 的追蹤檔清單、--changed-files 的讀取、走訪目錄（os.walk 本來就會產生代理字元）；輸出邊界（SARIF、閘門結果、標準輸出）
把它們轉成可輸出的形式，不讓代理字元流進 json.dumps 或寫檔而崩潰。兩組測試：
  OutputBoundary  printable／sarif_uri 兩個純函式：合法 UTF-8 的字串原樣不動，只有含代理字元的才轉義。
  NonUtf8Paths    經快篩的 main（假登錄庫、真 git）：不崩潰、其他路徑照常掃描、SARIF／閘門結果／標準輸出都是合法 UTF-8 JSON。
"""
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import g1_registry as gr  # noqa: E402
import g1_screen as sc  # noqa: E402  printable／sarif_uri 已收進 g1_screen（#266）
from fakes import FakeGit, run_cli  # noqa: E402
from gitrepo import TempRepo, isolated_git_environment, open_pull_request, write_raw  # noqa: E402

NON_UTF8_DIR = os.fsdecode(b"\xff-dir")      # 含代理字元：b"\xff" 以 surrogateescape 解碼
OLD = "2020-01-01T00:00:00Z"
REQUESTS = ("pypi", "requests", "2.0.0")


def known_registry():
    return gr.FakeRegistry({REQUESTS: gr.Found(gr.Facts("pypi", "requests", "2.0.0", OLD, None, None))})


def first_result_uri(run):
    """SARIF 第一筆發現的 artifactLocation.uri。"""
    return run.sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def typosquat_registry():
    return gr.FakeRegistry({("pypi", "reqeusts", "2.0.0"): gr.NotFound()})


class OutputBoundary(unittest.TestCase):
    def test_valid_utf8_text_is_left_alone(self):
        for s in ("requirements.txt", "中文/requirements.txt", "a b/c\td.txt", 'q"uote', "😀/x", ""):
            self.assertEqual(sc.printable(s), s)

    def test_a_lone_surrogate_is_escaped_as_the_original_byte(self):
        self.assertEqual(sc.printable(os.fsdecode(b"\xff-dir/x.txt")), r"\xff-dir/x.txt")
        self.assertEqual(sc.printable(os.fsdecode("中".encode() + b"\xfe")), r"中\xfe")

    def test_a_mixed_string_escapes_each_character_by_its_own_kind(self):
        # U+DC80–U+DCFF 是 surrogateescape 保留的原始位元組（寫成 \xHH）；範圍外的孤立代理字元寫成 \uXXXX；兩者可以並存
        self.assertEqual(sc.printable("a\udc80b\ud800c中"), r"a\x80b\ud800c中")

    def test_the_result_can_be_encoded_as_utf8(self):
        try:
            sc.printable(os.fsdecode(b"\xff\xfe\x80")).encode("utf-8")
        except UnicodeEncodeError as e:
            self.fail(f"轉義後仍含無法以 UTF-8 編碼的字元：{e}")

    def test_nested_structures_keys_and_non_strings_are_handled(self):
        raw = {NON_UTF8_DIR: [NON_UTF8_DIR, {"k": NON_UTF8_DIR}, ("t", NON_UTF8_DIR)], "n": None, "i": 3, "b": True, "f": 1.5}
        got = sc.printable(raw)
        self.assertEqual(got, {r"\xff-dir": [r"\xff-dir", {"k": r"\xff-dir"}, ["t", r"\xff-dir"]],
                               "n": None, "i": 3, "b": True, "f": 1.5})

    def test_the_input_is_not_modified(self):
        raw = {"a": [NON_UTF8_DIR]}
        sc.printable(raw)
        self.assertEqual(raw, {"a": [NON_UTF8_DIR]})

    def test_sarif_uri_of_a_valid_path_is_unchanged(self):
        for s in ("requirements.txt", "中文/a b.txt", "unknown"):
            self.assertEqual(sc.sarif_uri(s), s)

    def test_sarif_uri_of_a_non_utf8_path_is_percent_encoded(self):
        # artifactLocation.uri 是 URI：反斜線不是合法字元，要用百分比編碼；目錄分隔字元保留
        self.assertEqual(sc.sarif_uri(os.fsdecode(b"\xff-dir/requirements.txt")), "%FF-dir/requirements.txt")
        self.assertEqual(sc.sarif_uri(os.fsdecode("中/".encode() + b"\xfe.txt")), "%E4%B8%AD/%FE.txt")


class NonUtf8Paths(unittest.TestCase):
    def setUp(self):
        isolated_git_environment(self)

    def assert_well_formed(self, run):
        """沒有崩潰；閘門結果、SARIF 與標準輸出已在 run_cli 以嚴格 UTF-8 讀回並解析，能走到這裡就代表沒有代理字元漏進輸出。"""
        self.assertIsNone(run.error, f"main 不得因為非 UTF-8 的路徑而崩潰：{run.error!r}")
        self.assertEqual(run.gate.get("gate"), "G1")
        self.assertTrue(run.stdout.strip().startswith("{"))

    # ---- 入口：--changed-files 的讀取 ----
    def test_a_changed_files_list_with_a_non_utf8_path_scans_the_other_paths(self):
        with TempRepo() as r:
            open_pull_request(r, {"requirements.txt": "requests==2.0.0\n", b"\xff-dir/notes.txt": "x\n"})
            listing = pathlib.Path(tempfile.mkdtemp(), "changed.txt")
            listing.write_bytes(b"requirements.txt\n\xff-dir/notes.txt\n")
            run = run_cli(r.dir, "--changed-files", str(listing), "--base", "origin/main", registry=known_registry(), sarif=True)
        self.assertEqual(run.registry.calls, [REQUESTS], "整份清單不得因為一個非 UTF-8 的路徑而整個崩潰")
        self.assert_well_formed(run)

    def test_a_listed_non_utf8_path_that_does_not_exist_is_incomplete_not_a_crash(self):
        # 清單列的路徑在 HEAD 與 base 都不存在 → 未完成原因會把路徑印進標準輸出、閘門結果與標準錯誤；沒有任何清單可掃的分支也要轉義
        with TempRepo() as r:
            open_pull_request(r, {"requirements.txt": "x\n"})
            listing = pathlib.Path(tempfile.mkdtemp(), "changed.txt")
            listing.write_bytes(b"\xff-dir/requirements.txt\n")
            run = run_cli(r.dir, "--changed-files", str(listing), "--base", "origin/main", sarif=True)
        self.assert_well_formed(run)
        self.assertEqual((run.code, run.gate["status"]), (2, "incomplete"))
        self.assertIn(r"\xff-dir/requirements.txt", run.gate["status_reason"])
        self.assertIn(r"\xff-dir/requirements.txt", run.stdout)

    # ---- 入口：git 的追蹤檔清單（tracked_files）與走訪目錄 ----
    def test_a_full_scan_with_a_non_utf8_tracked_name_scans_the_manifests(self):
        with TempRepo() as r:
            r.write("requirements.txt", "requests==2.0.0\n")
            r.write_raw(b"\xff-dir/notes.txt")
            r.git("add", "-A")
            run = run_cli(r.dir, registry=known_registry(), sarif=True)
        self.assertEqual(run.registry.calls, [REQUESTS])
        self.assert_well_formed(run)

    def test_a_full_scan_outside_git_walks_non_utf8_names(self):
        # 非 git 目錄：os.walk 本來就會為非 UTF-8 的名稱產生代理字元；非 UTF-8 目錄下的清單也要被掃到（用不同的套件分辨）
        with tempfile.TemporaryDirectory() as d:
            D = pathlib.Path(d).resolve()
            (D / "requirements.txt").write_text("requests==2.0.0\n", encoding="utf-8")
            write_raw(D, b"\xff-dir/requirements.txt", b"flask==3.0.0\n")
            flask = ("pypi", "flask", "3.0.0")
            reg = gr.FakeRegistry({REQUESTS: gr.Found(gr.Facts("pypi", "requests", "2.0.0", OLD, None, None)),
                                   flask: gr.Found(gr.Facts("pypi", "flask", "3.0.0", OLD, None, None))})
            run = run_cli(D, git=FakeGit(tracked=None), registry=reg, sarif=True)
        self.assert_well_formed(run)
        self.assertEqual(sorted(run.registry.calls), sorted([REQUESTS, flask]))

    # ---- 輸出邊界：SARIF、閘門結果、標準輸出 ----
    def test_a_staged_manifest_under_a_non_utf8_directory_is_reported_without_crashing(self):
        with TempRepo() as r:
            r.write("keep.txt"); r.commit()
            r.write_raw(b"\xff-dir/requirements.txt", b"reqeusts==2.0.0\n")
            r.git("add", "-A")
            run = run_cli(r.dir, "--staged", registry=typosquat_registry(), sarif=True)
        self.assertEqual(run.code, 1, "查無此套件是 blocking 發現")
        self.assert_well_formed(run)
        self.assertEqual(first_result_uri(run), "%FF-dir/requirements.txt")
        self.assertIn(r"\xff-dir/requirements.txt", run.stdout, "標準輸出的 manifest 欄位是轉義後的文字")

    def test_the_same_manifest_under_a_valid_utf8_directory_is_reported_verbatim(self):
        # 對照：合法 UTF-8（含中文）的路徑，輸出一字不改
        with TempRepo() as r:
            r.write("keep.txt"); r.commit()
            r.write("中文/requirements.txt", "reqeusts==2.0.0\n")
            r.git("add", "-A")
            run = run_cli(r.dir, "--staged", registry=typosquat_registry(), sarif=True)
        self.assertEqual(run.code, 1)
        self.assertEqual(first_result_uri(run), "中文/requirements.txt")
        self.assertIn("中文/requirements.txt", run.stdout)


if __name__ == "__main__":
    unittest.main()
