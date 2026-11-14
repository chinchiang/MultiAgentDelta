"""套件登錄庫接縫（scripts/g1_registry.py）。 / Package-registry seam.

#264（#260 的 S3）：facts(eco, name, ver) 回傳三態 Found／NotFound／Unavailable，不丟例外；requires(name, ver)
取得 PyPI 的相依名稱。生產轉接器 HttpRegistry 把 npm 與 PyPI 的 JSON 翻譯成同一個 Facts，缺資料用 Unknown 表達
（這個生態系沒有這項資料可查則是 None）；替身 FakeRegistry 給測試與評測用。
傳輸層的替身（依網址腳本化的回應）在 tests/fakes.py，不放生產程式。
"""
import http.client
import pathlib
import sys
import unittest
import urllib.error

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import g1_registry as gr  # noqa: E402
from fakes import RoutedTransport, http_error  # noqa: E402

OLD = "2020-01-01T00:00:00Z"


def registry(routes):
    t = RoutedTransport(routes)
    return gr.HttpRegistry(transport=t, retries=2, backoff=0), t


NPM = "https://registry.npmjs.org/left-pad"
NPM_DL = "https://api.npmjs.org/downloads/point/last-week/left-pad"
PYPI = "https://pypi.org/pypi/requests/json"
NPM_META = {"time": {"1.3.0": OLD}, "versions": {"1.3.0": {"scripts": {"postinstall": "node x.js"}}}, "dist-tags": {"latest": "1.3.0"}}
PYPI_META = {"info": {"version": "2.32.0"}, "releases": {"2.32.0": [{"upload_time_iso_8601": OLD}], "2.33.0": []}}


class Names(unittest.TestCase):
    def test_valid_name(self):
        # npm 與 PyPI 的命名規則；名稱來自 PR 內的 manifest（不可信），不合法就不送出查詢
        for eco, name in (("npm", "left-pad"), ("npm", "@scope/pkg"), ("npm", "a.b_c~d"), ("pypi", "requests"), ("pypi", "Foo_Bar.baz-1")):
            self.assertTrue(gr.valid_name(eco, name), (eco, name))
        for eco, name in (("npm", ""), ("npm", "../etc/passwd"), ("npm", "a b"), ("npm", "@scope"), ("npm", "x" * 215),
                          ("pypi", ""), ("pypi", "-leading"), ("pypi", "trailing-"), ("pypi", "a/b"), ("pypi", "x" * 215), ("npm", None)):
            self.assertFalse(gr.valid_name(eco, name), (eco, name))

    def test_canon(self):
        # PyPI 依 PEP 503：大小寫不分，連續的 -、_、. 視為同一個 -；npm 只轉小寫（_ 與 - 是不同套件）
        self.assertEqual(gr.canon("pypi", "Typing_Extensions"), "typing-extensions")
        self.assertEqual(gr.canon("pypi", "a..b__c--d"), "a-b-c-d")
        self.assertEqual(gr.canon("npm", "Left_Pad"), "left_pad")
        self.assertNotEqual(gr.canon("npm", "a_b"), gr.canon("npm", "a-b"))

    def test_same_pep440(self):
        self.assertTrue(gr.same_pep440("2.32", "2.32.0"))
        self.assertTrue(gr.same_pep440("1.0RC1", "1.0rc1"))
        self.assertFalse(gr.same_pep440("2.31.9", "2.32"))


class NpmFacts(unittest.TestCase):
    def test_found_is_translated(self):
        reg, t = registry({NPM: NPM_META, NPM_DL: {"downloads": 5000}})
        r = reg.facts("npm", "left-pad", "1.3.0")
        self.assertEqual(r, gr.Found(gr.Facts("npm", "left-pad", "1.3.0", OLD, {"postinstall": "node x.js"}, 5000)))
        self.assertEqual(t.calls, [NPM, NPM_DL], "先查中繼資料，再查週下載量")

    def test_version_defaults_to_latest_and_v_prefix_matches(self):
        reg, _ = registry({NPM: NPM_META, NPM_DL: {"downloads": 1}})
        self.assertEqual(reg.facts("npm", "left-pad", None).facts.version, "1.3.0")
        self.assertEqual(reg.facts("npm", "left-pad", "v1.3.0").facts.version, "1.3.0")

    def test_missing_data_is_unknown_not_empty(self):
        # 鎖定版本不在發布紀錄 → 發布時間與安裝腳本都是「未知」，不是空值（空值會被當成「沒有腳本」而通過）
        reg, _ = registry({NPM: NPM_META, NPM_DL: {"downloads": 1}})
        f = reg.facts("npm", "left-pad", "9.9.9").facts
        self.assertEqual(f.version, "9.9.9")
        self.assertIsInstance(f.published_at, gr.Unknown)
        self.assertIsInstance(f.install_scripts, gr.Unknown)
        reg, _ = registry({NPM: {}, NPM_DL: {"downloads": 1}})
        f = reg.facts("npm", "left-pad", None).facts
        self.assertIsNone(f.version)
        self.assertIsInstance(f.published_at, gr.Unknown)
        self.assertIsInstance(f.install_scripts, gr.Unknown)

    def test_scripts_default_to_an_empty_mapping_when_the_version_has_none(self):
        reg, _ = registry({NPM: {"time": {"1.0.0": OLD}, "versions": {"1.0.0": {}}}, NPM_DL: {"downloads": 1}})
        self.assertEqual(reg.facts("npm", "left-pad", "1.0.0").facts.install_scripts, {})

    def test_scoped_package_urls(self):
        reg, t = registry({"https://registry.npmjs.org/@scope/pkg": NPM_META, "https://api.npmjs.org/downloads/point/last-week/@scope/pkg": {"downloads": 1}})
        self.assertIsInstance(reg.facts("npm", "@scope/pkg", None), gr.Found)
        self.assertEqual(t.calls, ["https://registry.npmjs.org/@scope/pkg", "https://api.npmjs.org/downloads/point/last-week/@scope/pkg"])

    def test_404_is_not_found_and_stops_there(self):
        reg, t = registry({NPM: http_error(404)})
        self.assertEqual(reg.facts("npm", "left-pad", "1.0.0"), gr.NotFound())
        self.assertEqual(t.calls, [NPM], "查無此套件就不再查下載量，也不重試")

    def test_server_error_is_unavailable_after_the_retries(self):
        reg, t = registry({NPM: http_error(500)})
        self.assertEqual(reg.facts("npm", "left-pad", None), gr.Unavailable("HTTP 500"))
        self.assertEqual(len(t.calls), 3, "暫時性錯誤重試 retries 次")

    def test_connection_failure_is_unavailable(self):
        reg, _ = registry({NPM: urllib.error.URLError("dns")})
        r = reg.facts("npm", "left-pad", None)
        self.assertIsInstance(r, gr.Unavailable)
        self.assertIn("dns", r.reason)

    def test_download_failures_are_unknown_with_the_error_type(self):
        for body, why in ((http_error(500), "HTTPError"), (urllib.error.URLError("x"), "URLError"), (TimeoutError(), "TimeoutError"),
                          ({}, "ValueError"), ({"downloads": "5000"}, "ValueError"), ({"downloads": None}, "ValueError"), ([], "AttributeError")):
            with self.subTest(why=why, body=repr(body)[:40]):
                reg, _ = registry({NPM: NPM_META, NPM_DL: body})
                f = reg.facts("npm", "left-pad", "1.3.0").facts
                self.assertEqual(f.weekly_downloads, gr.Unknown(why))
                self.assertEqual(f.version, "1.3.0", "下載量查不到不影響存在性與其他資料")

    def test_unexpected_response_shape_is_unavailable_not_an_exception(self):
        for body in ([], ["x"], "not a dict".encode(), {"time": [], "versions": 5}):
            with self.subTest(body=repr(body)[:30]):
                reg, _ = registry({NPM: body, NPM_DL: {"downloads": 1}})
                self.assertIsInstance(reg.facts("npm", "left-pad", None), gr.Unavailable)


class PypiFacts(unittest.TestCase):
    def test_found_is_translated_and_npm_only_fields_are_not_applicable(self):
        reg, t = registry({PYPI: PYPI_META})
        r = reg.facts("pypi", "requests", "2.32.0")
        self.assertEqual(r, gr.Found(gr.Facts("pypi", "requests", "2.32.0", OLD, None, None)))
        self.assertEqual(t.calls, [PYPI], "PyPI 只查一次，沒有週下載量與安裝腳本")

    def test_version_defaults_to_the_current_one_and_pep440_equal_versions_match(self):
        reg, _ = registry({PYPI: PYPI_META})
        self.assertEqual(reg.facts("pypi", "requests", None).facts.version, "2.32.0")
        f = reg.facts("pypi", "requests", "2.32").facts      # ==2.32 與發布的 2.32.0 是同一版（PEP 440）
        self.assertEqual((f.version, f.published_at), ("2.32.0", OLD))

    def test_unpublished_versions_have_unknown_publish_time(self):
        reg, _ = registry({PYPI: PYPI_META})
        for v in ("2.31.9", "2.33.0"):     # 不在發布紀錄／沒有任何檔案
            with self.subTest(v=v):
                f = reg.facts("pypi", "requests", v).facts
                self.assertEqual(f.version, v)
                self.assertIsInstance(f.published_at, gr.Unknown)
        for files in ([None], ["x"], [{}], [{"upload_time_iso_8601": ""}]):
            with self.subTest(files=files):
                reg, _ = registry({PYPI: {"info": {"version": "1.0"}, "releases": {"1.0": files}}})
                self.assertIsInstance(reg.facts("pypi", "requests", "1.0").facts.published_at, gr.Unknown)

    def test_404_and_failures(self):
        self.assertEqual(registry({PYPI: http_error(404)})[0].facts("pypi", "requests", None), gr.NotFound())
        self.assertEqual(registry({PYPI: http_error(503)})[0].facts("pypi", "requests", None), gr.Unavailable("HTTP 503"))
        self.assertIsInstance(registry({PYPI: TimeoutError()})[0].facts("pypi", "requests", None), gr.Unavailable)
        self.assertIsInstance(registry({PYPI: []})[0].facts("pypi", "requests", None), gr.Unavailable)

    def test_name_is_percent_encoded_in_the_url(self):
        reg, t = registry({"https://pypi.org/pypi/Foo_Bar/json": PYPI_META})
        self.assertIsInstance(reg.facts("pypi", "Foo_Bar", "2.32.0"), gr.Found)
        self.assertEqual(t.calls, ["https://pypi.org/pypi/Foo_Bar/json"])


class NeverRaises(unittest.TestCase):
    def test_any_failure_becomes_unavailable(self):
        for exc in (KeyError("bug"), RuntimeError("boom"), ValueError("v"), OSError("o"), http.client.IncompleteRead(b"x"),
                    urllib.error.URLError("u"), TimeoutError()):
            for eco, url, name in (("npm", NPM, "left-pad"), ("pypi", PYPI, "requests")):
                with self.subTest(exc=type(exc).__name__, eco=eco):
                    r = registry({url: exc})[0].facts(eco, name, None)
                    self.assertIsInstance(r, gr.Unavailable)
                    self.assertTrue(r.reason)

    def test_invalid_names_are_never_sent_to_the_registry(self):
        reg, t = registry({})
        for eco, name in (("npm", "../etc/passwd"), ("npm", ""), ("pypi", "a/b"), ("pypi", "-x")):
            self.assertIsInstance(reg.facts(eco, name, None), gr.Unavailable)
        self.assertEqual(t.calls, [])

    def test_unknown_ecosystem_is_unavailable(self):
        self.assertIsInstance(registry({})[0].facts("cargo", "serde", None), gr.Unavailable)


class Requires(unittest.TestCase):
    URL = "https://pypi.org/pypi/requests/2.31.0/json"

    def test_names_are_canonical_and_skip_urls_and_comments(self):
        meta = {"info": {"requires_dist": ["urllib3>=1.21", "charset_normalizer<4,>=2", "PySocks!=1.5.7 ; extra == 'socks'",
                                           "idna[all]>=2.5 ; python_version > '3'", "evil @ https://x.example/e.whl", "# comment"]}}
        reg, _ = registry({self.URL: meta})
        self.assertEqual(reg.requires("requests", "2.31.0"), {"urllib3", "charset-normalizer", "pysocks", "idna"})

    def test_failure_is_an_empty_set(self):
        # 結果只用來把鎖定檔中的間接相依排除在名稱相似度之外：查不到就照直接相依檢查，不會少查
        for body in (http_error(404), http_error(500), TimeoutError(), [], {"info": None}, {"info": {"requires_dist": None}}):
            with self.subTest(body=repr(body)[:30]):
                self.assertEqual(registry({self.URL: body})[0].requires("requests", "2.31.0"), set())

    def test_no_request_without_a_version_or_with_an_invalid_name(self):
        reg, t = registry({})
        self.assertEqual(reg.requires("requests", None), set())
        self.assertEqual(reg.requires("requests", ""), set())
        self.assertEqual(reg.requires("../x", "1.0"), set())
        self.assertEqual(t.calls, [])


class Fake(unittest.TestCase):
    def test_scripted_results_and_calls(self):
        found = gr.Found(gr.Facts("npm", "a", "1.0.0", OLD, {}, 10))
        fake = gr.FakeRegistry({("npm", "a", "1.0.0"): found, ("npm", "b", None): gr.NotFound(), ("pypi", "c", "2"): gr.Unavailable("逾時")},
                               requires={("c", "2"): {"d"}})
        self.assertIs(fake.facts("npm", "a", "1.0.0"), found)
        self.assertEqual(fake.facts("npm", "b", None), gr.NotFound())
        self.assertEqual(fake.facts("pypi", "c", "2"), gr.Unavailable("逾時"))
        self.assertEqual(fake.calls, [("npm", "a", "1.0.0"), ("npm", "b", None), ("pypi", "c", "2")])
        self.assertEqual(fake.requires("c", "2"), {"d"})
        self.assertEqual(fake.requires("x", "1"), set())

    def test_unscripted_lookups_are_unavailable_not_found(self):
        # 沒有腳本的查詢必須是「無法查詢」：不能悄悄變成「查得到、沒有問題」而讓測試或評測誤判為通過
        r = gr.FakeRegistry().facts("npm", "nobody", "1.0.0")
        self.assertIsInstance(r, gr.Unavailable)


if __name__ == "__main__":
    unittest.main()
