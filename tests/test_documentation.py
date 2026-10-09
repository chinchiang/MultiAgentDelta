"""文件維護回歸測試。 / Documentation maintenance regression tests."""
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import check_documents as docs

TEXT = '''[正體中文（臺灣）](#zh-tw) | [English](#english)
<a id="zh-tw"></a>
# 文件
中文操作說明。
<a id="english"></a>
# Documentation
English operating instructions.
'''


class Documents(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Documentation Test')
        self.git('config', 'user.email', 'docs@example.invalid')

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], text=True).strip()

    def write(self, name, text=TEXT):
        p = self.root/name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        self.git('add', name)

    def baseline(self):
        self.git('commit', '-qm', 'baseline')
        return self.git('rev-parse', 'HEAD')

    def test_structure_requires_real_sections_and_navigation(self):
        self.write('README.md')
        self.assertEqual(docs.check(self.root), ([], 1))
        for text in (TEXT.replace('<a id="english"></a>', ''), TEXT.replace('English operating instructions.', ''),
                     TEXT.replace('](#english)', '](#missing)'), TEXT + '<a id="zh-tw"></a>'):
            with self.subTest(text=text):
                self.write('README.md', text)
                self.assertTrue(docs.check(self.root)[0])

    def test_local_links_fragments_references_and_fences(self):
        self.write('guide file.md', TEXT + '\n## 中文標題\n## Repeat\n## Repeat\n')
        good = TEXT + '\n[guide](<guide%20file.md#中文標題>)\n[repeat][r]\n[r]: guide%20file.md#repeat-1\n```md\n[example](missing.md)\n```\n'
        self.write('README.md', good)
        self.assertFalse(docs.check(self.root)[0])
        for extra in ('\n[bad](gone.md)', '\n[bad](guide%20file.md#absent)', '\n[bad][undefined]', '\n[escape](../outside.md)'):
            self.write('README.md', good + extra)
            self.assertTrue(docs.check(self.root)[0])

    def test_paired_updates_exempt_shared_code_but_not_one_language(self):
        self.write('README.md')
        base = self.baseline()
        self.write('README.md', TEXT.replace('中文操作說明。', '新的中文操作說明。'))
        self.assertTrue(any('Only one language' in e for e in docs.check(self.root, base)[0]))
        self.write('README.md', TEXT.replace('中文操作說明。', '新的中文操作說明。').replace('English operating', 'Updated English operating'))
        self.assertFalse(docs.check(self.root, base)[0])
        self.write('README.md', TEXT + '\n```python\nprint("shared example")\n```\n')
        self.assertFalse(docs.check(self.root, base)[0])

    def test_prompt_content_requires_monotonic_version(self):
        name = 'config/harness/roles/appsec.md'
        original = '---\nprompt_version: appsec@2026-10-09.1\n---\n' + TEXT
        self.write(name, original)
        base = self.baseline()
        changed = original + '\n```json\n{"shared": true}\n```\n'
        self.write(name, changed)
        self.assertTrue(any('increased version' in e for e in docs.check(self.root, base)[0]))
        self.write(name, changed.replace('2026-10-09.1', '2026-10-09.2'))
        self.assertFalse(docs.check(self.root, base)[0])
        self.write(name, changed.replace('2026-10-09.1', '2026-10-08.9'))
        self.assertTrue(docs.check(self.root, base)[0])
        self.write(name, changed.replace('2026-10-09.1', '2026-99-99.1'))
        self.assertTrue(docs.check(self.root, base)[0])

    def test_missing_base_and_empty_repository_are_not_pass(self):
        self.assertTrue(docs.check(self.root)[0])
        self.write('README.md')
        with self.assertRaises(ValueError):
            docs.check(self.root, 'no-such-commit')


if __name__ == '__main__':
    unittest.main()
