"""以真正子程序驗證突變執行器。 / Exercise the mutation runner with real subprocesses."""
import contextlib
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
import run_mutations


class MutationRunner(unittest.TestCase):
    def test_real_mutants_and_original_source_preservation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('scripts', 'tests', 'schemas', 'config', 'docs/templates', 'evals', 'rulings'):
                (root/name).mkdir(parents=True, exist_ok=True)
            (root/'vibesec.yaml').write_text('mode: shadow\n')
            shutil.copyfile(ROOT/'scripts/mutation_worker.py', root/'scripts/mutation_worker.py')
            source = 'def allowed():\n    return True\n'
            (root/'scripts/subject.py').write_text(source)
            (root/'tests/test_subject.py').write_text('''import os, pathlib, sys, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]/'scripts'))
from subject import allowed
class Behavior(unittest.TestCase):
    def test_allowed(self):
        self.assertNotIn('SYNTHETIC_MODEL_KEY', os.environ)
        self.assertTrue(allowed())
''')
            mutations = []
            for name, after in [('killed', 'return False'), ('survived', 'return bool(1)'),
                                ('invalid', 'raise RuntimeError()'), ('timeout', 'while True: pass')]:
                mutations.append({'id': name, 'file': 'scripts/subject.py', 'before': 'return True',
                                  'after': after, 'test': 'test_subject', 'core': True})
            (root/'config/mutations.json').write_text(json.dumps(mutations))
            with patch.object(run_mutations, 'ROOT', root), patch.dict('os.environ', {'SYNTHETIC_MODEL_KEY': 'fake'}), contextlib.redirect_stdout(io.StringIO()):
                report = run_mutations.run('full', 2)
            self.assertEqual(report['status'], 'fail')
            self.assertEqual(report['counts'], {'killed': 1, 'survived': 1, 'invalid': 1, 'timeout': 1})
            self.assertEqual(report['score'], 0.25)
            self.assertEqual((root/'scripts/subject.py').read_text(), source)
            # 原始測試失敗時不得評分。 / Never score mutants against a failed baseline.
            (root/'scripts/subject.py').write_text(source.replace('True', 'False'))
            with patch.object(run_mutations, 'ROOT', root):
                report = run_mutations.run('full', 2)
            self.assertEqual(report['status'], 'incomplete')
            self.assertEqual(report['mutations'], [])
