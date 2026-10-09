"""獨立審查與突變報告判定。 / Independent review and mutation result classification."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import g4_review
import run_mutations


class ReviewBoundaries(unittest.TestCase):
    def test_approval_requires_current_head_independent_trusted_reviewer(self):
        good = {'user': {'login': 'reviewer'}, 'state': 'APPROVED',
                'commit_id': 'current', 'author_association': 'COLLABORATOR'}
        self.assertEqual(g4_review.trusted_approvers([good], 'author', 'current'), ['reviewer'])
        for field, value in (('commit_id', 'old'), ('user', {'login': 'author'}),
                             ('author_association', 'NONE'), ('state', 'CHANGES_REQUESTED')):
            bad = copy.deepcopy(good); bad[field] = value
            self.assertEqual(g4_review.trusted_approvers([bad], 'author', 'current'), [])
        revoked = dict(good, state='DISMISSED')
        self.assertEqual(g4_review.trusted_approvers([good, revoked], 'author', 'current'), [])

    def test_missing_second_family_is_incomplete(self):
        record = g4_review._example()
        record['providers'][1]['state'] = 'error'
        result = g4_review.evaluate(record, g4_review.load_cfg(), g4_review.known_controls())
        self.assertTrue(result['incomplete'])

    def test_runner_does_not_count_errors_or_missing_tests_as_killed(self):
        base = {'tests': 3, 'skipped': 1, 'errors': 0, 'failures': 0}
        self.assertEqual(run_mutations.classify(base, base), 'survived')
        self.assertEqual(run_mutations.classify(dict(base, failures=1), base), 'killed')
        for result in (dict(base, errors=1), dict(base, tests=0), dict(base, skipped=2)):
            self.assertEqual(run_mutations.classify(result, base), 'invalid')
