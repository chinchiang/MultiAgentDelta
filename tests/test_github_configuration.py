"""GitHub 管理驗證的失敗與保留測試。 / Fail-closed and non-destructive administration tests."""
import copy
import pathlib
import sys
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import configure_github as config


def protected():
    result = config.desired_protection()
    for key in ('enforce_admins', 'required_conversation_resolution', 'allow_force_pushes', 'allow_deletions'):
        result[key] = {'enabled': result[key]}
    return result


class Configuration(unittest.TestCase):
    def request(self, current=None, error=None, analyses=None, is_protected=None):
        self.calls = []
        state = {'current': current}
        def call(path, method='GET', body=None):
            self.calls.append((path, method, copy.deepcopy(body)))
            if path == 'repos/o/r': return {'default_branch': 'main'}
            if '/analyses?' in path: return [] if analyses is None else analyses
            if path.endswith('/protection'):
                if error: raise config.ApiError('unavailable', error)
                if method == 'PUT': state['current'] = protected(); return state['current']
                if state['current'] is None: raise config.ApiError('not found', 404)
                return state['current']
            return {'protected': current is not None if is_protected is None else is_protected}
        return call

    def test_admin_denial_still_checks_scanning_without_writes(self):
        report = config.audit('o/r', apply=True, request=self.request(error=403, analyses=[{'id': 1}]))
        self.assertEqual(report['status'], 'incomplete')
        self.assertEqual(report['checks']['code_scanning']['status'], 'pass')
        self.assertTrue(all(method == 'GET' for _, method, _ in self.calls))

    def test_missing_protection_and_empty_scanning_never_pass(self):
        report = config.audit('o/r', request=self.request())
        self.assertEqual(report['checks']['branch_protection']['status'], 'fail')
        self.assertEqual(report['checks']['code_scanning']['status'], 'incomplete')

    def test_create_only_when_explicitly_unprotected_and_verify(self):
        report = config.audit('o/r', apply=True, request=self.request(analyses=[{'id': 1}]))
        self.assertTrue(report['applied'])
        self.assertEqual(report['status'], 'pass')
        writes = [x for x in self.calls if x[1] == 'PUT']
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][2], config.desired_protection())
        report = config.audit('o/r', apply=True, request=self.request(is_protected=True))
        self.assertEqual(report['status'], 'incomplete')
        self.assertTrue(all(method == 'GET' for _, method, _ in self.calls))

    def test_existing_stricter_protection_is_preserved(self):
        current = protected()
        current['required_status_checks']['contexts'].append('Additional check')
        current['required_pull_request_reviews']['required_approving_review_count'] = 2
        report = config.audit('o/r', apply=True, request=self.request(current, analyses=[{'id': 1}]))
        self.assertEqual(report['status'], 'pass')
        self.assertFalse(report['applied'])
        self.assertTrue(all(method == 'GET' for _, method, _ in self.calls))

    def test_existing_gaps_and_bypass_are_reported_without_overwrite(self):
        current = protected()
        current['required_status_checks']['contexts'].remove('VibeSec Summary')
        current['required_pull_request_reviews']['bypass_pull_request_allowances'] = {'users': ['someone']}
        report = config.audit('o/r', apply=True, request=self.request(current, analyses=[{'id': 1}]))
        self.assertEqual(report['status'], 'fail')
        self.assertEqual(len(report['checks']['branch_protection']['gaps']), 2)
        self.assertTrue(all(method == 'GET' for _, method, _ in self.calls))


if __name__ == '__main__': unittest.main()
