"""閘門整合：授權目標、未實測狀態、ZAP 與可信政策。"""
import contextlib
import copy
import io
import json
import os
import pathlib
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import g4_review
import g5_gate
import g5_api_probes
from gate_verdict import verdict
from access_scenarios import run as access_run


def gate(gid, count=0):
    g = g4_review._static()
    g.update(gate=gid, status='fail' if count else 'pass', status_reason=None)
    g['findings_count']['blocking'] = count
    return g


class GateIntegration(unittest.TestCase):
    def test_trusted_mode_cannot_be_downgraded(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / 'schemas').mkdir(); (root / 'config/policy').mkdir(parents=True)
            (root / 'schemas/gate-result.schema.json').write_bytes((ROOT / 'schemas/gate-result.schema.json').read_bytes())
            (root / 'config/policy/blocking-policy.yaml').write_bytes((ROOT / 'config/policy/blocking-policy.yaml').read_bytes())
            (root / 'vibesec.yaml').write_text('mode: enforce\nrisk_tier: L3\n')
            self.assertEqual(verdict({'G1': gate('G1', 1)}, root, requested='shadow')[0], 1)
            self.assertEqual(verdict({'G1': None}, root)[0], 2)
            self.assertEqual(verdict({'G1': gate('G1')}, root)[0], 0)
            bad = gate('G1'); bad['status'] = 'bogus'
            self.assertEqual(verdict({'G1': bad}, root)[0], 2)

    def test_zap_is_required_and_alerts_are_counted(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / 'zap.json'
            p.write_text(json.dumps({'site': [{'alerts': []}]}))
            paths = {'zap-api': p, 'zap-baseline': p}
            self.assertEqual(g5_gate.merge(gate('G5'), paths)['status'], 'pass')
            self.assertEqual(g5_gate.merge({}, paths)['status'], 'incomplete')
            self.assertEqual(g5_gate.merge(gate('G5'), paths, outcomes={'zap-api': 'failure', 'zap-baseline': 'success'})['status'], 'incomplete')
            self.assertEqual(g5_gate.merge(gate('G5'), {'zap-api': p})['status'], 'incomplete')
            p.write_text(json.dumps({'site': [{'alerts': [{'pluginid': '40012'}]}]}))
            self.assertEqual(g5_gate.merge(gate('G5'), paths)['findings_count']['advisory'], 2)
            p.write_text('{}')
            self.assertEqual(g5_gate.merge(gate('G5'), paths)['status'], 'incomplete')

    def test_all_404_jwt_is_untested(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self): self.send_response(404); self.end_headers(); self.wfile.write(b'{}')
            do_POST = do_GET
            def log_message(self, *_): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        previous = os.getcwd()
        try:
            with tempfile.TemporaryDirectory() as d:
                p = pathlib.Path(d); (p / 'a').write_text('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.fake'); (p / 'b').write_text('fake-b')
                env = {'VIBESEC_CONFIG': str(ROOT / 'vibesec.yaml'), 'VIBESEC_TARGET_URL': f'http://127.0.0.1:{server.server_port}', 'VIBESEC_TOKEN_DIR': d, 'HAS_A': 'true', 'HAS_B': 'true'}
                os.chdir(d)
                with patch.dict(os.environ, env), contextlib.redirect_stdout(io.StringIO()): g5_api_probes.main()
                g = json.loads((p / 'reports/g5-gate.json').read_text())
                coverage = {r['control_id']: r for r in g['coverage']}
                self.assertEqual(coverage['jwt_alg_none']['state'], 'untested')
                self.assertEqual(g['status'], 'incomplete')
        finally:
            os.chdir(previous); server.shutdown(); server.server_close()

    def test_configured_access_checks_writes_and_missing_credentials(self):
        calls = []
        class Client:
            def request(self, path, method, token, data, headers):
                calls.append((method, token))
                if method == 'POST': return 201, '{"id":"owned-1"}'
                return (403, '{}') if token != 'a' else (200, '{"id":"owned-1"}')
        cfg = {'resources': [{'name': 'document', 'id_from': 'create', 'create_request': {'method': 'POST', 'path': '/docs', 'id_json_path': '$.id'}, 'requests': [{'method': m, 'path': '/docs/{id}'} for m in ('GET', 'PUT', 'DELETE')], 'expect': {'A': [200], 'B': [403], 'ANON': [403]}}]}
        found, state, _ = access_run(Client(), cfg, {'A': 'a', 'B': 'b'}, {})
        self.assertEqual((found, state), ([], 'pass'))
        self.assertIn(('DELETE', 'b'), calls)
        self.assertEqual(access_run(Client(), cfg, {'A': 'a'}, {})[1], 'untested')

if __name__ == '__main__': unittest.main()
