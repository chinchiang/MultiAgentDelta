"""安全邊界回歸：以本機伺服器、壞報告與真實政策重現審查發現。"""
import copy
import json
import pathlib
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import sarif_gate
import g1_kev
import g1_slopcheck
import g4_review
from safe_http import TargetClient


class Reports(unittest.TestCase):
    def test_failed_or_invalid_sarif_never_passes(self):
        good = {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'test'}}, 'results': []}]}
        failed = copy.deepcopy(good)
        failed['runs'][0]['invocations'] = [{'executionSuccessful': False, 'exitCode': 2}]
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / 'scan.sarif'
            invalid_tool = copy.deepcopy(good); invalid_tool["runs"][0]["tool"] = []
            invalid_invocation = copy.deepcopy(good); invalid_invocation["runs"][0]["invocations"] = 1
            for data in (invalid_tool, invalid_invocation, {}, [], {'version': '2.1.0', 'runs': []}, failed):
                p.write_text(json.dumps(data))
                g = sarif_gate.derive('G3', {n: p for n in ('semgrep', 'checkov', 'trivy')}, None, sarif_gate.load_policy())
                self.assertEqual(g['status'], 'incomplete')
            p.write_text(json.dumps(good))
            self.assertEqual(sarif_gate.derive('G3', {}, None, sarif_gate.load_policy())['status'], 'incomplete')

    def test_grype_requires_matches(self):
        with tempfile.TemporaryDirectory() as d:
            p, k = pathlib.Path(d) / 'g.json', pathlib.Path(d) / 'k.json'
            k.write_text(json.dumps({'vulnerabilities': [{'cveID': 'CVE-2021-44228'}]}))
            for data in ({}, [], {'matches': [None]}, {'matches': {}}):
                p.write_text(json.dumps(data))
                self.assertEqual(g1_kev.run(p, k)[0]['status'], 'incomplete')
            p.write_text('{"matches": []}')
            self.assertEqual(g1_kev.run(p, k)[0]['status'], 'pass')

    def test_bad_manifest_cli_is_incomplete(self):
        with tempfile.TemporaryDirectory() as d:
            p, gate = pathlib.Path(d) / 'package.json', pathlib.Path(d) / 'gate.json'
            p.write_text('{ invalid')
            r = subprocess.run([sys.executable, str(ROOT / 'scripts/g1_slopcheck.py'), '--manifest', str(p), '--gate', str(gate)], capture_output=True)
            self.assertEqual(r.returncode, 2)
            self.assertEqual(json.loads(gate.read_text())['status'], 'incomplete')

    def test_all_install_arguments_are_checked(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / 'AGENTS.md'
            p.write_text('pip install -r requirements.txt requests evil-package\nnpm install express @scope/pkg@1.2.3 evil-package\n')
            found = set(g1_slopcheck.rule_file_mentions(p))
            self.assertTrue({('pypi', 'requests', None), ('pypi', 'evil-package', None), ('npm', 'evil-package', None), ('npm', '@scope/pkg', '1.2.3')} <= found)
            self.assertFalse(any(x[1] == 'requirements.txt' for x in found))

    def test_record_cannot_demote_l3_policy(self):
        r = g4_review._example()
        f = r['findings'][0]
        f['policy_tier'] = 'advisory'
        f['ruling_ref'] = f"rulings/{f['id']}.yaml"
        ev = g4_review.evaluate(r, g4_review.load_cfg(), g4_review.known_controls(), ruling_loader=lambda _: g4_review._example_ruling(f['id']))
        self.assertEqual(ev['errors'], [])
        gate = g4_review.derive_gate(g4_review._static(), r, ev, None, 'fixture')
        self.assertEqual(gate['status'], 'fail')
        self.assertEqual(gate['findings_count']['blocking'], 1)


class Redirects(unittest.TestCase):
    def test_cross_origin_never_receives_token(self):
        received = []
        class Sink(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.headers.get('Authorization'))
                self.send_response(200); self.end_headers()
            def log_message(self, *_): pass
        sink = ThreadingHTTPServer(('127.0.0.1', 0), Sink)
        class Source(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/same':
                    location = '/ok'
                elif self.path == '/ok':
                    received.append(self.headers.get('Authorization'))
                    self.send_response(200); self.end_headers(); return
                else:
                    location = f'http://127.0.0.1:{sink.server_port}/capture'
                self.send_response(302); self.send_header('Location', location); self.end_headers()
            def log_message(self, *_): pass
        source = ThreadingHTTPServer(('127.0.0.1', 0), Source)
        for server in (sink, source):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            client = TargetClient(f'http://127.0.0.1:{source.server_port}')
            self.assertIsNone(client.request('/other', token='FAKE_TEST_TOKEN')[0])
            self.assertEqual(received, [])
            self.assertEqual(client.request('/same', token='FAKE_TEST_TOKEN')[0], 200)
            self.assertEqual(received, ['Bearer FAKE_TEST_TOKEN'])
            self.assertIsNone(client.request(f'http://127.0.0.1:{sink.server_port}/', token='FAKE_TEST_TOKEN')[0])
        finally:
            for server in (source, sink): server.shutdown(); server.server_close()

if __name__ == '__main__': unittest.main()
