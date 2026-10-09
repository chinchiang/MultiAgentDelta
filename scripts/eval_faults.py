"""對正式判定程式注入故障；驗證狀態，與漏洞召回率分開計分。"""
import contextlib
import io
import json
import os
import pathlib
import tempfile
import urllib.error
from unittest.mock import patch


def run(case):
    inp = case['input']
    if case['gate'] == 'G1' and inp.get('registry') == 'timeout':
        import g1_slopcheck as s
        with tempfile.TemporaryDirectory() as d, patch.object(s, 'http_json', side_effect=TimeoutError('fixture timeout')):
            p = pathlib.Path(d); (p/'package.json').write_text(json.dumps({'dependencies': {'some-new-pkg': '0.0.1'}}))
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                s.main(['g1_slopcheck.py', '--manifest', str(p/'package.json'), '--gate', str(p/'gate.json')])
            return json.loads((p/'gate.json').read_text())['status']
    if case['gate'] == 'G5':
        import g5_api_probes
        from safe_http import TargetClient
        previous = os.getcwd()
        try:
            with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {'VIBESEC_CONFIG': str(pathlib.Path(__file__).resolve().parents[1]/'vibesec.yaml'), 'VIBESEC_TARGET_URL': 'http://127.0.0.1:1', 'HAS_A': 'false', 'HAS_B': 'false', 'VIBESEC_TOKEN_DIR': ''}), patch.object(TargetClient, 'request', return_value=(405, '{}')), patch.object(TargetClient, 'open', side_effect=urllib.error.URLError('fixture')):
                os.chdir(d)
                with contextlib.redirect_stdout(io.StringIO()): g5_api_probes.main()
                return json.loads(pathlib.Path('reports/g5-gate.json').read_text())['status']
        finally: os.chdir(previous)
    if case['gate'] == 'G6':
        import g6_gate as g
        c = g.Collector(*g.load_catalog())
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d)/'promptfoo.json'
            if inp.get('tool', '').startswith('promptfoo'):
                p.write_text(json.dumps({'results': {'results': [{'success': False, 'failureReason': 1, 'testCase': {'metadata': {'vibesec_rule_id': 'vibesec.g6.stored-xss-via-ai-output'}}}]}}))
                g.ingest_promptfoo_eval(c, str(p), 100)
            g.ingest_promptfoo_redteam(c, None, 'fixture：缺少 provider 金鑰')
            return g.build(c, 'shadow', g.now())[0]['status']
    raise ValueError('沒有對應的故障情境執行器')
