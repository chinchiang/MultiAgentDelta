"""執行期隔離的攻擊與正常路徑測試。 / Runtime isolation attack and positive-path tests."""
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
import isolated_redteam
from runtime_broker import Broker, Server, handler, MAX_BODY


class Response(io.BytesIO):
    code = 200


class RuntimeIsolation(unittest.TestCase):
    def test_stale_output_removed_even_when_image_is_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory);report=output/'g6-promptfoo.json';report.write_text('{}')
            with patch.object(subprocess,'check_output',side_effect=subprocess.CalledProcessError(1,'docker')):
                with self.assertRaises(subprocess.CalledProcessError):
                    isolated_redteam.run('eval','missing','http://target.example',output,env={})
            self.assertFalse(report.exists())

    def test_broker_rejects_redirect_without_contacting_destination(self):
        import http.server
        class Redirect(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                self.send_response(307);self.send_header('Location','http://127.0.0.1:1/secret');self.end_headers()
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Redirect)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            broker=Broker(f'http://127.0.0.1:{server.server_port}')
            self.assertEqual(broker.dispatch('/target/chat',b'{}')[0],502)
        finally:server.shutdown();server.server_close();thread.join()

    def test_only_exact_routes_and_configured_model_are_forwarded(self):
        broker = Broker('https://target.example/base', 'openai', 'approved', 'synthetic-broker-secret')
        with patch.object(broker.opener, 'open', return_value=Response(b'{}')) as request:
            for path in ('http://evil.example/chat', '//evil.example/chat', '/target/../admin',
                         '/target/chat?next=evil', '/provider/v1/files', '/provider/v1/messages'):
                self.assertEqual(broker.dispatch(path, b'{}')[0],403)
            for data in ({'model':'other'}, {'model':'approved','stream':True},
                         {'model':'approved','max_tokens':999999}):
                self.assertIn(broker.dispatch('/provider/v1/chat/completions',json.dumps(data).encode())[0],(400,403))
            request.assert_not_called()
            self.assertEqual(broker.dispatch('/provider/v1/chat/completions',b'{"model":"approved"}')[0],200)
            sent=request.call_args.args[0]
            self.assertEqual(sent.full_url,'https://api.openai.com/v1/chat/completions')
            self.assertEqual(sent.get_header('Authorization'),'Bearer synthetic-broker-secret')
            self.assertEqual(json.loads(sent.data)['max_tokens'],4096)

    def test_request_budget_and_invalid_json_fail_closed(self):
        broker=Broker('http://target.example',max_requests=1)
        with patch.object(broker.opener,'open',return_value=Response(b'{}')) as request:
            for body in (b'[]',b'null',b'bad',b'x'*(MAX_BODY+1)):
                self.assertIn(broker.dispatch('/target/chat',body)[0],(400,413))
            self.assertEqual(broker.dispatch('/target/chat',b'{}')[0],200)
            self.assertEqual(broker.dispatch('/target/chat',b'{}')[0],429)
            self.assertEqual(request.call_count,1)

    def test_multiple_generations_are_rejected_before_request(self):
        broker = Broker('https://target.example', 'openai', 'approved', 'synthetic')
        with patch.object(broker.opener, 'open', return_value=Response(b'{}')) as request:
            self.assertEqual(broker.dispatch('/provider/v1/chat/completions',
                b'{"model":"approved","n":2}')[0], 400)
            request.assert_not_called()

    def test_oversized_response_is_rejected(self):
        broker = Broker('https://target.example')
        with patch.object(broker.opener, 'open', return_value=Response(b'x' * (MAX_BODY + 1))):
            self.assertEqual(broker.dispatch('/target/chat', b'{}')[0], 502)
        with patch.object(broker.opener, 'open', return_value=Response(b'x' * MAX_BODY)):
            self.assertEqual(broker.dispatch('/target/chat', b'{}')[0], 200)

    def test_key_is_not_returned_and_target_gets_no_provider_key(self):
        broker=Broker('https://target.example','anthropic','approved','synthetic-broker-secret')
        with patch.object(broker.opener,'open',return_value=Response(b'synthetic-broker-secret')) as request:
            self.assertEqual(broker.dispatch('/target/chat',b'{}'),(200,b'[REDACTED]'))
            self.assertIsNone(request.call_args.args[0].get_header('X-api-key'))

    def test_docker_command_has_no_host_credentials_or_host_network(self):
        with patch.dict(os.environ,{'AWS_SECRET_ACCESS_KEY':'synthetic-host-secret','GITHUB_TOKEN':'synthetic-gh-secret'}):
            command=isolated_redteam.docker_command('sha256:image',Path('/tmp/i/input'),Path('/tmp/i/out'),Path('/tmp/i/broker'),'eval')
        self.assertEqual(command[command.index('--network')+1],'none')
        self.assertIn('--read-only',command)
        self.assertNotIn('synthetic-host-secret',str(command));self.assertNotIn('synthetic-gh-secret',str(command))
        self.assertNotIn('/var/run/docker.sock',str(command));self.assertNotIn(str(ROOT),str(command))

    def test_provider_data_policy_is_checked_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'config').mkdir()
            (root/'config/providers.yaml').write_text('providers:\n  openai-cloud:\n    enabled: true\n    allowed_data_classes: [public]\n    base_url: https://api.openai.com/v1\n    api_key_env: OPENAI_API_KEY\n    model: test\n')
            with self.assertRaises(ValueError):isolated_redteam.provider_config({'OPENAI_API_KEY':'synthetic'},root)

    def test_custom_endpoint_is_not_silently_replaced_with_cloud(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'config').mkdir()
            (root/'config/providers.yaml').write_text('providers:\n  openai-cloud:\n    enabled: true\n    allowed_data_classes: [internal]\n    base_url: https://private.example/v1\n    api_key_env: OPENAI_API_KEY\n    model: test\n')
            with self.assertRaises(ValueError):isolated_redteam.provider_config({'OPENAI_API_KEY':'synthetic'},root)

    @unittest.skipUnless(os.environ.get('VIBESEC_DOCKER_TEST_IMAGE'), 'Optional real Docker isolation test / 選用的實際 Docker 隔離測試')
    def test_real_networkless_container_can_only_reach_broker(self):
        with tempfile.TemporaryDirectory() as directory:
            temp=Path(directory);temp.chmod(0o755)
            inputs,output,sockets=(temp/x for x in ('input','output','broker'))
            for path in (inputs,output,sockets):
                path.mkdir(mode=0o755);path.chmod(0o755)
            output.chmod(0o777)
            shutil.copyfile(ROOT/'scripts/runtime_bridge.py',inputs/'runtime_bridge.py')
            (inputs/'runtime_bridge.py').chmod(0o644)
            broker=Broker('http://target.example')
            server=Server(str(sockets/'http.sock'),handler(broker));(sockets/'http.sock').chmod(0o666)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            command=isolated_redteam.docker_command(os.environ['VIBESEC_DOCKER_TEST_IMAGE'],inputs,output,sockets,'eval')
            command=command[:command.index('/input/runtime_bridge.py')+1]+['python','-c', '''
import os,socket,urllib.request,urllib.error
assert 'AWS_SECRET_ACCESS_KEY' not in os.environ
assert 'GITHUB_TOKEN' not in os.environ
assert not os.path.exists('/workspace/MultiAgentDelta/.git/config')
assert not os.path.exists('/var/run/docker.sock')
assert urllib.request.urlopen('http://127.0.0.1:8080/health').status==200
try:
 socket.create_connection(('1.1.1.1',443),timeout=1)
except OSError: pass
else: raise AssertionError('Direct network access unexpectedly allowed')
r=urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8080/target/chat',data=b'{}',method='POST'))
assert r.read()==b'{"reply":"ok"}'
try:
 urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8080/provider/v1/files',data=b'{}',method='POST'))
except urllib.error.HTTPError as e: assert e.code==403
else: raise AssertionError('Forbidden route allowed')
print('network/file/credential isolation verified')
''']
            try:
                with patch.object(broker.opener,'open',return_value=Response(b'{"reply":"ok"}')), \
                     patch.dict(os.environ,{'AWS_SECRET_ACCESS_KEY':'synthetic-host-only','GITHUB_TOKEN':'synthetic-host-only'}):
                    result=subprocess.run(command,capture_output=True,text=True,timeout=45)
                self.assertEqual(result.returncode,0,result.stderr)
            finally:
                server.shutdown();server.server_close();thread.join()


if __name__=='__main__':unittest.main()
