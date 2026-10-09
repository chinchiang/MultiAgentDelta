"""容器外的受限 HTTP 轉接器。 / Restricted HTTP broker outside tool containers."""
import http.server
import json
import socketserver
import threading
import urllib.error
import urllib.request
from safe_http import origin

MAX_BODY = 4 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise urllib.error.URLError('Redirect denied / 拒絕重新導向')


class Broker:
    def __init__(self, target, provider=None, model=None, key=None, max_requests=1000):
        origin(target)
        if '?' in target or '#' in target:
            raise ValueError('Target query/fragment forbidden / 目標不得包含查詢或片段')
        if provider not in (None, 'openai', 'anthropic'):
            raise ValueError('Unknown provider / 未知模型供應商')
        if provider and (not model or not key):
            raise ValueError('Missing provider credentials / 缺少模型憑證')
        self.target, self.provider, self.model, self.key = target.rstrip('/'), provider, model, key
        self.remaining = max_requests
        self.budget_exhausted = False
        self.lock = threading.Lock()
        self.opener = urllib.request.build_opener(NoRedirect())

    def dispatch(self, path, body):
        if len(body) > MAX_BODY:
            return 413, b'{}'
        try:
            data = json.loads(body)
            if not isinstance(data, dict): raise ValueError()
        except (ValueError, UnicodeError):
            return 400, b'{}'
        headers = {'Content-Type': 'application/json'}
        if path == '/target/chat':
            url = self.target + '/chat'
        elif self.provider == 'openai' and path == '/provider/v1/chat/completions':
            url = 'https://api.openai.com/v1/chat/completions'
            headers['Authorization'] = 'Bearer ' + self.key
        elif self.provider == 'anthropic' and path == '/provider/v1/messages':
            url = 'https://api.anthropic.com/v1/messages'
            headers.update({'x-api-key': self.key, 'anthropic-version': '2023-06-01'})
        else:
            return 403, b'{}'
        if path.startswith('/provider/'):
            if data.get('model') != self.model or data.get('stream', False) is not False:
                return 403, b'{}'
            # 限制單次生成；不能靠呼叫參數提高額度。 / Cap generation per request.
            for field in ('max_tokens', 'max_completion_tokens'):
                if field in data and (type(data[field]) is not int or not 1 <= data[field] <= 4096):
                    return 400, b'{}'
            if not any(f in data for f in ('max_tokens', 'max_completion_tokens')):
                data['max_tokens'] = 4096
            if data.get('n', 1) != 1:
                return 400, b'{}'
        with self.lock:
            if self.remaining <= 0:
                self.budget_exhausted = True
                return 429, b'{}'
            self.remaining -= 1
        try:
            request = urllib.request.Request(url, data=json.dumps(data).encode(), headers=headers, method='POST')
            try:
                response = self.opener.open(request, timeout=90)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                status, output = response.code, response.read(MAX_BODY + 1)
            if len(output) > MAX_BODY: return 502, b'{}'
            if self.key: output = output.replace(self.key.encode(), b'[REDACTED]')
            return status, output
        except (OSError, ValueError):
            return 502, b'{}'


def handler(broker):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args): pass

        def do_POST(self):
            self.connection.settimeout(100)
            try:
                lengths = self.headers.get_all('Content-Length') or []
                if len(lengths) != 1 or self.headers.get('Transfer-Encoding'):
                    raise ValueError()
                length = int(lengths[0])
                if not 0 < length <= MAX_BODY: raise ValueError()
                body = self.rfile.read(length)
                if len(body) != length: raise ValueError()
                status, output = broker.dispatch(self.path, body)
            except (ValueError, OSError):
                status, output = 400, b'{}'
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(output)))
            self.end_headers()
            self.wfile.write(output)
    return Handler


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()
