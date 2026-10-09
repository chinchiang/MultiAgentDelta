"""無網路容器內的本機轉接器。 / Loopback bridge inside a networkless container."""
import os
import select
import socket
import socketserver
import subprocess
import sys
import threading


class Bridge(socketserver.BaseRequestHandler):
    def handle(self):
        with socket.socket(socket.AF_UNIX) as upstream:
            upstream.connect('/broker/http.sock')
            peers = {self.request: upstream, upstream: self.request}
            while True:
                ready, _, _ = select.select(list(peers), [], [], 110)
                if not ready: return
                for source in ready:
                    chunk = source.recv(65536)
                    if not chunk: return
                    peers[source].sendall(chunk)


if __name__ == '__main__':
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
    with Server(('127.0.0.1', 8080), Bridge) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        # 程序不繼承任何主機憑證；必要的虛擬 SDK 金鑰不是機密。 / No host credentials; SDK placeholders are not secrets.
        result = subprocess.run(sys.argv[1:], env=os.environ.copy())
        server.shutdown()
        raise SystemExit(result.returncode)
