"""離線測試子程序；僅允許回送位址。 / Offline test worker; loopback only."""
import ipaddress
import json
from pathlib import Path
import socket
import sys
import unittest


def main():
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / 'tests'))
    original = socket.socket.connect

    def connect(sock, address):
        if sock.family in (socket.AF_INET, socket.AF_INET6):
            try:
                allowed = ipaddress.ip_address(address[0]).is_loopback
            except ValueError:
                allowed = address[0] == 'localhost'
            if not allowed:
                raise RuntimeError('External network forbidden / 禁止外部網路')
        return original(sock, address)

    socket.socket.connect = connect
    suite = unittest.defaultTestLoader.loadTestsFromName(sys.argv[1])
    result = unittest.TextTestRunner(verbosity=0).run(suite)
    Path(sys.argv[2]).write_text(json.dumps({
        'tests': result.testsRun, 'failures': len(result.failures),
        'errors': len(result.errors), 'skipped': len(result.skipped),
        'failed_tests': [test.id() for test, _ in result.failures],
    }))
    return 0


if __name__ == '__main__':
    sys.exit(main())
