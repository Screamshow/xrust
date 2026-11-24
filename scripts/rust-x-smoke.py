"""Local Rust X profile/DirectProxy smoke; uses loopback only."""
import http.server
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

binary = str(Path(sys.argv[1]).resolve())
removed = ['naive', 'vmess', 'shadowsocks', 'tuic', 'anytls',
           'snell', 'shadowtls', 'fptn', 'openvpn', 'openvpn-client']
with tempfile.TemporaryDirectory() as work:
    config = Path(work) / 'config.json'
    for protocol in removed:
        for section in ['inbounds', 'outbounds', 'endpoints']:
            config.write_text(json.dumps({section: [{'type': protocol}]}))
            result = subprocess.run([binary, 'check', '-c', str(config)], capture_output=True)
            assert result.returncode and b'excluded from Rust X' in result.stderr + result.stdout, (protocol, result)
    config.write_text(json.dumps({"outbounds": [{"type": "trojan", "tag": "test", "server": "localhost",
        "server_port": 443, "password": "fixture", "tls": {"enabled": True}}]}))
    subprocess.run([binary, "check", "-c", str(config)], check=True)
    for section in ['inbounds', 'endpoints']:
        config.write_text(json.dumps({section: [{"type": "trojan"}]}))
        assert subprocess.run([binary, "check", "-c", str(config)], capture_output=True).returncode
    config.write_text('{"outbounds":[{"type":"socks"}]}')
    assert subprocess.run([binary, 'check', '-c', str(config)], capture_output=True).returncode
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), http.server.SimpleHTTPRequestHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    config.write_text(json.dumps({'inbounds': [{'type': 'mixed', 'tag': 'direct-proxy-in',
        'listen': '127.0.0.1', 'listen_port': port}], 'outbounds': [{'type': 'direct', 'tag': 'direct-proxy-out'}],
        'route': {'final': 'direct-proxy-out'}}))
    subprocess.run([binary, 'check', '-c', str(config)], check=True)
    with (Path(work) / 'runtime.log').open('w') as log:
        process = subprocess.Popen([binary, 'run', '-c', str(config)], stdout=log, stderr=log)
        try:
            for _ in range(100):
                assert process.poll() is None, 'core exited'
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise AssertionError('mixed inbound did not start')
            curl = ['curl', '--fail', '--silent', '--show-error', '--max-time', '5', '--noproxy', '']
            url = f'http://127.0.0.1:{server.server_port}/'
            subprocess.run(curl + ['--socks5-hostname', f'127.0.0.1:{port}', url], check=True, stdout=subprocess.DEVNULL)
            subprocess.run(curl + ['--proxy', f'http://127.0.0.1:{port}', url], check=True, stdout=subprocess.DEVNULL)
            subprocess.run(curl + ['--socks4', f'127.0.0.1:{port}', url], check=True, stdout=subprocess.DEVNULL)
        finally:
            process.terminate()
            process.wait(timeout=5)
            server.shutdown()
print('PASS: removed protocols rejected; Trojan client accepted; DirectProxy SOCKS4/SOCKS5/HTTP traffic passed')
