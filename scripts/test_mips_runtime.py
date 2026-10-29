#!/usr/bin/env python3
"""Run the actual soft-float client on QEMU 24Kc, using loopback fixtures only."""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def read_exact(sock, count):
    data = b''
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise RuntimeError('short read')
        data += chunk
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--sysroot', required=True)
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    payload = bytes(range(256)) * 1024
    tls_exchanges = []

    class Origin(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *unused):
            pass

    class TlsProxy(socketserver.BaseRequestHandler):
        def handle(self):
            with context.wrap_socket(self.request, server_side=True) as client:
                client.settimeout(30)
                headers = b''
                while b'\r\n\r\n' not in headers:
                    part = client.recv(4096)
                    if not part:
                        return
                    headers += part
                    if len(headers) > 65536:
                        raise RuntimeError('oversized CONNECT')
                request, pending = headers.split(b'\r\n\r\n', 1)
                method, address, _ = request.split(b'\r\n', 1)[0].split(b' ')
                assert method == b'CONNECT'
                host, port = address.decode().rsplit(':', 1)
                assert host == '127.0.0.1' and int(port) == origin.server_port
                tls_exchanges.append(client.cipher()[0])
                with socket.create_connection((host, int(port)), timeout=20) as remote:
                    client.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
                    if pending:
                        remote.sendall(pending)
                    while True:
                        readable, _, _ = select.select([client, remote], [], [], 30)
                        if not readable:
                            return
                        for source in readable:
                            data = source.recv(65536)
                            if not data:
                                return
                            (remote if source is client else client).sendall(data)

    class Dns(socketserver.BaseRequestHandler):
        def handle(self):
            query, sock = self.request
            answer = (query[:2] + b'\x81\x80' + query[4:6] + b'\0\1\0\0\0\0' + query[12:] +
                      b'\xc0\x0c\0\1\0\1\0\0\0\x3c\0\4' + bytes([203, 0, 113, 7]))
            sock.sendto(answer, self.client_address)

    class ProxyServer(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    with tempfile.TemporaryDirectory(prefix='xrust-mips-smoke-') as directory:
        root = Path(directory)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-keyout', str(root / 'key.pem'),
                        '-out', str(root / 'cert.pem')], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / 'cert.pem', root / 'key.pem')
        origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
        proxy = ProxyServer(('127.0.0.1', 0), TlsProxy)
        dns = socketserver.ThreadingUDPServer(('127.0.0.1', 0), Dns)
        servers = [origin, proxy, dns]
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        mixed_port, api_port, dns_port = free_port(), free_port(), free_port()
        config = {
            'log': {'level': 'error'},
            'dns': {'servers': [{'type': 'udp', 'tag': 'dns', 'server': '127.0.0.1',
                                'server_port': dns.server_address[1]}], 'final': 'dns'},
            'inbounds': [
                {'type': 'mixed', 'tag': 'mixed', 'listen': '127.0.0.1', 'listen_port': mixed_port},
                {'type': 'direct', 'tag': 'dns-in', 'listen': '127.0.0.1', 'listen_port': dns_port, 'network': 'udp'},
            ],
            'outbounds': [{'type': 'http', 'tag': 'tls-proxy', 'server': '127.0.0.1',
                           'server_port': proxy.server_address[1],
                           'tls': {'enabled': True, 'server_name': 'localhost', 'insecure': True}}],
            'route': {'rules': [{'inbound': ['dns-in'], 'action': 'hijack-dns'}], 'final': 'tls-proxy'},
            'experimental': {'clash_api': {'external_controller': f'127.0.0.1:{api_port}'}},
        }
        path = root / 'config.json'
        path.write_text(json.dumps(config))
        command = [args.qemu, '-cpu', '24Kc', '-L', args.sysroot, args.binary]
        subprocess.run(command + ['check', '-c', str(path)], check=True)
        with (root / 'runtime.log').open('w+') as log:
            environment = dict(os.environ, XRUST_AF_ALG='off')
            process = subprocess.Popen(command + ['run', '-c', str(path)], stdout=log, stderr=log, env=environment)
            try:
                deadline = time.monotonic() + 30
                while True:
                    if process.poll() is not None:
                        log.seek(0)
                        raise RuntimeError(log.read())
                    try:
                        with socket.create_connection(('127.0.0.1', mixed_port), timeout=1):
                            break
                    except OSError:
                        if time.monotonic() > deadline:
                            raise RuntimeError('MIPS startup timeout')
                        time.sleep(0.1)
                for socks in (False, True):
                    with socket.create_connection(('127.0.0.1', mixed_port), timeout=30) as client:
                        if socks:
                            client.sendall(b'\x05\x01\x00')
                            assert read_exact(client, 2) == b'\x05\x00'
                            client.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', origin.server_port))
                            assert read_exact(client, 10)[:2] == b'\x05\x00'
                        target = '/data' if socks else f'http://127.0.0.1:{origin.server_port}/data'
                        client.sendall(f'GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'.encode())
                        response = b''
                        while True:
                            data = client.recv(65536)
                            if not data:
                                break
                            response += data
                        headers, body = response.split(b'\r\n\r\n', 1)
                        assert b'200' in headers.split(b'\r\n', 1)[0]
                        assert hashlib.sha256(body).digest() == hashlib.sha256(payload).digest()
                        print(f'PASS: MIPS {"SOCKS5" if socks else "HTTP"} -> TLS proxy, {len(body)} bytes')
                name = b'\x04mips\x04test\x00'
                query = b'\x12\x34\x01\x00\x00\x01\0\0\0\0\0\0' + name + b'\0\1\0\1'
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(10)
                    client.sendto(query, ('127.0.0.1', dns_port))
                    answer = client.recv(4096)
                    assert answer[:2] == query[:2] and answer.endswith(bytes([203, 0, 113, 7]))
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(f'http://127.0.0.1:{api_port}/connections', timeout=10) as reply:
                    counters = json.load(reply)
                # SOCKS traffic is registered in Clash; plain HTTP forwarding
                # need not share that accounting path. Check the tracked flow.
                assert counters['downloadTotal'] >= len(payload), counters
                assert len(tls_exchanges) >= 2
                print('PASS: MIPS DNS hijack, Clash API counters and software TLS:', ', '.join(tls_exchanges))
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                for server in servers:
                    server.shutdown()
                    server.server_close()


if __name__ == '__main__':
    main()
