"""Independent Xray traffic matrix. All keys are freshly generated test keys."""
import argparse
import concurrent.futures
import copy
import hashlib
import http.client
import http.server
import itertools
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import threading
import time

SOCKS_HOST = '127.0.0.1'

def exact(s, n):
    out = bytearray()
    while len(out) < n:
        block = s.recv(n - len(out))
        if not block:
            raise RuntimeError(f"EOF after {len(out)}/{n}")
        out.extend(block)
    return bytes(out)


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def socks(p, target, command=1):
    s = socket.create_connection((SOCKS_HOST, p), 5)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(8)
    s.sendall(b'\x05\x01\x00')
    assert exact(s, 2) == b'\x05\x00'
    s.sendall(bytes([5, command, 0, 1, 127, 0, 0, 1]) + target.to_bytes(2, 'big'))
    h = exact(s, 4)
    assert h[1] == 0, h.hex()
    address = exact(s, {1: 4, 4: 16}[h[3]])
    bound = int.from_bytes(exact(s, 2), 'big')
    return s, (socket.inet_ntop(socket.AF_INET if h[3] == 1 else socket.AF_INET6, address), bound)


def echo(c):
    try:
        with c:
            while block := c.recv(65536):
                c.sendall(block)
    except (OSError, ssl.SSLError):
        pass


class Peer:
    def __init__(self, exe, config, directory, label, listen):
        self.exe, self.config, self.directory, self.label, self.listen = exe, config, directory, label, listen
        self.proc = None
        self.logs = []
        try:
            self.start()
        except BaseException:
            self.stop()
            raise

    def start(self):
        path = self.directory / (self.label + '.json')
        path.write_text(json.dumps(self.config))
        log = open(self.directory / (self.label + f'-{len(self.logs)}.log'), 'w')
        self.logs.append(log)
        self.proc = subprocess.Popen([str(self.exe), 'run', '-c', str(path)], stdout=log, stderr=log)
        for _ in range(100):
            if self.proc.poll() is not None:
                raise RuntimeError(self.label + ' exited')
            try:
                with socket.create_connection(('127.0.0.1', self.listen), .1):
                    return
            except OSError:
                time.sleep(.03)
        raise RuntimeError(self.label + ' not ready')

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        for log in self.logs:
            log.flush()


class ArmPeer(Peer):
    ssh = '/mnt/c/Windows/System32/OpenSSH/ssh.exe'
    scp = '/mnt/c/Windows/System32/OpenSSH/scp.exe'
    opts = ['-i', 'C:/Users/Evidence/.ssh/codex_router_key', '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes']
    host = 'root@192.168.90.1'
    root = '/tmp/vless-preflight-20261104'

    @staticmethod
    def windows(path):
        return 'C:/' + str(path).removeprefix('/mnt/c/')

    def start(self):
        path = self.directory / (self.label + '.json')
        self.config['inbounds'][0]['listen'] = '192.168.90.1'
        out = self.config['outbounds'][0]
        if 'tls' in out and 'certificate_path' in out['tls']:
            cert = Path(out['tls']['certificate_path'])
            subprocess.run([self.scp, '-O', *self.opts, self.windows(cert), self.host + ':' + self.root + '/cert.pem'], check=True, capture_output=True)
            out['tls']['certificate_path'] = self.root + '/cert.pem'
        path.write_text(json.dumps(self.config))
        subprocess.run([self.scp, '-O', *self.opts, self.windows(path), self.host + ':' + self.root + '/client.json'], check=True, capture_output=True)
        wsl_ip = subprocess.check_output(['hostname', '-I'], text=True).split()[0]
        remote = out['server_port']
        log = open(self.directory / (self.label + f'-{len(self.logs)}.log'), 'w')
        self.logs.append(log)
        command = f'sh {self.root}/run.sh'
        self.proc = subprocess.Popen([self.ssh, *self.opts, '-o', 'ExitOnForwardFailure=yes', '-R', f'{remote}:{wsl_ip}:{remote}', self.host, command], stdout=log, stderr=log)
        for _ in range(150):
            if self.proc.poll() is not None:
                raise RuntimeError('ARM client exited')
            try:
                with socket.create_connection((SOCKS_HOST, self.listen), .2):
                    return
            except OSError:
                time.sleep(.03)
        raise RuntimeError('ARM client not ready')

    def stop(self):
        # The named test binary is never the production core. Check its exact
        # executable before stopping it; timeout bounds abandoned SSH sessions.
        command = f'for p in /proc/[0-9]*/exe; do e=$(readlink "$p" 2>/dev/null); if [ "$e" = "{self.root}/vless-matrix-arm" ]; then n=${{p#/proc/}}; n=${{n%/exe}}; kill "$n"; fi; done'
        subprocess.run([self.ssh, *self.opts, self.host, command], capture_output=True, timeout=10)
        super().stop()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--xray', type=Path, required=True)
    ap.add_argument('--client', type=Path, required=True)
    ap.add_argument('--work', type=Path, required=True)
    ap.add_argument('--keys', default='x,m,xx,xm,mx,mm,xmx')
    ap.add_argument('--modes', default='tcp,packet-up,stream-up,stream-one')
    ap.add_argument('--appearances', default='native,xorpub,random')
    ap.add_argument('--rtts', default='1rtt,0rtt')
    ap.add_argument('--vision', action='store_true')
    ap.add_argument('--security', choices=['tls', 'reality', 'none'], default='tls')
    ap.add_argument('--packet-encoding', choices=['xudp', 'plain'], default='xudp')
    ap.add_argument('--controls', action='store_true')
    ap.add_argument('--negatives', action='store_true')
    ap.add_argument('--xray-client', action='store_true')
    ap.add_argument('--arm', action='store_true')
    ap.add_argument('--encryption-none', action='store_true')
    ap.add_argument('--reality-pq', action=argparse.BooleanOptionalAction, default=None)
    ap.add_argument('--reality-debug', action='store_true')
    args = ap.parse_args()
    global SOCKS_HOST
    if args.arm:
        SOCKS_HOST = '192.168.90.1'
    os.umask(0o077)
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    xr, client = args.xray.resolve(), args.client.resolve()
    repo = Path(__file__).resolve().parent.parent
    git = ['git.exe', '-C', ArmPeer.windows(repo)] if str(repo).startswith('/mnt/c/') else ['git', '-C', str(repo)]
    metadata = {'source': subprocess.check_output([*git, 'rev-parse', 'HEAD'], text=True).strip(),
                'source_diff_sha256': hashlib.sha256(subprocess.check_output([*git, 'diff', 'HEAD'])).hexdigest(),
                'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'xray': subprocess.check_output([str(xr), 'version'], text=True).strip(),
                'xray_sha256': hashlib.sha256(xr.read_bytes()).hexdigest(),
                'client_sha256': hashlib.sha256(client.read_bytes()).hexdigest(),
                'options': {k: str(v) for k, v in vars(args).items()}}
    (work / 'metadata.json').write_text(json.dumps(metadata, indent=2))
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(work/'key.pem'),
                    '-out', str(work/'cert.pem'), '-days', '2', '-subj', '/CN=localhost', '-addext',
                    'subjectAltName=DNS:localhost', '-addext', 'basicConstraints=critical,CA:FALSE'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if args.arm:
        # Router and peer clocks can differ by a second. Preserve certificate
        # date validation while letting the freshly issued test cert become valid.
        time.sleep(3)
    def key(command):
        return dict(line.split(': ', 1) for line in subprocess.check_output([str(xr), command], text=True).strip().splitlines())
    xkeys = [key('x25519') for _ in range(3)]
    mkeys = [key('mlkem768') for _ in range(3)]
    reality = key('x25519')
    uuid = 'b831381d-6324-4d53-ad4f-8cda48b30811'
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(work/'cert.pem', work/'key.pem')
    context.set_alpn_protocols(['h2', 'http/1.1'])
    def listener(tls=False):
        sock = socket.socket()
        sock.bind(('127.0.0.1', 0)); sock.listen()
        def run():
            while True:
                c, _ = sock.accept()
                c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                def serve(c=c):
                    try:
                        echo(context.wrap_socket(c, server_side=True) if tls else c)
                    except (OSError, ssl.SSLError):
                        c.close()
                threading.Thread(target=serve, daemon=True).start()
        threading.Thread(target=run, daemon=True).start()
        return sock
    sink, tls_sink = listener(), listener(True)
    http_body = b'VLESS Encryption verified HTTPS\n' * 19
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Length', str(len(http_body)))
            self.end_headers()
            self.wfile.write(http_body)

        def log_message(self, *_):
            pass
    https = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    https.socket = context.wrap_socket(https.socket, server_side=True)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind(('127.0.0.1', 0))
    dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); dns.bind(('127.0.0.1', 0))
    counts = {'udp_received': 0, 'dns_received': 0}
    def udp_echo():
        while True:
            data, addr = udp.recvfrom(65535); counts['udp_received'] += 1; udp.sendto(data, addr)
    def dns_answer():
        while True:
            data, addr = dns.recvfrom(65535)
            counts['dns_received'] += 1
            reply = data[:2] + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' + data[12:] + b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x01'
            dns.sendto(reply, addr)
    threading.Thread(target=udp_echo, daemon=True).start()
    threading.Thread(target=dns_answer, daemon=True).start()
    def tcp_check(local, tls=False, size=256*1024+37):
        s, _ = socks(local, (tls_sink if tls else sink).getsockname()[1])
        if tls:
            ctx = ssl.create_default_context(cafile=str(work/'cert.pem'))
            s = ctx.wrap_socket(s, server_hostname='localhost')
        with s:
            payload = os.urandom(size)
            if tls:
                # CPython SSLSocket is not safe for concurrent read/write calls.
                for offset in range(0, len(payload), 4096):
                    block = payload[offset:offset + 4096]
                    s.sendall(block)
                    assert exact(s, len(block)) == block
                return
            with concurrent.futures.ThreadPoolExecutor(1) as pool:
                sent = pool.submit(s.sendall, payload)
                assert exact(s, len(payload)) == payload
                sent.result(timeout=8)
    def udp_check(local):
        if args.arm:
            probe = Path(__file__).with_name('probe_socks_udp.py')
            command = ['/mnt/c/Users/Evidence/AppData/Local/Python/pythoncore-3.14-64/python.exe', ArmPeer.windows(probe),
                       '--host', SOCKS_HOST, '--port', str(local), '--echo-port', str(udp.getsockname()[1]),
                       '--dns-port', str(dns.getsockname()[1]), '--max-size', '4096' if args.vision else '8000']
            completed = subprocess.run(command, capture_output=True, text=True, timeout=25)
            if completed.returncode:
                raise RuntimeError('native UDP probe: ' + completed.stderr[-1500:])
            return
        control, relay = socks(local, 0, 3)
        with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(8)
            for n in ([1, 12, 512, 1200, 2048, 4096] if args.vision or args.xray_client else [1, 12, 512, 1200, 4096, 8000]):
                payload = os.urandom(n)
                header = b'\x00\x00\x00\x01\x7f\x00\x00\x01' + udp.getsockname()[1].to_bytes(2, 'big')
                s.sendto(header + payload, relay)
                try:
                    received, _ = s.recvfrom(65535)
                except TimeoutError as e:
                    raise TimeoutError(f'UDP echo {n} bytes') from e
                assert received[:3] == b'\x00\x00\x00' and received[10:] == payload, f'UDP mismatch {n}'
            query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x04test\x00\x00\x01\x00\x01'
            s.sendto(b'\x00\x00\x00\x01\x7f\x00\x00\x01' + dns.getsockname()[1].to_bytes(2, 'big') + query, relay)
            try:
                received, _ = s.recvfrom(65535)
            except TimeoutError as e:
                raise TimeoutError('UDP DNS response') from e
            assert received[10:12] == b'\x12\x34' and received[-4:] == b'\xc0\x00\x02\x01'
    def https_check(local):
        s, _ = socks(local, https.server_port)
        ctx = ssl.create_default_context(cafile=str(work/'cert.pem'))
        with ctx.wrap_socket(s, server_hostname='localhost') as s:
            s.sendall(b'GET /verified HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
            response = http.client.HTTPResponse(s)
            response.begin()
            assert response.status == 200 and response.read() == http_body
    results = []
    for chain, appearance, rtt, mode in itertools.product(args.keys.split(','), args.appearances.split(','), args.rtts.split(','), args.modes.split(',')):
        label = f'{chain}-{appearance}-{rtt}-{mode}'
        directory = work/label; directory.mkdir()
        remote, local = port(), port()
        public, private = [], []
        for i, kind in enumerate(chain):
            k = (xkeys if kind == 'x' else mkeys)[i]
            public.append(k['Password (PublicKey)'] if kind == 'x' else k['Client'])
            private.append(k['PrivateKey'] if kind == 'x' else k['Seed'])
        stream = {'network': 'tcp', 'security': args.security}
        tls = {'enabled': True, 'server_name': 'localhost', 'certificate_path': str(work/'cert.pem'),
               'alpn': ['h2'] if mode != 'tcp' else ['http/1.1'], 'utls': {'enabled': True, 'fingerprint': 'chrome'}}
        if args.security == 'tls':
            stream['tlsSettings'] = {'alpn': ['h2', 'http/1.1'], 'certificates': [{'certificateFile': str(work/'cert.pem'), 'keyFile': str(work/'key.pem')}]}
        elif args.security == 'reality':
            stream['realitySettings'] = {'show': args.reality_debug, 'dest': f'127.0.0.1:{tls_sink.getsockname()[1]}', 'serverNames': ['localhost'], 'privateKey': reality['PrivateKey'], 'shortIds': ['0123456789abcdef']}
            tls.pop('certificate_path'); tls['reality'] = {'enabled': True, 'public_key': reality['Password (PublicKey)'], 'short_id': '0123456789abcdef'}
            tls['alpn'] = ['h2', 'http/1.1']
            if args.reality_pq is not None:
                tls['reality']['support_x25519mlkem768'] = args.reality_pq
        if mode != 'tcp':
            stream.update(network='xhttp', xhttpSettings={'path': '/test/enc', 'mode': mode})
        user = {'id': uuid}
        if args.vision: user['flow'] = 'xtls-rprx-vision'
        server = {'log': {'loglevel': 'debug'}, 'inbounds': [{'listen': '127.0.0.1', 'port': remote, 'protocol': 'vless', 'settings': {'clients': [user], 'decryption': f'mlkem768x25519plus.{appearance}.600s.' + '.'.join(private)}, 'streamSettings': stream}], 'outbounds': [{'protocol': 'freedom', 'settings': {'finalRules': [{'action': 'allow'}]}}]}
        if args.arm: server['inbounds'][0]['listen'] = '0.0.0.0'
        out = {'type': 'vless', 'tag': 'v', 'server': '127.0.0.1', 'server_port': remote, 'uuid': uuid,
               'encryption': f'mlkem768x25519plus.{appearance}.{rtt}.' + '.'.join(public)}
        if args.encryption_none:
            server['inbounds'][0]['settings']['decryption'] = 'none'
            out['encryption'] = 'none'
        if args.security != 'none': out['tls'] = tls
        if args.vision: out['flow'] = 'xtls-rprx-vision'
        if args.packet_encoding == 'plain': out['packet_encoding'] = ''
        if mode != 'tcp': out['transport'] = {'type': 'xhttp', 'path': '/test/enc', 'mode': mode}
        cc = {'log': {'level': 'debug'}, 'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': local}], 'outbounds': [out], 'route': {'final': 'v'}}
        if args.xray_client:
            cs = copy.deepcopy(stream)
            cs.pop('tlsSettings', None); cs.pop('realitySettings', None)
            if args.security == 'tls': cs['tlsSettings'] = {'serverName': 'localhost', 'fingerprint': 'chrome', 'alpn': tls['alpn'], 'certificates': [{'certificateFile': str(work/'cert.pem'), 'usage': 'verify'}]}
            if args.security == 'reality': cs['realitySettings'] = {'serverName': 'localhost', 'fingerprint': 'chrome', 'password': reality['Password (PublicKey)'], 'shortId': '0123456789abcdef'}
            cu = {'id': uuid, 'encryption': out['encryption']}
            if args.vision: cu['flow'] = out['flow']
            cc = {'log': {'loglevel': 'debug'}, 'inbounds': [{'listen': '127.0.0.1', 'port': local, 'protocol': 'socks', 'settings': {'udp': True}}], 'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{'address': '127.0.0.1', 'port': remote, 'users': [cu]}]}, 'streamSettings': cs}]}
        peers = []
        result = {'case': label, 'checks': [], 'success': False}
        before_counts = counts.copy()
        try:
            peers.append(Peer(xr, server, directory, 'server', remote))
            peers.append((ArmPeer if args.arm else Peer)(xr if args.xray_client else client, cc, directory, 'client', local))
            for _ in range(3):
                tcp_check(local)
                result['checks'].append('tcp-echo')
            tcp_check(local, tls=True, size=1024*1024+37)
            result['checks'].append('verified-inner-tls-1MiB')
            https_check(local); result['checks'].append('verified-https-200-body')
            udp_check(local); result['checks'].append('udp-6-sizes-and-dns')
            with concurrent.futures.ThreadPoolExecutor(4) as pool:
                list(pool.map(lambda _: tcp_check(local, tls=True, size=65536+37), range(4)))
            result['checks'].append('four-concurrent-verified-tls')
            if args.controls and rtt == '0rtt':
                peers[0].stop(); peers[0].start()
                try:
                    tcp_check(local, size=17)
                    raise AssertionError('stale ticket accepted')
                except (OSError, RuntimeError):
                    pass
                tcp_check(local, tls=True, size=65536+37)
                result['checks'].append('restart-ticket-recovery')
            if args.negatives:
                for negative in ['wrong-key', 'wrong-uuid', 'wrong-sni'] + (['reversed-chain'] if len(chain) > 1 else []):
                    if negative == 'wrong-sni' and args.security == 'none':
                        continue
                    peers[1].stop()
                    bad = copy.deepcopy(cc)
                    bout = bad['outbounds'][0]
                    if negative == 'wrong-key':
                        other = key('x25519') if chain[-1] == 'x' else key('mlkem768')
                        replacement = other['Password (PublicKey)'] if chain[-1] == 'x' else other['Client']
                        bout['encryption'] = f'mlkem768x25519plus.{appearance}.{rtt}.' + '.'.join(public[:-1] + [replacement])
                    elif negative == 'wrong-uuid':
                        bout['uuid'] = '11111111-1111-4111-8111-111111111111'
                    elif negative == 'wrong-sni':
                        bout['tls']['server_name'] = 'wrong.example'
                    else:
                        bout['encryption'] = f'mlkem768x25519plus.{appearance}.{rtt}.' + '.'.join(reversed(public))
                    peers[1] = (ArmPeer if args.arm else Peer)(client, bad, directory, negative, local)
                    refused = False
                    try:
                        tcp_check(local, size=17)
                    except (OSError, RuntimeError, AssertionError):
                        refused = True
                    assert refused, negative + ' accepted payload'
                    result['checks'].append(negative + '-rejected')
            result['success'] = True
        except Exception as e:
            result['error'] = f'{type(e).__name__}: {e}'
        finally:
            for peer in reversed(peers): peer.stop()
        result['sink_packets'] = {k: counts[k] - before_counts[k] for k in counts}
        results.append(result)
        (work/'results.json').write_text(json.dumps(results, indent=2))
        print(('PASS ' if result['success'] else 'FAIL ') + label + ' ' + result.get('error', ''), flush=True)
    assert all(r['success'] for r in results), 'matrix failures'


if __name__ == '__main__':
    main()
