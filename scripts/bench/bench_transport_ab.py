#!/usr/bin/env python3
"""Focused Linux transport A/B benchmark; reuses bench_proto_all's fixtures.

Example: --bin baseline=/path/a --bin candidate=/path/b --sing-box /path/sb
--xray /path/xray --only vless-h2-tls,vless-grpc-tls --out results.json
Synthetic loopback measurements, not router/WAN performance. No root required.
"""
import argparse
import asyncio
import base64
import copy
import hashlib
import json
import multiprocessing
import os
import platform
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import bench_proto_all as b


def socks_connect(timeout=12):
    s = socket.create_connection(('127.0.0.1', b.PROXY_PORT), timeout=timeout)
    try:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(bytes([5, 1, 0]))
        if b.recvn(s, 2) != bytes([5, 0]):
            raise RuntimeError('SOCKS auth rejected')
        s.sendall(bytes([5, 1, 0, 1]) + socket.inet_aton(SINK_HOST) + struct.pack('!H', b.SINK_PORT + (3 if INNER_TLS else 0)))
        reply = b.recvn(s, 10)
        if reply[1] != 0:
            raise RuntimeError(f'SOCKS connect status {reply[1]}')
        return TLS_CONTEXT.wrap_socket(s, server_hostname='localhost') if INNER_TLS else s
    except BaseException:
        s.close()
        raise


# A non-loopback local destination also works through WireGuard endpoints.
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
    probe.connect(('192.0.2.1', 9))  # routing lookup only; sends no packet
    SINK_HOST = probe.getsockname()[0]
b.socks_connect = socks_connect
INNER_TLS = False
TLS_CONTEXT = None
SINK_DEBUG = False


def sink(cpus, cert, key):
    os.sched_setaffinity(0, cpus)

    async def handle(r, w):
        try:
            mode = await r.readexactly(1)
            if SINK_DEBUG:
                print('sink mode:', mode.hex(), flush=True)
            if mode == b.MODE_SOURCE:
                chunk = bytes(64 * 1024)
                while True:
                    w.write(chunk)
                    await w.drain()
            elif mode == b.MODE_ECHO:
                while True:
                    w.write(await r.readexactly(64))
                    await w.drain()
                    if SINK_DEBUG:
                        print('sink echoed 64 bytes', flush=True)
            else:
                total = 0
                while chunk := await r.read(64 * 1024):
                    total += len(chunk)
                    if mode == b.MODE_SINK:
                        w.write(struct.pack('!Q', total))
                        await w.drain()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            w.close()

    async def run():
        server = await asyncio.start_server(handle, '0.0.0.0', b.SINK_PORT)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(cert, key)
        secure = await asyncio.start_server(handle, '0.0.0.0', b.SINK_PORT + 3, ssl=ctx)
        async with server, secure:
            await server.serve_forever()
    asyncio.run(run())


def latency(rounds):
    s = b.socks_connect()
    try:
        s.sendall(b.MODE_ECHO)
        data = bytes(64)
        samples = []
        for i in range(rounds + 30):
            start = time.perf_counter_ns()
            s.sendall(data)
            if b.recvn(s, 64) != data:
                raise RuntimeError('corrupted echo')
            if i >= 30:
                samples.append((time.perf_counter_ns() - start) / 1000)
        samples.sort()
        return {f'p{p}_us': round(samples[min(len(samples)-1, int(len(samples)*p/100))], 2)
                for p in (50, 99)}
    finally:
        s.close()


def throughput(direction, streams, seconds, pid):
    sockets = []
    try:
        for _ in range(streams):
            s = b.socks_connect()
            sockets.append(s)
            s.sendall(b.MODE_SOURCE if direction == 'down' else b.MODE_SINK)
        totals, errors = [0] * streams, []
        go, stop = threading.Event(), threading.Event()
        def worker(i, s):
            go.wait()
            try:
                if direction == 'down':
                    s.settimeout(0.3)
                    buf = bytearray(256 * 1024)
                    while not stop.is_set():
                        try:
                            n = s.recv_into(buf)
                        except socket.timeout:
                            continue
                        if not n:
                            raise RuntimeError('premature download EOF')
                        totals[i] += n
                else:
                    s.settimeout(.3)
                    def count_acks():
                        pending = bytearray()
                        try:
                            while not stop.is_set():
                                try:
                                    chunk = s.recv(4096)
                                except socket.timeout:
                                    continue
                                if not chunk:
                                    raise RuntimeError('premature upload EOF')
                                pending.extend(chunk)
                                while len(pending) >= 8:
                                    totals[i], = struct.unpack('!Q', pending[:8])
                                    del pending[:8]
                        except Exception as e:
                            errors.append(str(e))
                    reader = threading.Thread(target=count_acks, daemon=True)
                    reader.start()
                    buf = bytes(64 * 1024)
                    while not stop.is_set():
                        s.sendall(buf)
                    reader.join(2)
                    if reader.is_alive():
                        raise RuntimeError('upload acknowledgement reader stuck')
            except Exception as e:
                errors.append(str(e))
        threads = [threading.Thread(target=worker, args=(i, s), daemon=True)
                   for i, s in enumerate(sockets)]
        for thread in threads:
            thread.start()
        cpu0 = sum(b.cpu_split(pid))
        start = time.perf_counter()
        go.set()
        time.sleep(seconds)
        # Sample the steady transfer window before stopping workers. Joining
        # socket readers can add a timeout tail with no traffic or CPU work.
        # Including that tail biases throughput by up to 0.3/seconds.
        elapsed = time.perf_counter() - start
        got = sum(totals)
        cpu = sum(b.cpu_split(pid)) - cpu0
        stop.set()
        for thread in threads:
            thread.join(10)
        if any(t.is_alive() for t in threads) or errors or not got:
            raise RuntimeError(f'transfer failed: {errors}')
        return {'gbps': round(got*8/elapsed/1e9, 3),
                'cpu_s_per_gib': round(cpu/(got/(1 << 30)), 3),
                'bytes': got, 'elapsed_s': round(elapsed, 3)}
    finally:
        for s in sockets:
            s.close()


def spawn(binary, cfg, cpus, workers, directory, name):
    path = Path(directory) / (name + '.json')
    path.write_text(json.dumps(cfg))
    log = open(Path(directory) / (name + '.log'), 'w')
    env = dict(os.environ, XRUST_WORKERS=str(workers), GOMAXPROCS=str(workers))
    try:
        return subprocess.Popen([binary, 'run', '-c', str(path)], stdout=log, stderr=log,
                                env=env, preexec_fn=lambda: os.sched_setaffinity(0, cpus))
    finally:
        log.close()


def stop_process(proc):
    if proc is not None:
        proc.terminate()
        try:
            proc.wait(3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def wg_pair(awg=False):
    # Public synthetic fixtures, never operator/customer keys.
    def key(byte):
        raw = bytes([byte])*32
        der = bytes.fromhex('302e020100300506032b656e04220420') + raw
        pub = subprocess.check_output(['openssl', 'pkey', '-inform', 'DER', '-pubout',
                                       '-outform', 'DER'], input=der)[-32:]
        return base64.b64encode(raw).decode(), base64.b64encode(pub).decode()
    a, ap = key(0x11)
    z, zp = key(0x22)
    server = {'type': 'wireguard', 'tag': 'wg', 'private_key': z,
              'address': ['10.66.66.1/24'], 'listen_port': b.SERVER_PORT,
              'peers': [{'public_key': ap, 'allowed_ips': ['0.0.0.0/0']}]}
    client = {'type': 'wireguard', 'tag': 'proxy', 'private_key': a,
              'address': ['10.66.66.2/24'], 'peers': [{'address': '127.0.0.1',
              'port': b.SERVER_PORT, 'public_key': zp, 'allowed_ips': ['0.0.0.0/0']}]}
    if awg:
        opts = {'jc': 4, 'jmin': 40, 'jmax': 70, 's1': 20, 's2': 40,
                'h1': 1234567, 'h2': 2345678, 'h3': 3456789, 'h4': 4567890}
        server.update(opts)
        client.update(opts)
    return server, client


def main():
    global INNER_TLS, TLS_CONTEXT, SINK_DEBUG
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bin', action='append', required=True, help='label=absolute binary path')
    ap.add_argument('--sing-box', required=True)
    ap.add_argument('--xray', required=True)
    ap.add_argument('--only', default='vless-tls,vless-tls-vision,vless-ws-tls,vless-grpc-tls,vless-h2-tls,vless-tls-h2mux,vless-xhttp-tls')
    ap.add_argument('--seconds', type=float, default=2)
    ap.add_argument('--rounds', type=int, default=500)
    ap.add_argument('--repeats', type=int, default=3)
    ap.add_argument('--out', required=True)
    ap.add_argument('--inner-tls', action='store_true', help='real TLS 1.3 payload for Vision Direct; download/latency only')
    ap.add_argument('--debug', action='store_true')
    args = ap.parse_args()
    if args.seconds <= 0 or args.rounds < 1 or args.repeats < 1:
        ap.error('seconds, rounds and repeats must be positive')
    binaries = [entry.split('=', 1) for entry in args.bin]
    if any(len(entry) != 2 or not entry[0] for entry in binaries):
        ap.error('--bin must be label=absolute-path')
    for _, path in binaries:
        if not Path(path).is_file():
            ap.error(f'missing binary {path}')
    # Refuse occupied ports before sending any synthetic benchmark traffic.
    for port in (b.SINK_PORT, b.SINK_PORT+3, b.PROXY_PORT, b.SERVER_PORT):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            with socket.socket(socket.AF_INET, kind) as probe:
                if kind == socket.SOCK_STREAM:
                    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind(('0.0.0.0', port))
    available = sorted(os.sched_getaffinity(0))
    if len(available) < 8:
        ap.error('requires 8 available CPUs for client/server/load isolation')
    groups = {}
    for cpu in available:
        topology = Path(f'/sys/devices/system/cpu/cpu{cpu}/topology')
        key = ((topology/'physical_package_id').read_text().strip(),
               (topology/'core_id').read_text().strip())
        groups.setdefault(key, []).append(cpu)
    cores = sorted(groups.values(), key=min)
    if len(cores) < 6:
        ap.error('requires 6 physical cores to exclude SMT siblings from the load')
    client_cpus = {min(cores[0])}
    server_cpus = {min(core) for core in cores[1:5]}
    load_cpus = {cpu for core in cores[5:] for cpu in core}
    os.sched_setaffinity(0, load_cpus)
    out = Path(args.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    result = {'environment': {'kernel': platform.release(), 'client_cpus': sorted(client_cpus),
              'server_cpus': sorted(server_cpus), 'load_cpus': sorted(load_cpus),
              'seconds': args.seconds, 'rounds': args.rounds, 'workers': 1,
              'inner_tls': args.inner_tls,
              'binaries': {label: {'path': path, 'sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest()}
                           for label, path in binaries}}, 'runs': []}
    with tempfile.TemporaryDirectory(prefix='transport-ab-') as directory:
        certs = b.make_certs(directory)
        cases = {case['id']: case for case in b.get_cases(certs)}
        INNER_TLS = args.inner_tls
        SINK_DEBUG = args.debug
        TLS_CONTEXT = ssl.create_default_context(cafile=certs['crt'])
        TLS_CONTEXT.minimum_version = ssl.TLSVersion.TLSv1_3
        sink_proc = multiprocessing.Process(target=sink, args=(load_cpus, certs['crt'], certs['key']), daemon=True)
        for cid in ('vless-reality', 'vless-reality-vision'):
            cases[cid]['server']['tls']['reality']['handshake']['server_port'] = b.SINK_PORT + 3
        # Keep padded mux separate: it exercises a different stream codec.
        cases['vless-tls-h2mux-padding'] = copy.deepcopy(cases['vless-tls-h2mux'])
        cases['vless-tls-h2mux-padding']['client_sb']['multiplex']['padding'] = True
        sink_proc.start()
        try:
            b.wait_listen(b.SINK_PORT)
            for cid in args.only.split(','):
                for repeat in range(args.repeats):
                    # Alternate order to reduce temperature/order bias.
                    for label, binary in binaries[::1 if repeat % 2 == 0 else -1]:
                        row = {'protocol': cid, 'variant': label, 'repeat': repeat}
                        server = client = None
                        try:
                            if cid in ('wireguard', 'amneziawg'):
                                endpoint_s, endpoint_c = wg_pair(cid == 'amneziawg')
                                server = spawn(args.sing_box, {'log': {'level': 'error'},
                                    'endpoints': [endpoint_s], 'outbounds': [{'type': 'direct', 'tag': 'direct'}],
                                    'route': {'final': 'direct'}}, server_cpus, 4, directory, 'wg-server')
                                time.sleep(.3)
                                if server.poll() is not None:
                                    raise RuntimeError('endpoint server startup failed: ' + (Path(directory)/'wg-server.log').read_text()[-1000:])
                                client = spawn(binary, {'log': {'level': 'error'}, 'inbounds': [
                                    {'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': b.PROXY_PORT}],
                                    'endpoints': [endpoint_c], 'route': {'final': 'proxy'}},
                                    client_cpus, 1, directory, 'wg-client')
                                b.wait_listen(b.PROXY_PORT)
                            else:
                                case = cases[cid]
                                if case.get('server_type') == 'xray':
                                    server_cfg = {'log': {'loglevel': 'debug' if args.debug else 'warning'}, 'inbounds': [dict(
                                        case['server_xray'], listen='127.0.0.1', port=b.SERVER_PORT)],
                                        # Recent Xray blocks private destinations by
                                        # default. Permit only this isolated sink.
                                        'outbounds': [{'protocol': 'freedom', 'settings': {
                                            'finalRules': [{'action': 'allow', 'ip': [SINK_HOST + '/32'],
                                                            'port': f'{b.SINK_PORT},{b.SINK_PORT+3}'}]}}]}
                                    server_bin = args.xray
                                else:
                                    server_cfg = {'log': {'level': 'warn'}, 'inbounds': [dict(
                                        case['server'], listen='127.0.0.1', listen_port=b.SERVER_PORT)],
                                        'outbounds': [{'type': 'direct'}]}
                                    server_bin = args.sing_box
                                server = spawn(server_bin, server_cfg, server_cpus, 4, directory, 'server')
                                b.wait_listen(b.SERVER_PORT)
                                if label == 'reference-xray':
                                    client, _ = b.launch_client('xray', binary, case, client_cpus, 1)
                                else:
                                    client = spawn(binary, {'log': {'level': 'debug' if args.debug else 'warn'},
                                    'inbounds': [{'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': b.PROXY_PORT}],
                                    'outbounds': [dict(case['client_sb'], tag='proxy')],
                                    'route': {'final': 'proxy'}}, client_cpus, 1, directory, 'client')
                                b.wait_listen(b.PROXY_PORT)
                            row['idle_rss_mib'] = b.proc_status(client.pid)['VmRSS']
                            row['latency'] = latency(args.rounds)
                            for direction in (('down',) if INNER_TLS else ('down', 'up')):
                                for streams in (1, 8):
                                    row[f'{direction}_{streams}'] = throughput(direction, streams, args.seconds, client.pid)
                            row['peak_rss_mib'] = b.proc_status(client.pid)['VmHWM']
                            holds = []
                            try:
                                for _ in range(32):
                                    s = b.socks_connect()
                                    holds.append(s)
                                    s.sendall(b.MODE_HOLD)
                                time.sleep(.2)
                                row['hold32_rss_mib'] = b.proc_status(client.pid)['VmRSS']
                            finally:
                                for s in holds:
                                    s.close()
                            time.sleep(.3)
                            row['recovery_rss_mib'] = b.proc_status(client.pid)['VmRSS']
                            row['status'] = 'OK'
                        except Exception as e:
                            row.update(status='FAIL', error=str(e))
                            names = ('wg-server', 'wg-client') if cid in ('wireguard', 'amneziawg') else ('server', 'client')
                            for name in names:
                                log = Path(directory) / (name + '.log')
                                if log.exists():
                                    row[name + '_log'] = log.read_text()[-2000:]
                        finally:
                            stop_process(client)
                            stop_process(server)
                            b.wait_port_free(b.PROXY_PORT)
                            b.wait_port_free(b.SERVER_PORT)
                        result['runs'].append(row)
                        out.write_text(json.dumps(result, indent=2))
                        print(json.dumps(row), flush=True)
        finally:
            sink_proc.terminate()
            sink_proc.join(3)


if __name__ == '__main__':
    main()
