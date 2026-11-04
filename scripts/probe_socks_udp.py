"""Native host UDP generator for the independent ARM encryption fixture."""
import argparse
import json
import os
import socket
import test_vless_encryption_matrix as matrix

ap = argparse.ArgumentParser()
ap.add_argument('--host', required=True)
ap.add_argument('--port', type=int, required=True)
ap.add_argument('--echo-port', type=int, required=True)
ap.add_argument('--dns-port', type=int, required=True)
ap.add_argument('--max-size', type=int, default=8000)
args = ap.parse_args()
matrix.SOCKS_HOST = args.host
control, relay = matrix.socks(args.port, 0, 3)
sizes = [1, 12, 512, 1200, 2048 if args.max_size == 4096 else 4096, args.max_size]
with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.settimeout(8)
    for n in sizes:
        payload = os.urandom(n)
        header = b'\x00\x00\x00\x01\x7f\x00\x00\x01' + args.echo_port.to_bytes(2, 'big')
        s.sendto(header + payload, relay)
        received, _ = s.recvfrom(65535)
        assert received[:3] == b'\x00\x00\x00' and received[10:] == payload, f'UDP mismatch {n}'
    query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x04test\x00\x00\x01\x00\x01'
    s.sendto(b'\x00\x00\x00\x01\x7f\x00\x00\x01' + args.dns_port.to_bytes(2, 'big') + query, relay)
    received, _ = s.recvfrom(65535)
    assert received[10:12] == b'\x12\x34' and received[-4:] == b'\xc0\x00\x02\x01'
print(json.dumps({'sizes': sizes, 'dns': True, 'native_host_generator': True}))
