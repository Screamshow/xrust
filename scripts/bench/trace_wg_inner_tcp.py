#!/usr/bin/env python3
"""Bounded TCP-header-only diagnostic on an owned AWG TUN in Linux.

Run inside the peer namespace, before starting the client. This deliberately
adds capture overhead: use a separate diagnostic run, never primary throughput
measurements. Only decoded header metadata is saved; payload bytes are discarded.
"""
# SPDX-License-Identifier: GPL-3.0-only
import argparse
import collections
import json
import os
import signal
import socket
import struct
import time
from pathlib import Path


def tcp_options(raw):
    result = {}
    offset = 0
    while offset < len(raw):
        kind = raw[offset]
        if kind == 0:
            break
        if kind == 1:
            offset += 1
            continue
        if offset + 1 >= len(raw):
            break
        length = raw[offset + 1]
        if length < 2 or offset + length > len(raw):
            break
        if kind == 2 and length == 4:
            result['mss'] = int.from_bytes(raw[offset + 2:offset + 4], 'big')
        elif kind == 3 and length == 3:
            result['window_scale'] = raw[offset + 2]
        elif kind == 4 and length == 2:
            result['sack_permitted'] = True
        elif kind == 5:
            result['sack_blocks'] = (length - 2) // 8
        offset += length
    return result


def capture(args):
    os.sched_setaffinity(0, {args.cpu})
    running = True
    drain_deadline = None

    def stop(*_):
        nonlocal running, drain_deadline
        running = False
        drain_deadline = time.perf_counter() + 1

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    rows = []
    flows = collections.defaultdict(lambda: {'packets': 0, 'payload_bytes_observed': 0,
                                             'max_payload_gap_ms': 0, 'last_payload_t': None})
    start = time.perf_counter()
    start_realtime_ns = time.time_ns()
    with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3)) as sock:
        timestamp_mode = 'userspace-dequeue-monotonic'
        try:
            sock.setsockopt(socket.SOL_SOCKET, 35, 1)  # Linux SO_TIMESTAMPNS on this Linux/WSL fixture.
            timestamp_mode = 'kernel-realtime-anchored-at-start'
        except OSError:
            pass
        try:
            sock.setsockopt(socket.SOL_SOCKET, 33, 8 * 1024 * 1024)  # Linux SO_RCVBUFFORCE, owned socket only.
            buffer_mode = 'SO_RCVBUFFORCE'
        except OSError:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
            buffer_mode = 'SO_RCVBUF-capped-fallback'
        actual_rcvbuf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        sock.bind((args.interface, 0))
        sock.settimeout(.1)
        Path(str(args.output) + '.ready').touch()
        while len(rows) < args.max_packets:
            if running and time.perf_counter() - start >= args.duration:
                stop()
            if not running and time.perf_counter() >= drain_deadline:
                break
            try:
                packet, ancillary, _, _ = sock.recvmsg(96, 64)
            except TimeoutError:
                if not running:
                    break
                continue
            if len(packet) < 40 or packet[0] >> 4 != 4 or packet[9] != 6:
                continue
            ip_header = (packet[0] & 15) * 4
            if len(packet) < ip_header + 20 or int.from_bytes(packet[6:8], 'big') & 0x1fff:
                continue
            tcp_header = (packet[ip_header + 12] >> 4) * 4
            if tcp_header < 20 or len(packet) < ip_header + tcp_header:
                continue
            total = int.from_bytes(packet[2:4], 'big')
            payload = total - ip_header - tcp_header
            if payload < 0:
                continue
            source = socket.inet_ntoa(packet[12:16])
            dest = socket.inet_ntoa(packet[16:20])
            sport, dport, seq, ack, _, flags, window = struct.unpack('!HHIIBBH', packet[ip_header:ip_header + 16])
            t = time.perf_counter() - start
            for level, kind, value in ancillary:
                if level == socket.SOL_SOCKET and kind == 35 and len(value) >= struct.calcsize('@ll'):
                    seconds, nanos = struct.unpack('@ll', value[:struct.calcsize('@ll')])
                    t = (seconds * 1_000_000_000 + nanos - start_realtime_ns) / 1_000_000_000
                    break
            key = f'{source}:{sport}>{dest}:{dport}'
            flow = flows[key]
            if not flow['packets']:
                flow.update(seq_origin=seq, first_t=t)
            flow['packets'] += 1
            if payload:
                if flow['last_payload_t'] is not None:
                    flow['max_payload_gap_ms'] = max(flow['max_payload_gap_ms'], (t - flow['last_payload_t']) * 1000)
                else:
                    flow['first_payload_t'] = t
                flow['last_payload_t'] = t
                flow['payload_bytes_observed'] += payload
            flow['last_t'] = t
            options = tcp_options(packet[ip_header + 20:ip_header + tcp_header])
            if flags & 2:
                flow['syn_options'] = options
            row = dict(t=round(t, 7), flow=key, flags=flags, seq_relative=(seq - flow['seq_origin']) & 0xffffffff,
                       ack=ack, window_raw=window, payload_length=payload)
            if options:
                row['options'] = options
            rows.append(row)
        packets, drops = struct.unpack('II', sock.getsockopt(263, 6, 8))
    args.output.write_text(json.dumps(dict(interface=args.interface, duration=time.perf_counter() - start,
        capture_packets=packets, capture_drops=drops, bounded_packet_limit=args.max_packets,
        socket_buffer_mode=buffer_mode, socket_rcvbuf_actual_bytes=actual_rcvbuf, capture_cpu=args.cpu,
        timestamp_mode=timestamp_mode,
        limit_reached=len(rows) >= args.max_packets, flows=dict(flows), packets=rows,
        note='Header metadata only; no payload saved. Separate diagnostic with capture overhead, not timing/DPI equivalence.'), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--duration', type=float, default=120)
    parser.add_argument('--max-packets', type=int, default=40000)
    parser.add_argument('--cpu', type=int, default=1)
    capture(parser.parse_args())
