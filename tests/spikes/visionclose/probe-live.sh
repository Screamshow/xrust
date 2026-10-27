#!/usr/bin/env bash
# How a connection through a *running* core ends, seen from the LAN side.
#
# The companion to `run.sh`, for the case where the far end is not a stand but
# a real server: no reference core, no capture on the WAN side, no root. A
# logging relay sits between the probe and the core's inbound, so the inner
# session's bytes are on disk exactly as the core delivered them, and the
# records at the end of that stream say how the session was ended -- which is
# what an `ssl.SSLError` at the probe does not.
#
# Needs an inbound that speaks HTTP CONNECT (`mixed`, `http`): the relay path
# behind it is the same one a redirect or tproxy client takes, a bare client
# socket. Add one temporarily if the core only has tproxy.
#
#   PROXY=127.0.0.1:2080 probe-live.sh <outdir>
#
#   PROXY=host:port   the core's CONNECT inbound (required)
#   TARGET=host:port  default www.youtube.com:443
#   REQ_PATH=/robots.txt
#   PROBE=raw         raw request with `Connection: close`, then read to the
#                     end of the TLS stream (the failing case)
#   PROBE=keepalive   three requests over one socket (the control)
#   REPEAT=1          how many times to run the probe, each on a new connection
#   CAFILE=           a CA file, when the target is not publicly trusted
#
# Certificate verification stays on and no SSL error is swallowed. Nothing on
# the host is changed: the script only listens on a local port and connects.
set -uo pipefail

OUT="${1:?usage: PROXY=host:port probe-live.sh <outdir>}"
PROXY="${PROXY:?PROXY=host:port of the CONNECT inbound}"
TARGET="${TARGET:-www.youtube.com:443}"
REQ_PATH="${REQ_PATH:-/robots.txt}"
PROBE="${PROBE:-raw}"
REPEAT="${REPEAT:-1}"
TEE_PORT="${TEE_PORT:-19931}"

PY="${PYTHON:-}"
if [ -z "$PY" ]; then
    for candidate in python3 python; do
        if command -v "$candidate" > /dev/null 2>&1 && "$candidate" --version > /dev/null 2>&1; then
            PY="$candidate"
            break
        fi
    done
fi
if [ -z "$PY" ]; then
    echo "no working python: set PYTHON=..." >&2
    exit 2
fi

mkdir -p "$OUT"
WORK="$(mktemp -d)"
PIDS=()
cleanup() {
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" 2> /dev/null
    done
    rm -rf "$WORK"
}
trap cleanup EXIT

cat > "$WORK/tee.py" <<'PY'
"""A transparent relay that writes both directions of each connection."""
import argparse, socket, socketserver, threading


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        n = self.server.next_index()
        up = open(f"{self.server.out}-{n}-up.bin", "wb")
        down = open(f"{self.server.out}-{n}-down.bin", "wb")
        try:
            peer = socket.create_connection(self.server.to)
        except OSError as exc:
            print(f"[relay {n}] dial failed: {exc!r}", flush=True)
            up.close()
            down.close()
            return

        def pump(src, dst, log):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    log.write(data)
                    log.flush()
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        threads = [
            threading.Thread(target=pump, args=(self.request, peer, up), daemon=True),
            threading.Thread(target=pump, args=(peer, self.request, down), daemon=True),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        up.close()
        down.close()
        peer.close()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, listen, to, out):
        super().__init__(listen, Handler)
        self.to = to
        self.out = out
        self._n = 0
        self._lock = threading.Lock()

    def next_index(self):
        with self._lock:
            self._n += 1
            return self._n


ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, required=True)
ap.add_argument("--to", required=True)
ap.add_argument("--out", required=True)
args = ap.parse_args()
host, port = args.to.rsplit(":", 1)
print("relay ready", flush=True)
Server(("127.0.0.1", args.port), (host, int(port)), args.out).serve_forever()
PY

cat > "$WORK/probe.py" <<'PY'
"""The failing case and its control, against whatever the proxy reaches."""
import argparse, http.client, socket, ssl, sys

ap = argparse.ArgumentParser()
ap.add_argument("--target", required=True)
ap.add_argument("--via", required=True)
ap.add_argument("--path", required=True)
ap.add_argument("--mode", default="raw")
ap.add_argument("--cafile", default=None)
args = ap.parse_args()

host, port = args.target.rsplit(":", 1)
port = int(port)


def dial():
    vh, vp = args.via.rsplit(":", 1)
    sock = socket.create_connection((vh, int(vp)), timeout=30)
    sock.sendall(
        f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode()
    )
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(1)
        if not chunk:
            raise SystemExit("proxy closed during CONNECT")
        buf += chunk
    line = buf.split(b"\r\n", 1)[0].decode(errors="replace")
    if " 200" not in line:
        raise SystemExit(f"proxy refused: {line}")
    return sock


ctx = ssl.create_default_context(cafile=args.cafile)

if args.mode == "keepalive":
    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=30)
    conn.sock = ctx.wrap_socket(dial(), server_hostname=host)
    for i in range(3):
        conn.request("GET", args.path, headers={"Host": host, "Connection": "keep-alive"})
        resp = conn.getresponse()
        body = resp.read()
        print(f"round {i + 1}: {resp.status}, body {len(body)}", flush=True)
        if resp.status != 200:
            print("FAIL keep-alive round", flush=True)
            sys.exit(4)
    conn.close()
    print("OK keep-alive, three requests over one socket", flush=True)
    sys.exit(0)

tls = ctx.wrap_socket(dial(), server_hostname=host)
print(f"handshake: {tls.version()} {tls.cipher()[0]}", flush=True)
tls.sendall(
    f"GET {args.path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
)
got = b""
error = None
while True:
    try:
        chunk = tls.recv(65536)
    except Exception as exc:
        error = exc
        break
    if not chunk:
        break
    got += chunk

head, _, body = got.partition(b"\r\n\r\n")
status = head.split(b"\r\n", 1)[0].decode(errors="replace") if head else "(none)"
length = None
for line in head.split(b"\r\n")[1:]:
    if line.lower().startswith(b"content-length:"):
        length = int(line.split(b":", 1)[1])
print(f"received {len(got)} bytes; {status}", flush=True)
print(f"content-length {length}, body {len(body)}", flush=True)
if error is not None:
    print(f"FAIL tls close: {type(error).__name__}: {error}", flush=True)
    print(f"body complete: {length is not None and len(body) == length}", flush=True)
    sys.exit(2)
if length is None or len(body) != length:
    print("FAIL body truncated", flush=True)
    sys.exit(3)
print("OK clean end of stream after a complete body", flush=True)
PY

cat > "$WORK/tail.py" <<'PY'
"""The records at the end of the inner stream the core delivered.

Shape alone cannot say who sent the last record: an alert of the inner session
and an alert of the tunnel outer TLS are both a 19-byte application_data record
for a TLS 1.3 AEAD suite. The probe decides. If it failed with a record-layer
error while the body was complete, then that last record is the one that did
not decrypt, so the session did not send it -- and the tunnel delivered a
record of someone else. If the probe was clean, the tail is the session own
close_notify and all is well.
"""
import pathlib, sys

for path in sys.argv[1:]:
    data = pathlib.Path(path).read_bytes()
    if not data:
        continue
    if data.startswith(b"HTTP/"):
        cut = data.find(b"\r\n\r\n")
        if cut >= 0:
            data = data[cut + 4 :]
    print(f"\n{pathlib.Path(path).name}: {len(data)} bytes of inner stream")
    chunks, i = [], 0
    while i + 5 <= len(data):
        ln = int.from_bytes(data[i + 3 : i + 5], "big")
        whole = i + 5 + ln <= len(data)
        chunks.append((i, data[i], data[i + 1 : i + 3].hex(), ln, whole))
        if not whole:
            break
        i += 5 + ln
    trailing = len(data) - i if (not chunks or chunks[-1][4]) else 0
    print(f"  {len(chunks)} record(s); last 4:")
    for off, kind, ver, ln, whole in chunks[-4:]:
        note = "" if whole else "  INCOMPLETE: runs past the end of the stream"
        print(f"    @{off}: type=0x{kind:02x} ver={ver} len={ln}{note}")
    if trailing:
        print(f"  {trailing} trailing byte(s) that are not a record header")
    elif chunks and chunks[-1][4]:
        off, kind, _, ln, _ = chunks[-1]
        alert = "  (the size of an alert under a TLS 1.3 AEAD suite)" if (
            kind == 0x17 and ln == 19
        ) else ""
        print(f"  ends on a record boundary; last type=0x{kind:02x} len={ln}{alert}")
    print(f"  last 32 bytes: {data[-32:].hex()}")
PY

CA_ARG=""
[ -n "${CAFILE:-}" ] && CA_ARG="--cafile $CAFILE"

"$PY" "$WORK/tee.py" --port "$TEE_PORT" --to "$PROXY" --out "$OUT/inner" \
    > "$OUT/relay.log" 2>&1 &
PIDS+=($!)
n=0
while [ "$n" -lt 100 ]; do
    if "$PY" -c "import socket,sys; s=socket.socket(); s.settimeout(0.5); sys.exit(s.connect_ex(('127.0.0.1', $TEE_PORT)))" 2> /dev/null; then
        break
    fi
    n=$((n + 1))
    sleep 0.1
done

rc=0
for round in $(seq 1 "$REPEAT"); do
    echo "===== probe $round / $REPEAT ($PROBE -> $TARGET via $PROXY) ====="
    "$PY" "$WORK/probe.py" --target "$TARGET" --via "127.0.0.1:$TEE_PORT" \
        --path "$REQ_PATH" --mode "$PROBE" $CA_ARG 2>&1 | tee -a "$OUT/probe.log"
    this="${PIPESTATUS[0]}"
    [ "$this" != "0" ] && rc="$this"
    sleep 1
done

echo
"$PY" "$WORK/tail.py" "$OUT"/inner-*-down.bin 2>&1 | tee "$OUT/tail.log"
echo
echo "probe rc=$rc  artifacts in $OUT"
exit "$rc"
