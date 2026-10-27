#!/usr/bin/env bash
# How a Vision connection ends, from the LAN application's point of view.
#
# The arbiter for Vision is Xray, so Xray terminates the tunnel here and our
# client dials it; the inner session is a real TLS 1.3 origin with a known
# response length, and the probe is the one from the field report: a raw
# request with `Connection: close`, then a read that waits for the end of the
# TLS stream. A keep-alive probe over one socket is the control.
#
# Two relays record every byte of both directions, one between the probe and
# our client (the inner session) and one between our client and Xray (the
# tunnel). The inner stream a tunnel delivers must be the origin's stream byte
# for byte; `compare` says whether it was, which tells a lost, duplicated or
# injected chunk apart from a vague SSL error at the probe.
#
# Knobs, one variable at a time:
#   ORIGIN_CLOSE=clean     origin ends with close_notify, then FIN (default)
#   ORIGIN_CLOSE=bare-fin  origin ends with FIN and no close_notify
#   LEAK=1                 the tunnel peer writes one more record of its own
#                          behind the Direct stream, which is what a server
#                          without Xray's `SuppressOuterCloseNotify` leaks
#                          (XTLS/Xray-core issue 6794)
#   TLS12=1                inner TLS 1.2, which keeps Vision out of Direct
#   REALITY=1              REALITY instead of an ordinary certificate
#   BIG=<bytes>            ask the origin for a body of this size
#   PROBE=raw|keepalive|half-close
#
# `ORIGIN_CLOSE=bare-fin LEAK=1` is the combination that reproduces the report:
# a complete body, then a record the inner session cannot decrypt. Each knob on
# its own ends cleanly.
set -uo pipefail

OUT="${1:?usage: run.sh <outdir>}"
OUR="${OUR_BIN:?OUR_BIN=<our xrust binary>}"
XRAY="${XRAY_BIN:-xray}"
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
CERTS="$ROOT/tests/golden/certs"

ORIGIN_PORT="${ORIGIN_PORT:-19921}"
ORIGIN_TEE_PORT="${ORIGIN_TEE_PORT:-19922}"
TUNNEL_PORT="${TUNNEL_PORT:-19923}"
TUNNEL_TEE_PORT="${TUNNEL_TEE_PORT:-19924}"
PROXY_PORT="${PROXY_PORT:-19925}"
PROXY_TEE_PORT="${PROXY_TEE_PORT:-19926}"
UUID="${UUID:-b831381d-6324-4d53-ad4f-8cda48b30811}"
SNI="${SNI:-localhost}"
ORIGIN_CLOSE="${ORIGIN_CLOSE:-clean}"
PROBE="${PROBE:-raw}"
BIG="${BIG:-0}"
# A fixed REALITY pair, so the stand needs no key generation step.
REALITY_PRIVATE="${REALITY_PRIVATE:-aB59gTyGXq5aiXIB1IFL2lGYRA2qG1I1AQZuSCU2TGw}"
REALITY_PUBLIC="${REALITY_PUBLIC:-59aZXK9ieKXf2VT5qhIr3zAcFd-v214wwXgTxGflK08}"
SHORT_ID="${SHORT_ID:-0123456789abcdef}"

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
if ! command -v "$XRAY" > /dev/null 2>&1 && [ ! -x "$XRAY" ]; then
    echo "no Xray binary: set XRAY_BIN" >&2
    exit 2
fi

mkdir -p "$OUT"
WORK="$(mktemp -d)"
PIDS=()
cleanup() {
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" 2> /dev/null
    done
    sleep 0.3
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill -9 "$pid" 2> /dev/null
    done
    rm -rf "$WORK"
}
trap cleanup EXIT

wait_port() {
    local port="$1" n=0
    while [ "$n" -lt 150 ]; do
        if ("$PY" -c "import socket,sys; s=socket.socket(); s.settimeout(0.5); sys.exit(s.connect_ex(('127.0.0.1', int(sys.argv[1]))))" "$port") 2> /dev/null; then
            return 0
        fi
        n=$((n + 1))
        sleep 0.1
    done
    echo "port $port never came up" >&2
    return 1
}

# ---------------------------------------------------------------- the origin
cat > "$WORK/origin.py" <<'PY'
"""A TLS origin with a known response length and a chosen way of closing."""
import argparse, socket, ssl, sys, threading

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, required=True)
ap.add_argument("--cert", required=True)
ap.add_argument("--key", required=True)
ap.add_argument("--close", default="clean")
ap.add_argument("--tls12", action="store_true")
args = ap.parse_args()

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
if args.tls12:
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
else:
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(args.cert, args.key)
# REALITY forwards the first flight to its target, which has to offer ALPN
ctx.set_alpn_protocols(["h2", "http/1.1"])


def answer(close, size):
    body = bytes(((i * 31 + 7) & 0xFF) for i in range(size))
    head = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
        b"Content-Length: %d\r\n" % len(body)
    )
    tail = b"Connection: close\r\n\r\n" if close else b"Connection: keep-alive\r\n\r\n"
    return head + tail + body


def serve(conn, tag):
    buf = b""
    while True:
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return
            buf += chunk
        head, buf = buf.split(b"\r\n\r\n", 1)
        first = head.split(b"\r\n", 1)[0]
        size = 792
        if b"?size=" in first:
            size = int(first.split(b"?size=", 1)[1].split(b" ", 1)[0])
        close = b"connection: close" in head.lower()
        out = answer(close, size)
        conn.sendall(out)
        print(f"{tag} answered {len(out)} bytes close={close}", flush=True)
        if not close:
            continue
        if args.close == "clean":
            # close_notify, then the socket: what a correct TLS peer does
            conn.unwrap().close()
        else:
            # FIN with nothing in front of it
            raw = socket.socket(fileno=conn.detach())
            raw.close()
        print(f"{tag} closed close={args.close}", flush=True)
        return


srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", args.port))
srv.listen(16)
print(f"origin ready on {args.port} close={args.close}", flush=True)
n = 0
while True:
    raw, _ = srv.accept()
    n += 1
    tag = f"[origin {n}]"

    def run(raw=raw, tag=tag):
        try:
            conn = ctx.wrap_socket(raw, server_side=True)
        except Exception as exc:
            # REALITY's own probe of the target lands here
            print(f"{tag} handshake failed: {exc!r}", flush=True)
            raw.close()
            return
        try:
            serve(conn, tag)
        except Exception as exc:
            print(f"{tag} error: {exc!r}", flush=True)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    threading.Thread(target=run, daemon=True).start()
PY

# ------------------------------------------------------------ the byte relay
cat > "$WORK/tee.py" <<'PY'
"""A transparent relay that writes every byte of both directions to files."""
import argparse, socket, socketserver, threading


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        n = self.server.next_index()
        up = open(f"{self.server.out}-{n}-up.bin", "wb")
        down = open(f"{self.server.out}-{n}-down.bin", "wb")
        try:
            peer = socket.create_connection(self.server.to)
        except OSError as exc:
            print(f"[tee {n}] dial failed: {exc!r}", flush=True)
            up.close()
            down.close()
            return

        def pump(src, dst, log, append=b""):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        if append:
                            log.write(append)
                            log.flush()
                            dst.sendall(append)
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

        t1 = threading.Thread(target=pump, args=(self.request, peer, up), daemon=True)
        t2 = threading.Thread(
            target=pump,
            args=(peer, self.request, down, self.server.append_down),
            daemon=True,
        )
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        up.close()
        down.close()
        peer.close()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, listen, to, out, append_down):
        super().__init__(listen, Handler)
        self.to = to
        self.out = out
        self.append_down = append_down
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
ap.add_argument("--append-down", default="")
args = ap.parse_args()
host, port = args.to.rsplit(":", 1)
Server(
    ("127.0.0.1", args.port),
    (host, int(port)),
    args.out,
    bytes.fromhex(args.append_down),
).serve_forever()
PY

# ----------------------------------------------------------------- the probe
cat > "$WORK/probe.py" <<'PY'
"""The field report's client: a raw request that waits for the TLS end of
stream, and the keep-alive control. Certificate verification stays on and no
SSL error is swallowed -- the verdict is the result."""
import argparse, http.client, os, socket, ssl, sys

ap = argparse.ArgumentParser()
ap.add_argument("--target", required=True)
ap.add_argument("--via", default=None)
ap.add_argument("--cafile", required=True)
ap.add_argument("--mode", default="raw")
ap.add_argument("--rounds", type=int, default=3)
ap.add_argument("--size", type=int, default=0)
ap.add_argument("--tls12", action="store_true")
args = ap.parse_args()

host, port = args.target.rsplit(":", 1)
port = int(port)
path = "/robots.txt" + (f"?size={args.size}" if args.size else "")
want = args.size or 792


def dial():
    if not args.via:
        return socket.create_connection((host, port), timeout=20)
    vh, vp = args.via.rsplit(":", 1)
    sock = socket.create_connection((vh, int(vp)), timeout=20)
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
if args.tls12:
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
else:
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3

if args.mode == "keepalive":
    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=20)
    conn.sock = ctx.wrap_socket(dial(), server_hostname=host)
    for i in range(args.rounds):
        conn.request("GET", path, headers={"Host": host, "Connection": "keep-alive"})
        resp = conn.getresponse()
        body = resp.read()
        print(f"round {i + 1}: {resp.status} {len(body)} bytes", flush=True)
        if resp.status != 200 or len(body) != want:
            print("FAIL keep-alive round", flush=True)
            sys.exit(4)
    conn.close()
    print("OK keep-alive rounds", flush=True)
    sys.exit(0)

tls = ctx.wrap_socket(dial(), server_hostname=host)
print(f"handshake: {tls.version()} {tls.cipher()[0]}", flush=True)
tls.sendall(
    f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
)
if args.mode == "half-close":
    # SSLSocket.shutdown() would drop the TLS object, so the half-close of the
    # upload goes through a duplicate of the descriptor
    fd = os.dup(tls.fileno())
    dup = socket.socket(fileno=fd)
    dup.shutdown(socket.SHUT_WR)
    dup.detach()
    os.close(fd)

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
complete = length is not None and len(body) == length == want
if error is not None:
    print(f"FAIL tls close: {type(error).__name__}: {error}", flush=True)
    print(f"body complete: {complete}", flush=True)
    sys.exit(2)
if not complete:
    print("FAIL body truncated", flush=True)
    sys.exit(3)
print("OK clean end of stream after a complete body", flush=True)
PY

# --------------------------------------------------------------- the compare
cat > "$WORK/compare.py" <<'PY'
"""Is the inner stream the client received the stream the origin sent?"""
import pathlib, sys

run, index = sys.argv[1], sys.argv[2]
d = pathlib.Path(run)


def strip_connect(data, which):
    if which == "up" and data.startswith(b"CONNECT "):
        cut = data.find(b"\r\n\r\n")
        return data[cut + 4 :] if cut >= 0 else data
    if which == "down" and data.startswith(b"HTTP/"):
        cut = data.find(b"\r\n\r\n")
        return data[cut + 4 :] if cut >= 0 else data
    return data


def records(data):
    out, i = [], 0
    while i + 5 <= len(data):
        ln = int.from_bytes(data[i + 3 : i + 5], "big")
        out.append((i, data[i], ln, i + 5 + ln <= len(data)))
        if i + 5 + ln > len(data):
            break
        i += 5 + ln
    if i < len(data) and (not out or out[-1][3]):
        out.append((i, None, len(data) - i, False))
    return out


ok = True
for label, which in (("download", "down"), ("upload", "up")):
    cp = d / f"inner-{index}-{which}.bin"
    op = d / f"origin-{index}-{which}.bin"
    if not cp.exists() or not op.exists():
        print(f"{label}: no capture")
        ok = False
        continue
    client = strip_connect(cp.read_bytes(), which)
    origin = op.read_bytes()
    sent, got = (origin, client) if label == "download" else (client, origin)
    print(f"{label}: sent {len(sent)}, received {len(got)}")
    for off, kind, ln, whole in records(sent)[-3:]:
        if kind is None:
            print(f"  @{off}: {ln} bytes that are not a record header")
        else:
            note = "" if whole else " (runs past the end)"
            print(f"  @{off}: type=0x{kind:02x} len={ln}{note}")
    n = min(len(sent), len(got))
    first = next((i for i in range(n) if sent[i] != got[i]), n)
    if first < n:
        ok = False
        print(f"  {label}: DIFFERS from offset {first}")
        print(f"    sent     {sent[first : first + 32].hex()}")
        print(f"    received {got[first : first + 32].hex()}")
        continue
    if len(got) > len(sent):
        ok = False
        print(f"  {label}: {len(got) - len(sent)} bytes the sender never sent")
        print(f"    injected {got[len(sent) : len(sent) + 32].hex()}")
        continue
    if len(got) < len(sent):
        # The peer that closed first stops reading, so a trailing write of the
        # other side is legitimately not delivered -- a client's own
        # close_notify behind an origin that ended with a bare FIN, say. Only a
        # gap in the middle, which the prefix check above catches, is a loss.
        print(f"  {label}: a prefix arrived; last {len(sent) - len(got)} bytes")
        print("    were written after the receiver had closed (not delivered)")
        continue
    print(f"  {label}: identical")
print("VERDICT: byte-exact" if ok else "VERDICT: the stream was altered")
sys.exit(0 if ok else 1)
PY

# ---------------------------------------------------------------- the config
if [ "${REALITY:-0}" = "1" ]; then
    SERVER_SECURITY="\"security\": \"reality\",
        \"realitySettings\": {
          \"target\": \"127.0.0.1:$ORIGIN_PORT\",
          \"serverNames\": [\"$SNI\"],
          \"privateKey\": \"$REALITY_PRIVATE\",
          \"shortIds\": [\"$SHORT_ID\"]
        }"
    CLIENT_SECURITY="\"reality\": {\"enabled\": true, \"public_key\": \"$REALITY_PUBLIC\", \"short_id\": \"$SHORT_ID\"},"
else
    SERVER_SECURITY="\"security\": \"tls\",
        \"tlsSettings\": {
          \"alpn\": [\"h2\", \"http/1.1\"],
          \"certificates\": [{\"certificateFile\": \"$CERTS/localhost.crt\", \"keyFile\": \"$CERTS/localhost.key\"}]
        }"
    CLIENT_SECURITY="\"certificate_path\": \"$CERTS/localhost.crt\","
fi

cat > "$WORK/server.json" <<JSON
{
  "log": {"loglevel": "info"},
  "inbounds": [{
    "tag": "vless-in",
    "listen": "127.0.0.1",
    "port": $TUNNEL_PORT,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "$UUID", "flow": "xtls-rprx-vision"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      $SERVER_SECURITY
    }
  }],
  "outbounds": [{
    "tag": "direct",
    "protocol": "freedom",
    "settings": {
      "redirect": "127.0.0.1:$ORIGIN_TEE_PORT",
      "finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]
    }
  }]
}
JSON

cat > "$WORK/client.json" <<JSON
{
  "log": {"level": "debug", "timestamp": true},
  "inbounds": [{
    "type": "mixed",
    "tag": "in",
    "listen": "127.0.0.1",
    "listen_port": $PROXY_PORT
  }],
  "outbounds": [{
    "type": "vless",
    "tag": "out",
    "server": "127.0.0.1",
    "server_port": $TUNNEL_TEE_PORT,
    "uuid": "$UUID",
    "flow": "xtls-rprx-vision",
    "tls": {
      "enabled": true,
      "server_name": "$SNI",
      $CLIENT_SECURITY
      "utls": {"enabled": true, "fingerprint": "${FINGERPRINT:-firefox}"}
    }
  }]
}
JSON

# A record-shaped 24 bytes: the shape of an outer close_notify, which is what a
# peer that does not suppress it writes behind the Direct stream.
LEAK_BYTES=""
if [ "${LEAK:-0}" = "1" ]; then
    LEAK_BYTES="1703030013$("$PY" -c "print('ab' * 19)")"
fi

TLS12_ARG=""
[ "${TLS12:-0}" = "1" ] && TLS12_ARG="--tls12"

# ------------------------------------------------------------------ the stand
"$PY" "$WORK/origin.py" --port "$ORIGIN_PORT" --cert "$CERTS/localhost.crt" \
    --key "$CERTS/localhost.key" --close "$ORIGIN_CLOSE" $TLS12_ARG \
    > "$OUT/origin.log" 2>&1 &
PIDS+=($!)
"$PY" "$WORK/tee.py" --port "$ORIGIN_TEE_PORT" --to "127.0.0.1:$ORIGIN_PORT" \
    --out "$OUT/origin" > "$OUT/tee-origin.log" 2>&1 &
PIDS+=($!)
"$PY" "$WORK/tee.py" --port "$PROXY_TEE_PORT" --to "127.0.0.1:$PROXY_PORT" \
    --out "$OUT/inner" > "$OUT/tee-inner.log" 2>&1 &
PIDS+=($!)
wait_port "$ORIGIN_PORT" || exit 1
wait_port "$ORIGIN_TEE_PORT" || exit 1

"$XRAY" run -c "$WORK/server.json" > "$OUT/server.log" 2>&1 &
PIDS+=($!)
wait_port "$TUNNEL_PORT" || exit 1

"$PY" "$WORK/tee.py" --port "$TUNNEL_TEE_PORT" --to "127.0.0.1:$TUNNEL_PORT" \
    --out "$OUT/tunnel" --append-down "$LEAK_BYTES" > "$OUT/tee-tunnel.log" 2>&1 &
PIDS+=($!)
wait_port "$TUNNEL_TEE_PORT" || exit 1

"$OUR" run -c "$WORK/client.json" > "$OUT/ours.log" 2>&1 &
PIDS+=($!)
wait_port "$PROXY_PORT" || exit 1
wait_port "$PROXY_TEE_PORT" || exit 1

SIZE_ARG=""
[ "$BIG" != "0" ] && SIZE_ARG="--size $BIG"
"$PY" "$WORK/probe.py" --target "$SNI:$ORIGIN_PORT" --via "127.0.0.1:$PROXY_TEE_PORT" \
    --cafile "$CERTS/localhost.crt" --mode "$PROBE" $SIZE_ARG $TLS12_ARG \
    2>&1 | tee "$OUT/probe.log"
rc="${PIPESTATUS[0]}"
sleep 1

echo
"$PY" "$WORK/compare.py" "$OUT" 2 2>&1 | tee "$OUT/compare.log"
cmp_rc="${PIPESTATUS[0]}"
echo
echo "probe rc=$rc  compare rc=$cmp_rc  artifacts in $OUT"
exit "$rc"
