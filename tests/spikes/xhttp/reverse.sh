#!/usr/bin/env bash
# A real Xray XHTTP client against our server, packet-up.
#
# Xray's client sends each POST without waiting for the one before it
# (splithttp/dialer.go), so POSTs reach the server out of order and the server
# has to put them back by seq. The probe pushes SIZE bytes through and checks
# that the echo is byte for byte what it sent.
#
# HTTP=h2 is TLS with h2, HTTP=h1 is plain HTTP/1.1, HTTP=h1tls is TLS with
# http/1.1. POST_BYTES and INTERVAL_MS are the client's scMaxEachPostBytes and
# scMinPostsIntervalMs: small values put many POSTs in flight. BUFFERED is our
# server's sc_max_buffered_posts (empty: the default).
#
# Each run is classified:
#   OK              the echo matches byte for byte
#   EXPLICIT-ERROR  the session ended early: what came back is a correct
#                   prefix, the probe saw EOF or a reset before its timeout,
#                   and our server logged why
#   ENDED-UNLOGGED  as above, but our server logged nothing about it
#   STALL           a correct prefix, then nothing until the probe timeout
#   CORRUPT         what came back is not a prefix of what was sent
#
# XRAY_GOGC sets GOGC for the Xray client only, as a diagnostic: GOGC=off
# keeps its pooled upload connections from being closed by the collector.
set -uo pipefail

OUT="${1:?usage: reverse.sh <outdir>}"
OUR="${OUR_BIN:?OUR_BIN=<our tachyon-core binary>}"
XRAY="${XRAY_BIN:-xray}"
HTTP="${HTTP:-h2}"
SERVER_PORT="${SERVER_PORT:-19912}"
ECHO_PORT="${ECHO_PORT:-19911}"
SOCKS_PORT="${SOCKS_PORT:-19913}"
PATH_X="${PATH_X:-/xh}"
UUID="${UUID:-00000000-0000-0000-0000-000000000001}"
SIZE="${SIZE:-8388608}"
PROBE_TIMEOUT="${PROBE_TIMEOUT:-60}"
POST_BYTES="${POST_BYTES:-65536}"
INTERVAL_MS="${INTERVAL_MS:-1}"
BUFFERED="${BUFFERED:-}"
PY="${PYTHON:-python3}"

mkdir -p "$OUT"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
CERTS="$ROOT/tests/golden/certs"
PIN="$(openssl x509 -in "$CERTS/localhost.crt" -outform DER | sha256sum | cut -d' ' -f1)"

cat > "$WORK/echo.py" <<'PY'
import socket, sys, threading
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1])))
srv.listen(8)
def serve(conn):
    with conn:
        while True:
            data = conn.recv(65536)
            if not data:
                return
            conn.sendall(data)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
PY

cat > "$WORK/probe.py" <<'PY'
import random, socket, struct, sys, threading, time
proxy, port, size, wait = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
data = random.Random(1).randbytes(size)
s = socket.create_connection(("127.0.0.1", proxy), timeout=wait)
s.settimeout(wait)
s.sendall(b"\x05\x01\x00")
if s.recv(2) != b"\x05\x00":
    sys.exit("no socks greeting")
s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", port))
reply = s.recv(10)
if len(reply) < 2 or reply[1] != 0:
    sys.exit("socks connect refused: %r" % (reply,))
got = bytearray()
end = {"why": "done"}
def reader():
    try:
        while len(got) < size:
            chunk = s.recv(65536)
            if not chunk:
                end["why"] = "eof"
                return
            got.extend(chunk)
    except socket.timeout:
        end["why"] = "timeout"
    except OSError as e:
        end["why"] = "reset (%s)" % e.__class__.__name__
t = threading.Thread(target=reader)
t.start()
start = time.time()
try:
    s.sendall(data)
except OSError:
    pass  # the session ended under the upload; the reader says how
t.join()
took = time.time() - start
if bytes(got) == data:
    verdict = "OK"
elif not data.startswith(bytes(got)):
    verdict = "CORRUPT"
elif end["why"] == "timeout":
    verdict = "STALL"
else:
    verdict = "ENDED"
print("RESULT %s why=%s SENT %d GOT %d in %.2fs (%.1f Mbit/s)" % (
    verdict, end["why"], size, len(got), took, len(got) * 8 / took / 1e6 if took else 0))
sys.exit(0 if verdict == "OK" else 1)
PY

case "$HTTP" in
    h2)
        OUR_TLS=", \"tls\": {\"enabled\": true, \"certificate_path\": \"$CERTS/localhost.crt\", \"key_path\": \"$CERTS/localhost.key\", \"alpn\": [\"h2\"]}"
        XRAY_SEC="\"security\": \"tls\", \"tlsSettings\": {\"serverName\": \"localhost\", \"pinnedPeerCertSha256\": \"$PIN\", \"alpn\": [\"h2\"]}"
        ;;
    h1tls)
        # HTTP/1.1 path check with a workaround, not browser-profile
        # compatibility. Xray's default uTLS hello (chrome) offers h2 whatever
        # "alpn" says, while the client still speaks HTTP/1.1
        # (splithttp/dialer.go decideHTTPVersion), and our server picks h2 for
        # XHTTP. "unsafe" is Go's own hello, which offers only http/1.1.
        # XRAY_FP=chrome shows the mismatch.
        OUR_TLS=", \"tls\": {\"enabled\": true, \"certificate_path\": \"$CERTS/localhost.crt\", \"key_path\": \"$CERTS/localhost.key\", \"alpn\": [\"http/1.1\"]}"
        XRAY_SEC="\"security\": \"tls\", \"tlsSettings\": {\"serverName\": \"localhost\", \"pinnedPeerCertSha256\": \"$PIN\", \"alpn\": [\"http/1.1\"], \"fingerprint\": \"${XRAY_FP:-unsafe}\"}"
        ;;
    h1)
        OUR_TLS=""
        XRAY_SEC="\"security\": \"none\""
        ;;
    *)
        echo "HTTP must be h2, h1 or h1tls" >&2
        exit 2
        ;;
esac
if [ -n "$BUFFERED" ]; then OUR_BUF=", \"sc_max_buffered_posts\": $BUFFERED"; else OUR_BUF=""; fi

cat > "$WORK/server.json" <<JSON
{
  "log": {"level": "warn"},
  "inbounds": [{
    "type": "vless", "tag": "in", "listen": "127.0.0.1", "listen_port": $SERVER_PORT,
    "users": [{"name": "u", "uuid": "$UUID"}],
    "transport": {"type": "xhttp", "path": "$PATH_X"$OUR_BUF}$OUR_TLS
  }],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"final": "direct"}
}
JSON

cat > "$WORK/client.json" <<JSON
{
  "log": {"loglevel": "warning"},
  "inbounds": [{"listen": "127.0.0.1", "port": $SOCKS_PORT, "protocol": "socks", "settings": {"udp": false}}],
  "outbounds": [{
    "protocol": "vless",
    "settings": {"vnext": [{"address": "127.0.0.1", "port": $SERVER_PORT, "users": [{"id": "$UUID", "encryption": "none"}]}]},
    "streamSettings": {
      "network": "xhttp",
      "xhttpSettings": {"path": "$PATH_X", "mode": "packet-up", "scMaxEachPostBytes": $POST_BYTES, "scMinPostsIntervalMs": $INTERVAL_MS},
      $XRAY_SEC
    }
  }]
}
JSON

"$PY" "$WORK/echo.py" "$ECHO_PORT" > "$OUT/echo.log" 2>&1 &
ECHO=$!
"$OUR" run -c "$WORK/server.json" > "$OUT/server.log" 2>&1 &
SERVER=$!
sleep 1
if [ -n "${XRAY_GOGC:-}" ]; then
    GOGC="$XRAY_GOGC" "$XRAY" run -c "$WORK/client.json" > "$OUT/client.log" 2>&1 &
else
    "$XRAY" run -c "$WORK/client.json" > "$OUT/client.log" 2>&1 &
fi
CLIENT=$!
sleep 2

"$PY" "$WORK/probe.py" "$SOCKS_PORT" "$ECHO_PORT" "$SIZE" "$PROBE_TIMEOUT" > "$OUT/probe.log" 2>&1


kill "$CLIENT" "$SERVER" "$ECHO" 2>/dev/null
wait "$CLIENT" "$SERVER" "$ECHO" 2>/dev/null

cat "$OUT/probe.log"
CLASS="$(sed -n 's/^RESULT \([A-Z-]*\).*/\1/p' "$OUT/probe.log")"
if [ "$CLASS" = "ENDED" ]; then
    if grep -q "ending the session" "$OUT/server.log"; then
        CLASS="EXPLICIT-ERROR"
    else
        CLASS="ENDED-UNLOGGED"
    fi
fi
LABEL="$HTTP"
if [ "$HTTP" = "h1tls" ] && [ "${XRAY_FP:-unsafe}" = "unsafe" ]; then
    LABEL="h1tls, HTTP/1.1 path check with fingerprint=unsafe workaround"
fi
echo "CLASS ${CLASS:-NONE} ($LABEL)"
if [ "$CLASS" = "OK" ]; then
    echo "PASS  Xray's packet-up client ($LABEL) came through our server intact"
    exit 0
fi
echo "FAIL" >&2
for log in client server; do
    echo "--- $log" >&2
    tail -15 "$OUT/$log.log" >&2 2>/dev/null
done
exit 1
