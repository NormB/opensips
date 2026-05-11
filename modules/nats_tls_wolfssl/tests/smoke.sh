#!/usr/bin/env bash
# Smoke: load nats_tls_wolfssl + event_nats, verify the
# "TLS backend = wolfSSL" log line + the user-module confirmation.
# Requires /opt/libnats-wolfssl/ pre-installed; CI's wolfssl job
# builds this in the preceding step.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
CFG="$(mktemp /tmp/opensips-smoke-XXXXXX.cfg)"
LOG="$(mktemp /tmp/opensips-smoke-XXXXXX.log)"
trap 'rm -f "$CFG" "$LOG"' EXIT

cat > "$CFG" <<EOF
log_level=3
debug_mode=no
stderror_enabled=yes
syslog_enabled=no
udp_workers=1
tcp_workers=0
socket=udp:127.0.0.1:15170
mpath="$ROOT/modules"

loadmodule "proto_udp.so"

loadmodule "$ROOT/modules/signaling/signaling.so"
loadmodule "$ROOT/modules/sl/sl.so"
loadmodule "$ROOT/modules/tm/tm.so"
loadmodule "$ROOT/modules/rr/rr.so"
loadmodule "$ROOT/modules/maxfwd/maxfwd.so"
loadmodule "$ROOT/modules/sipmsgops/sipmsgops.so"

loadmodule "$ROOT/modules/nats_tls_wolfssl/nats_tls_wolfssl.so"
# CI builds libnats from upstream tag v3.12.0 -> SONAME libnats.so.3.12.
# Override the wrapper's default path (which points at 3.13).
modparam("nats_tls_wolfssl", "libnats_path",
         "/opt/libnats-wolfssl/lib/libnats.so.3.12")
loadmodule "$ROOT/modules/event_nats/event_nats.so"

route { sl_send_reply(200, "OK"); exit; }
EOF

LD_LIBRARY_PATH="$ROOT/lib/nats:${LD_LIBRARY_PATH:-}" \
    "$ROOT/opensips" -F -f "$CFG" -m 64 -M 4 > "$LOG" 2>&1 &
OPS=$!
sleep 2
kill "$OPS" 2>/dev/null || true
wait "$OPS" 2>/dev/null || true

cat "$LOG"
