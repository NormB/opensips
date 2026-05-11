#!/usr/bin/env bash
# Negative smoke (positive path): load event_nats with NEITHER
# wrapper module.  Expect OpenSIPS to start and emit the
# "system default" diagnostic log line.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
CFG="$(mktemp /tmp/opensips-none-XXXXXX.cfg)"
LOG="$(mktemp /tmp/opensips-none-XXXXXX.log)"
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

# No nats_tls_* wrapper loaded -- fallback path.
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
