#!/usr/bin/env bash
# Smoke: load nats_tls_openssl + event_nats, verify the two
# diagnostic log lines are emitted.  CI's grep checks the output.
#
# This script does NOT need a running nats-server -- event_nats's
# mod_init registers with the pool but only opens connections in
# child_init / first use.  We let OpenSIPS run for 2 seconds, kill
# it, and inspect the captured log.
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

# OpenSIPS 4.x compiles UDP into core, but it still needs a
# proto_udp.so directive to mark the transport as loaded.  The
# .so itself is silently absent from the build tree -- the
# loadmodule line is the trigger, not the .so file.
loadmodule "proto_udp.so"

loadmodule "$ROOT/modules/signaling/signaling.so"
loadmodule "$ROOT/modules/sl/sl.so"
loadmodule "$ROOT/modules/tm/tm.so"
loadmodule "$ROOT/modules/rr/rr.so"
loadmodule "$ROOT/modules/maxfwd/maxfwd.so"
loadmodule "$ROOT/modules/sipmsgops/sipmsgops.so"

loadmodule "$ROOT/modules/nats_tls_openssl/nats_tls_openssl.so"
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
