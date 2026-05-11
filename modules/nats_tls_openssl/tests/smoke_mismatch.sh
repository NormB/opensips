#!/usr/bin/env bash
# Negative smoke: load BOTH wrappers, verify OpenSIPS refuses at
# config-parse time with the mutual-exclusion LM_ERR.  Expected
# OpenSIPS exit is non-zero; we still report the captured log so
# CI's grep can confirm the right error message fired.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
CFG="$(mktemp /tmp/opensips-mismatch-XXXXXX.cfg)"
LOG="$(mktemp /tmp/opensips-mismatch-XXXXXX.log)"
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

loadmodule "$ROOT/modules/nats_tls_openssl/nats_tls_openssl.so"
loadmodule "$ROOT/modules/nats_tls_wolfssl/nats_tls_wolfssl.so"
loadmodule "$ROOT/modules/event_nats/event_nats.so"

route { sl_send_reply(200, "OK"); exit; }
EOF

# Expect non-zero exit -- mutual-exclusion check should refuse the
# config.  We capture the log either way so the grep in the CI step
# can confirm the right LM_ERR fired.
LD_LIBRARY_PATH="$ROOT/lib/nats:${LD_LIBRARY_PATH:-}" \
    "$ROOT/opensips" -F -f "$CFG" -m 64 -M 4 > "$LOG" 2>&1 || true

cat "$LOG"
