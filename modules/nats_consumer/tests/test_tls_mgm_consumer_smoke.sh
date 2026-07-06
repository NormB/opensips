#!/bin/bash
#
# Copyright (C) 2026 OpenSIPS Solutions
# SPDX-License-Identifier: GPL-2.0-or-later
#
# test_tls_mgm_consumer_smoke.sh -- end-to-end smoke for nats_consumer
# routed through the v4.0-nats-rc1 tls_mgm pivot.
#
# Boots a TLS-enabled nats-server with JetStream on a private port,
# generates a self-signed CA + server cert + client cert, writes an
# opensips.cfg that loads tls_mgm with the "nats" client_domain +
# event_nats (registers the pool with the tls:// URL) + nats_consumer
# (binds a JetStream pull consumer in startup_route + drains via
# timer_route), publishes a handful of messages with the nats CLI
# over TLS, then polls nats_consumer_list via mi_datagram to assert
# msgs_delivered + acks both reach the seeded count.
#
# This closes the README:531 limitation ("TLS NATS cluster integration
# test is not part of the unit harness") -- the lib/nats smoke pinned
# only the cachedb_nats handshake, not the consumer's JetStream pull
# path.
#
# Skip semantics: exit 77 (autotools convention) on missing
# prerequisites.  Real failures exit 1.
#
# Run:
#   modules/nats_consumer/tests/test_tls_mgm_consumer_smoke.sh

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
TREE_ROOT="$(cd "${HERE}/../../.." && pwd)"

OPENSIPS_BIN="${OPENSIPS_BIN:-${TREE_ROOT}/opensips}"
OPENSIPS_LIB_NATS="${OPENSIPS_LIB_NATS:-${TREE_ROOT}/lib/nats}"
NATS_PORT="${NATS_PORT:-4226}"
OPENSIPS_SIP_PORT="${OPENSIPS_SIP_PORT:-65521}"
MI_PORT="${MI_PORT:-8898}"
WAIT_SECS="${WAIT_SECS:-10}"
N_MESSAGES="${N_MESSAGES:-5}"
STREAM="TLS_CONS_SMOKE"
SUBJECT="tls.cons.smoke"
HANDLE_ID="tls_smoke"
DURABLE="tls_smoke_durable"

WORKDIR="$(mktemp -d -t test_tls_mgm_consumer_smoke.XXXXXX)"
NATS_PID=""
OPENSIPS_PID=""
SUITE_FAIL=0
PASSED=0
FAILED=0

skip() { echo "SKIP: $*"; exit 77; }
fail() { echo "FAIL: $*"; FAILED=$((FAILED+1)); SUITE_FAIL=1; }
pass() { echo "PASS: $*"; PASSED=$((PASSED+1)); }

cleanup() {
    [ -n "$OPENSIPS_PID" ] && kill -TERM "$OPENSIPS_PID" 2>/dev/null
    [ -n "$NATS_PID"     ] && kill -TERM "$NATS_PID"     2>/dev/null
    sleep 0.3
    [ -n "$OPENSIPS_PID" ] && kill -KILL "$OPENSIPS_PID" 2>/dev/null
    [ -n "$NATS_PID"     ] && kill -KILL "$NATS_PID"     2>/dev/null
    wait 2>/dev/null
    if [ "$SUITE_FAIL" -eq 0 ]; then
        rm -rf "$WORKDIR"
    else
        echo
        echo "Workdir preserved for inspection: $WORKDIR"
    fi
}
trap cleanup EXIT

# ──────────────────────────────────────────────────────────────────
# Prerequisite checks (autotools-style skip on absence)
# ──────────────────────────────────────────────────────────────────
need() {
    command -v "$1" >/dev/null 2>&1 || skip "$1 not found in PATH"
}

[ -x "$OPENSIPS_BIN" ] || skip "opensips binary not found at $OPENSIPS_BIN (build it first)"
[ -f "$OPENSIPS_LIB_NATS/libnats_pool.so" ] || skip "libnats_pool.so not built; run 'make -C lib/nats'"
[ -f "$TREE_ROOT/modules/nats_consumer/nats_consumer.so" ] || skip "nats_consumer.so not built"
[ -f "$TREE_ROOT/modules/event_nats/event_nats.so" ] || skip "event_nats.so not built (nats_consumer depends on it for the pool registration)"
[ -f "$TREE_ROOT/modules/tls_mgm/tls_mgm.so" ] || skip "tls_mgm.so not built"

# A libnats built WITHOUT TLS makes the pool fail hard on tls:// URLs
# (no silent plaintext downgrade) -- the case then "fails" for an
# environmental reason.  TLS-built libnats dynamic-links libssl;
# detect via ldd and skip with the reason otherwise.
LIBNATS_PATH="$(ldconfig -p 2>/dev/null | awk '/libnats\.so /{print $NF; exit}')"
if [ -n "${LIBNATS_PATH}" ] && ! ldd "${LIBNATS_PATH}" 2>/dev/null | grep -q libssl; then
    skip "libnats at ${LIBNATS_PATH} was built without TLS (no libssl linkage); rebuild with -DNATS_BUILD_WITH_TLS=ON"
fi
[ -f "$TREE_ROOT/modules/tls_openssl/tls_openssl.so" ] || skip "tls_openssl.so not built"
[ -f "$TREE_ROOT/modules/mi_datagram/mi_datagram.so" ] || skip "mi_datagram.so not built (test polls MI for assertions)"
need openssl
need nats-server
need nats
need nc

if nc -z 127.0.0.1 "$NATS_PORT" 2>/dev/null; then
    skip "test NATS port $NATS_PORT already in use; set NATS_PORT to override"
fi
if nc -uz 127.0.0.1 "$MI_PORT" 2>/dev/null; then
    skip "test MI port $MI_PORT already in use; set MI_PORT to override"
fi

echo "==== test_tls_mgm_consumer_smoke ===="
echo "  workdir:    $WORKDIR"
echo "  nats port:  $NATS_PORT"
echo "  mi port:    $MI_PORT"

# ──────────────────────────────────────────────────────────────────
# CA + server + client cert (3-day validity; throwaway test certs).
# ──────────────────────────────────────────────────────────────────
cd "$WORKDIR" || skip "cd to workdir failed"

cat > openssl.cnf <<'EOF'
[req]
distinguished_name = req_dn
prompt = no
[req_dn]
CN = test-ca
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
[v3_server]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1
[v3_client]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

openssl genrsa -out ca.key 2048 2>/dev/null \
    && openssl req -x509 -new -nodes -key ca.key -days 1 -out ca.crt \
        -subj "/CN=test-ca" -extensions v3_ca -config openssl.cnf 2>/dev/null \
    || { fail "CA generation"; exit 1; }
pass "CA generated"

openssl genrsa -out server.key 2048 2>/dev/null \
    && openssl req -new -key server.key -out server.csr \
        -subj "/CN=localhost" -config openssl.cnf 2>/dev/null \
    && openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
        -CAcreateserial -out server.crt -days 1 \
        -extfile openssl.cnf -extensions v3_server 2>/dev/null \
    || { fail "server cert chain"; exit 1; }
pass "server cert signed by CA"

openssl genrsa -out client.key 2048 2>/dev/null \
    && openssl req -new -key client.key -out client.csr \
        -subj "/CN=opensips-test" -config openssl.cnf 2>/dev/null \
    && openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
        -CAcreateserial -out client.crt -days 1 \
        -extfile openssl.cnf -extensions v3_client 2>/dev/null \
    || { fail "client cert chain"; exit 1; }
pass "client cert signed by CA"

# ──────────────────────────────────────────────────────────────────
# nats-server config: TLS + JetStream (the consumer's whole point).
# ──────────────────────────────────────────────────────────────────
cat > nats-server.conf <<EOF
listen: 127.0.0.1:${NATS_PORT}
http: 127.0.0.1:$((NATS_PORT + 1))

tls {
    cert_file: "${WORKDIR}/server.crt"
    key_file:  "${WORKDIR}/server.key"
    ca_file:   "${WORKDIR}/ca.crt"
    verify:    false
    timeout:   2
}

jetstream {
    store_dir: "${WORKDIR}/jetstream"
}
EOF

nats-server -c nats-server.conf \
    -l "${WORKDIR}/nats-server.log" \
    -P "${WORKDIR}/nats-server.pid" &
NATS_PID=$!

for i in $(seq 1 20); do
    if nc -z 127.0.0.1 "$NATS_PORT" 2>/dev/null; then
        pass "nats-server listening on port $NATS_PORT after ${i}*0.25s"
        break
    fi
    sleep 0.25
done
if ! nc -z 127.0.0.1 "$NATS_PORT" 2>/dev/null; then
    fail "nats-server never started"
    tail -30 "${WORKDIR}/nats-server.log" 2>&1 | sed 's/^/  | /'
    exit 1
fi

# A `nats` CLI context for this test's TLS broker.
# `nats` resolves contexts under $XDG_CONFIG_HOME (or ~/.config) by
# default; override to $WORKDIR so the test does not pollute the
# operator's contexts.
export XDG_CONFIG_HOME="${WORKDIR}/cli-cfg"
mkdir -p "${XDG_CONFIG_HOME}"
nats context add tls-smoke \
    --server "tls://localhost:${NATS_PORT}" \
    --tlscert "${WORKDIR}/client.crt" \
    --tlskey  "${WORKDIR}/client.key" \
    --tlsca   "${WORKDIR}/ca.crt" \
    --select >/dev/null 2>&1 \
    || { fail "nats CLI context add"; exit 1; }
pass "nats CLI context configured for TLS broker"

# Pre-create the JetStream stream the consumer will bind to.  Using
# memory storage keeps the test cheap and avoids leftover state on
# disk between failed runs.
nats stream add "${STREAM}" \
    --subjects "${SUBJECT}" \
    --storage memory \
    --retention limits \
    --max-msgs=-1 \
    --max-bytes=-1 \
    --max-age=1h \
    --replicas 1 \
    --discard old \
    --dupe-window 2m \
    --defaults >/dev/null 2>&1 \
    || { fail "nats stream add"; exit 1; }
pass "JetStream stream ${STREAM} created over TLS"

# ──────────────────────────────────────────────────────────────────
# opensips.cfg: tls_mgm 'nats' domain + event_nats (registers pool) +
# nats_consumer (binds and drains the stream).
# ──────────────────────────────────────────────────────────────────
cat > opensips.cfg <<EOF
log_level=3
xlog_level=3
stderror_enabled=yes
syslog_enabled=no

udp_workers=1
tcp_workers=0

socket=udp:127.0.0.1:${OPENSIPS_SIP_PORT}

loadmodule "proto_udp.so"
loadmodule "${TREE_ROOT}/modules/sipmsgops/sipmsgops.so"
loadmodule "${TREE_ROOT}/modules/signaling/signaling.so"
loadmodule "${TREE_ROOT}/modules/sl/sl.so"
loadmodule "${TREE_ROOT}/modules/maxfwd/maxfwd.so"

# MI surface for assertions.  JSON-RPC over UDP datagram.
loadmodule "${TREE_ROOT}/modules/mi_datagram/mi_datagram.so"
modparam("mi_datagram", "socket_name", "udp:127.0.0.1:${MI_PORT}")

# tls_mgm 'nats' client domain feeds the NATS handshake.  The
# trust path uses ca_list (single PEM) here; the ca_directory
# path is already exercised by lib/nats/tests/test_tls_mgm_smoke.sh.
loadmodule "${TREE_ROOT}/modules/tls_mgm/tls_mgm.so"
modparam("tls_mgm", "client_domain", "nats")
modparam("tls_mgm", "certificate", "[nats]${WORKDIR}/client.crt")
modparam("tls_mgm", "private_key", "[nats]${WORKDIR}/client.key")
modparam("tls_mgm", "ca_list",     "[nats]${WORKDIR}/ca.crt")
modparam("tls_mgm", "verify_cert", "[nats]1")

loadmodule "${TREE_ROOT}/modules/tls_openssl/tls_openssl.so"

# event_nats owns the pool registration with a tls:// URL.
# nats_consumer piggy-backs (it does not call nats_pool_register
# itself; see lib/nats/README.md "Registration contract").
loadmodule "${TREE_ROOT}/modules/event_nats/event_nats.so"
modparam("event_nats", "nats_url", "tls://localhost:${NATS_PORT}")

loadmodule "${TREE_ROOT}/modules/nats_consumer/nats_consumer.so"

startup_route {
    nats_consumer_bind("id=${HANDLE_ID};stream=${STREAM};durable=${DURABLE};filter=${SUBJECT};deliver_policy=all;ack_policy=explicit;ack_wait=30s;max_deliver=5");
}

# 1-second drain timer.  OpenSIPS script has no while-loop primitive,
# so the per-tick drain is unrolled.  N_MESSAGES is small (5 by default);
# bumping the unroll to 32 covers any reasonable test setting without
# stalling the ticker.
timer_route[drain, 1] {
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
    if (nats_fetch("${HANDLE_ID}", 250)) { nats_ack(); }
}

route {
    sl_send_reply(200, "ok");
    exit;
}
EOF

# ──────────────────────────────────────────────────────────────────
# Boot opensips.
# ──────────────────────────────────────────────────────────────────
LD_LIBRARY_PATH="/usr/local/lib:${OPENSIPS_LIB_NATS}:${LD_LIBRARY_PATH:-}" \
    "$OPENSIPS_BIN" -F -i -f "${WORKDIR}/opensips.cfg" \
        > "${WORKDIR}/opensips.log" 2>&1 &
OPENSIPS_PID=$!

# Wait for the consumer process to subscribe -- this is the moment
# at which the stream/durable pair is bound on the broker.
deadline=$((SECONDS + WAIT_SECS))
got_bound=0
got_subscribed=0
while [ "$SECONDS" -lt "$deadline" ]; do
    if [ -s "${WORKDIR}/opensips.log" ]; then
        grep -q "NATS pool: connected to" "${WORKDIR}/opensips.log" \
            && got_bound=1
        # nats_consumer logs "subscribed handle '<id>' to stream '<s>'"
        # on success; fall back to a looser match if the exact text
        # drifts.
        grep -Eq "subscribed.*${HANDLE_ID}|js_PullSubscribe.*ok|consumer.*subscribed" \
            "${WORKDIR}/opensips.log" \
            && got_subscribed=1
    fi
    [ "$got_bound" = 1 ] && [ "$got_subscribed" = 1 ] && break
    sleep 0.25
done

[ "$got_bound" = 1 ] \
    && pass "NATS pool connected to broker over TLS" \
    || fail "'NATS pool: connected to' log line never appeared"

# subscribed is a softer assertion -- log wording is implementation
# detail.  Treat absence as informational, not a hard fail, as long
# as msgs_delivered later proves drain.
if [ "$got_subscribed" = 1 ]; then
    pass "consumer process reports subscribed handle"
else
    echo "INFO: subscribed log line not seen; relying on MI assertion below"
fi

# Confirm opensips survived startup.
if ! kill -0 "$OPENSIPS_PID" 2>/dev/null; then
    fail "opensips exited prematurely during init"
    tail -40 "${WORKDIR}/opensips.log" 2>&1 | sed 's/^/  | /'
    exit 1
fi
pass "opensips still running after init"

# ──────────────────────────────────────────────────────────────────
# Publish messages over TLS and assert delivery via MI.
# ──────────────────────────────────────────────────────────────────
for i in $(seq 1 "$N_MESSAGES"); do
    nats pub "${SUBJECT}" "tls-smoke-${i}" >/dev/null 2>&1 \
        || { fail "nats pub message ${i}"; exit 1; }
done
pass "${N_MESSAGES} messages published over TLS"

# Poll nats_consumer_list until msgs_delivered + acks both >= N.
# The drain timer fires once per second, so the worst case is
# ~N seconds + JetStream propagation.
deadline=$((SECONDS + 15))
msgs_delivered=0
acks=0
while [ "$SECONDS" -lt "$deadline" ]; do
    reply="$(printf '{"jsonrpc":"2.0","id":1,"method":"nats_consumer:nats_consumer_list"}' \
        | nc -u -w 2 127.0.0.1 "$MI_PORT" 2>/dev/null)"
    if [ -n "$reply" ]; then
        # The reply is a JSON-RPC envelope wrapping an array of
        # handle entries.  Hand-grep two integer fields.
        msgs_delivered="$(printf '%s' "$reply" | grep -oE '"msgs_delivered"[[:space:]]*:[[:space:]]*[0-9]+' \
            | grep -oE '[0-9]+' | head -1)"
        acks="$(printf '%s' "$reply" | grep -oE '"acks"[[:space:]]*:[[:space:]]*[0-9]+' \
            | grep -oE '[0-9]+' | head -1)"
        msgs_delivered="${msgs_delivered:-0}"
        acks="${acks:-0}"
        if [ "$msgs_delivered" -ge "$N_MESSAGES" ] \
            && [ "$acks" -ge "$N_MESSAGES" ]; then
            break
        fi
    fi
    sleep 0.5
done

if [ "${msgs_delivered:-0}" -ge "$N_MESSAGES" ]; then
    pass "consumer delivered ${msgs_delivered} >= ${N_MESSAGES} messages"
else
    fail "msgs_delivered=${msgs_delivered:-0} < ${N_MESSAGES}; last MI reply:"
    printf '%s\n' "${reply:-<no reply>}" | head -3 | sed 's/^/  | /'
fi

if [ "${acks:-0}" -ge "$N_MESSAGES" ]; then
    pass "consumer acked ${acks} >= ${N_MESSAGES} messages"
else
    fail "acks=${acks:-0} < ${N_MESSAGES}"
fi

# Defensive: no TLS / NATS errors slipped through end-to-end.
if grep -E "ERROR.*nats|tls_mgm.*failed|TLS.*not available|libnats not available|handshake.*failed" \
        "${WORKDIR}/opensips.log" >/dev/null 2>&1; then
    fail "fatal NATS/TLS errors in opensips.log"
    grep -E "ERROR.*nats|tls_mgm.*failed|TLS.*not available|libnats not available|handshake.*failed" \
        "${WORKDIR}/opensips.log" | head -5 | sed 's/^/  | /'
else
    pass "no fatal NATS/TLS errors in opensips.log"
fi

echo "==== summary: $PASSED pass, $FAILED fail ===="
exit "$SUITE_FAIL"
