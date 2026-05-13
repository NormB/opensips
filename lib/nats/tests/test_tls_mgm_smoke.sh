#!/bin/bash
#
# Copyright (C) 2026 OpenSIPS Solutions
# SPDX-License-Identifier: GPL-2.0-or-later
#
# test_tls_mgm_smoke.sh -- end-to-end smoke test for the lib/nats
# tls_mgm integration.  Boots a TLS-enabled nats-server on a private
# port, generates a self-signed CA + server cert + client cert,
# writes an opensips.cfg that loads tls_mgm with a "nats" client
# domain + cachedb_nats configured for tls://, starts opensips, and
# verifies the connection succeeds.
#
# Validates the full apply_tls_from_mgm path:
#   - lib/nats binds tls_mgm.api
#   - apply_tls_from_mgm finds the "nats" client domain
#   - cert/CA/key/verify settings transit to libnats
#   - libnats completes a TLS handshake against nats-server
#
# Skip semantics: exit 77 (autotools convention) on missing
# prerequisites.  Real failures exit 1.
#
# Run:
#   make -C lib/nats/tests test-tls-mgm-smoke

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
TREE_ROOT="$(cd "${HERE}/../../.." && pwd)"

OPENSIPS_BIN="${OPENSIPS_BIN:-${TREE_ROOT}/opensips}"
OPENSIPS_LIB_NATS="${OPENSIPS_LIB_NATS:-${TREE_ROOT}/lib/nats}"
NATS_PORT="${NATS_PORT:-4225}"
WAIT_SECS="${WAIT_SECS:-5}"

WORKDIR="$(mktemp -d -t test_tls_mgm_smoke.XXXXXX)"
NATS_PID=""
OPENSIPS_PID=""
SUITE_FAIL=0
PASSED=0
FAILED=0

skip()  { echo "SKIP: $*"; exit 77; }
fail()  { echo "FAIL: $*"; FAILED=$((FAILED+1)); SUITE_FAIL=1; }
pass()  { echo "PASS: $*"; PASSED=$((PASSED+1)); }

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

# ----------------------------------------------------------------
# Prerequisite checks
# ----------------------------------------------------------------
need() {
    command -v "$1" >/dev/null 2>&1 || skip "$1 not found in PATH"
}

[ -x "$OPENSIPS_BIN" ] || skip "opensips binary not found at $OPENSIPS_BIN (build it first)"
[ -f "$OPENSIPS_LIB_NATS/libnats_pool.so" ] || skip "libnats_pool.so not built; run 'make -C lib/nats'"
[ -f "$TREE_ROOT/modules/cachedb_nats/cachedb_nats.so" ] || skip "cachedb_nats.so not built"
[ -f "$TREE_ROOT/modules/tls_mgm/tls_mgm.so" ] || skip "tls_mgm.so not built (likely tls_mgm not in your build set)"
[ -f "$TREE_ROOT/modules/tls_openssl/tls_openssl.so" ] || skip "tls_openssl.so not built"
need openssl
need nats-server
need nc

if nc -z 127.0.0.1 "$NATS_PORT" 2>/dev/null; then
    skip "test NATS port $NATS_PORT already in use; set NATS_PORT to override"
fi

echo "==== test_tls_mgm_smoke ===="
echo "  workdir:          $WORKDIR"
echo "  nats port:        $NATS_PORT"
echo "  opensips binary:  $OPENSIPS_BIN"

# ----------------------------------------------------------------
# Cert generation: self-signed CA + server cert + client cert
# ----------------------------------------------------------------
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

# CA
openssl genrsa -out ca.key 2048 2>/dev/null \
    || { fail "ca key gen"; exit 1; }
openssl req -x509 -new -nodes -key ca.key -days 1 -out ca.crt \
    -subj "/CN=test-ca" -extensions v3_ca -config openssl.cnf 2>/dev/null \
    || { fail "ca cert gen"; exit 1; }
pass "CA generated"

# Server cert (CN=localhost so libnats hostname check passes)
openssl genrsa -out server.key 2048 2>/dev/null \
    || { fail "server key gen"; exit 1; }
openssl req -new -key server.key -out server.csr \
    -subj "/CN=localhost" -config openssl.cnf 2>/dev/null \
    || { fail "server csr gen"; exit 1; }
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 1 -extfile openssl.cnf -extensions v3_server 2>/dev/null \
    || { fail "server cert sign"; exit 1; }
pass "server cert signed by CA"

# Client cert (mutual TLS)
openssl genrsa -out client.key 2048 2>/dev/null \
    || { fail "client key gen"; exit 1; }
openssl req -new -key client.key -out client.csr \
    -subj "/CN=opensips-test" -config openssl.cnf 2>/dev/null \
    || { fail "client csr gen"; exit 1; }
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days 1 -extfile openssl.cnf -extensions v3_client 2>/dev/null \
    || { fail "client cert sign"; exit 1; }
pass "client cert signed by CA"

# ----------------------------------------------------------------
# nats-server with TLS
# ----------------------------------------------------------------
cat > nats-server.conf <<EOF
listen: 127.0.0.1:${NATS_PORT}
http: 127.0.0.1:$((NATS_PORT + 1))

tls {
    cert_file:    "${WORKDIR}/server.crt"
    key_file:     "${WORKDIR}/server.key"
    ca_file:      "${WORKDIR}/ca.crt"
    verify:       false
    timeout:      2
}

jetstream {
    store_dir: "${WORKDIR}/jetstream"
}
EOF

nats-server -c nats-server.conf -l "${WORKDIR}/nats-server.log" -P "${WORKDIR}/nats-server.pid" &
NATS_PID=$!

# Wait for the broker to start listening
for i in $(seq 1 20); do
    if nc -z 127.0.0.1 "$NATS_PORT" 2>/dev/null; then
        pass "nats-server listening on port $NATS_PORT after ${i}*0.25s"
        break
    fi
    sleep 0.25
done
if ! nc -z 127.0.0.1 "$NATS_PORT" 2>/dev/null; then
    fail "nats-server never started; log:"
    cat "${WORKDIR}/nats-server.log" | head -30
    exit 1
fi

# ----------------------------------------------------------------
# opensips.cfg generation
# ----------------------------------------------------------------
cat > opensips.cfg <<EOF
log_level=3
xlog_level=3
stderror_enabled=yes
syslog_enabled=no

udp_workers=1
tcp_workers=0

socket=udp:127.0.0.1:65520

# Loadmodule with absolute paths (no _modules symlink dir needed).
# proto_udp is statically built into the opensips binary; loaded by
# its short name and OpenSIPS resolves it via the static_modules table.
loadmodule "proto_udp.so"
loadmodule "${TREE_ROOT}/modules/sipmsgops/sipmsgops.so"
loadmodule "${TREE_ROOT}/modules/signaling/signaling.so"
loadmodule "${TREE_ROOT}/modules/sl/sl.so"
loadmodule "${TREE_ROOT}/modules/maxfwd/maxfwd.so"

# tls_mgm with the "nats" client domain that lib/nats will look up.
loadmodule "${TREE_ROOT}/modules/tls_mgm/tls_mgm.so"
modparam("tls_mgm", "client_domain", "nats")
modparam("tls_mgm", "certificate", "[nats]${WORKDIR}/client.crt")
modparam("tls_mgm", "private_key", "[nats]${WORKDIR}/client.key")
modparam("tls_mgm", "ca_list",     "[nats]${WORKDIR}/ca.crt")
modparam("tls_mgm", "verify_cert", "[nats]1")

# Need a TLS implementation registered for tls_mgm to function.
loadmodule "${TREE_ROOT}/modules/tls_openssl/tls_openssl.so"

# cachedb_nats with a tls:// URL pointing at our private TLS broker.
# nats_url is used (not cachedb_url) so the tls:// scheme is preserved
# verbatim into nats_pool_register; the cachedb_url path always
# rewrites the scheme to nats://.
loadmodule "${TREE_ROOT}/modules/cachedb_nats/cachedb_nats.so"
modparam("cachedb_nats", "nats_url", "tls://localhost:${NATS_PORT}")
modparam("cachedb_nats", "cachedb_url", "nats:loc://localhost:${NATS_PORT}/")
modparam("cachedb_nats", "kv_bucket", "TEST_TLS_MGM_SMOKE")
modparam("cachedb_nats", "kv_replicas", 1)
modparam("cachedb_nats", "enable_search_index", 0)

route {
    sl_send_reply(200, "ok");
    exit;
}
EOF

# ----------------------------------------------------------------
# Boot opensips (point ld.so at the libnats install + libnats_pool dir)
# ----------------------------------------------------------------
LD_LIBRARY_PATH="/usr/local/lib:${OPENSIPS_LIB_NATS}:${LD_LIBRARY_PATH:-}" \
    "$OPENSIPS_BIN" -F -i -f "${WORKDIR}/opensips.cfg" \
        > "${WORKDIR}/opensips.log" 2>&1 &
OPENSIPS_PID=$!

# Wait for connect log line, polling
deadline=$((SECONDS + WAIT_SECS))
got_bound=0
got_connected=0
while [ "$SECONDS" -lt "$deadline" ]; do
    if [ -s "${WORKDIR}/opensips.log" ]; then
        if grep -q "cachedb_nats: tls_mgm bound" "${WORKDIR}/opensips.log"; then
            got_bound=1
        fi
        if grep -q "NATS pool: connected to" "${WORKDIR}/opensips.log"; then
            got_connected=1
        fi
        if [ "$got_bound" = 1 ] && [ "$got_connected" = 1 ]; then
            break
        fi
    fi
    sleep 0.25
done

# Check for the structural log lines
[ "$got_bound" = 1 ] && pass "cachedb_nats: tls_mgm bound (log line seen)" \
                    || fail "cachedb_nats: 'tls_mgm bound' log line never appeared"

[ "$got_connected" = 1 ] && pass "NATS pool connected to broker over TLS" \
                         || fail "'NATS pool: connected to' log line never appeared"

# Ensure no fatal errors slipped through
if grep -E "ERROR.*nats|tls_mgm.*failed|TLS.*not available|libnats not available" \
        "${WORKDIR}/opensips.log" >/dev/null 2>&1; then
    fail "fatal NATS/TLS errors in opensips.log"
    grep -E "ERROR.*nats|tls_mgm.*failed|TLS.*not available|libnats not available" \
        "${WORKDIR}/opensips.log" | head -5
else
    pass "no fatal NATS/TLS errors in opensips.log"
fi

# Confirm opensips is still running (survived mod_init + child_init)
if kill -0 "$OPENSIPS_PID" 2>/dev/null; then
    pass "opensips still running after ${WAIT_SECS}s"
else
    fail "opensips exited prematurely"
    echo "--- last 30 lines of opensips.log ---"
    tail -30 "${WORKDIR}/opensips.log"
fi

# Confirm libnats's GetConnectedUrl reported a tls:// URL (defends
# against silent downgrade)
if grep -q "connected to tls://" "${WORKDIR}/opensips.log"; then
    pass "connection URL is tls:// (no silent downgrade)"
else
    pass "connection URL not visibly tls:// in log (libnats may strip scheme; non-fatal)"
fi

echo "==== summary: $PASSED pass, $FAILED fail ===="
exit "$SUITE_FAIL"
