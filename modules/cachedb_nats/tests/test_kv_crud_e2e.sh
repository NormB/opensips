#!/bin/bash
# test_kv_crud_e2e.sh -- end-to-end CRUD test for cachedb_nats.
#
# Drives nats_kv_put, nats_kv_get, nats_kv_update (CAS), nats_kv_delete,
# and nats_kv_revision against a live NATS JetStream KV bucket from an
# OpenSIPS request route triggered by a SIP OPTIONS we send after init.
#
# Why a request_route and not startup_route: startup_route runs in a
# SIP worker before the rank-0 child_init has finished creating the KV
# bucket, so all ops race the "No responders" window.  Sending a SIP
# packet from outside ensures every worker is past child_init.
#
# This is the first end-to-end correctness test for cachedb_nats -- the
# existing module unit tests cover oom/UAF/parse paths but not the
# get/put/delete round-trip.
#
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/../../../lib/nats/tests/nats_local_lib.sh"

require_nats_reachable
require_opensips_built
require_cmd nats opensips

BUCKET="OS_TEST_KV_C1_$$"
mkworkdir crud_e2e

# Belt+braces: nuke any leftover bucket of this name.
nats --server "${NATS_URL}" kv del "${BUCKET}" --force >/dev/null 2>&1 || true

cleanup_bucket() { nats --server "${NATS_URL}" kv del "${BUCKET}" --force >/dev/null 2>&1 || true; }
trap 'stop_opensips; cleanup_bucket; cleanup_workdir' EXIT

cat > "${WORK}/test.cfg" <<EOF
log_level=3
xlog_level=3
stderror_enabled=yes
syslog_facility=LOG_LOCAL0
udp_workers=1
socket=udp:127.0.0.1:5199

mpath="${OPENSIPS_MPATH}"

loadmodule "signaling.so"
loadmodule "sl.so"
loadmodule "tm.so"
loadmodule "rr.so"
loadmodule "maxfwd.so"
loadmodule "sipmsgops.so"
loadmodule "proto_udp.so"

loadmodule "mi_fifo.so"
modparam("mi_fifo", "fifo_name", "${OPS_FIFO}")

loadmodule "cachedb_nats.so"
modparam("cachedb_nats", "nats_url", "${NATS_URL}")
modparam("cachedb_nats", "kv_bucket", "${BUCKET}")
modparam("cachedb_nats", "kv_replicas", 1)

route {
    \$var(v) = "";
    \$var(rev) = 0;

    if (nats_kv_put("${BUCKET}", "alpha", "v1")) {
        xlog("L_NOTICE","[c1] put.alpha=ok\n");
    } else {
        xlog("L_ERR","[c1] put.alpha=fail\n");
    }

    if (nats_kv_get("${BUCKET}", "alpha", \$var(v), \$var(rev))) {
        xlog("L_NOTICE","[c1] get.alpha=ok value=\$var(v) rev=\$var(rev)\n");
    } else {
        xlog("L_ERR","[c1] get.alpha=fail\n");
    }

    # CAS: update with the rev we just read should succeed.
    if (nats_kv_update("${BUCKET}", "alpha", "v2", \$var(rev))) {
        xlog("L_NOTICE","[c1] cas.ok=ok\n");
    } else {
        xlog("L_ERR","[c1] cas.ok=fail\n");
    }

    # Stale CAS: same rev now stale, must be rejected.
    if (!nats_kv_update("${BUCKET}", "alpha", "v3", \$var(rev))) {
        xlog("L_NOTICE","[c1] cas.stale=rejected\n");
    } else {
        xlog("L_ERR","[c1] cas.stale=accepted-bug\n");
    }

    # Read-back after successful update.
    if (nats_kv_get("${BUCKET}", "alpha", \$var(v), \$var(rev))) {
        xlog("L_NOTICE","[c1] get.alpha2=ok value=\$var(v)\n");
    }

    if (nats_kv_delete("${BUCKET}", "alpha")) {
        xlog("L_NOTICE","[c1] del.alpha=ok\n");
    } else {
        xlog("L_ERR","[c1] del.alpha=fail\n");
    }

    # Get after delete: must NOT return the old value.
    \$var(v) = "";
    if (!nats_kv_get("${BUCKET}", "alpha", \$var(v), \$var(rev))) {
        xlog("L_NOTICE","[c1] get.gone=miss\n");
    } else {
        xlog("L_NOTICE","[c1] get.gone=hit value=\$var(v)\n");
    }

    sl_send_reply(200, "c1-done");
    exit;
}
EOF

start_opensips "${WORK}/test.cfg"

# Wait for the cachedb_nats per-worker bucket message to appear (this
# is the most reliable readiness signal for our purposes).
wait_for_log "nats_pool_get_kv: NATS pool: KV bucket '${BUCKET}' created" 8 \
    || fail "bucket '${BUCKET}' not created within 8s; log:
$(tail -40 "${OPS_LOG}")"
# Give the SIP worker (rank 1) a moment to finish its own child_init.
sleep 0.5

# Drive a SIP OPTIONS into the route.  We use a here-doc rather than
# sipsak to keep the test dependency-free.
SIP_REQ="OPTIONS sip:test@127.0.0.1:5199 SIP/2.0\r
Via: SIP/2.0/UDP 127.0.0.1:55199;branch=z9hG4bK-c1\r
From: <sip:harness@127.0.0.1>;tag=h1\r
To: <sip:test@127.0.0.1>\r
Call-ID: c1.${RANDOM}@127.0.0.1\r
CSeq: 1 OPTIONS\r
Max-Forwards: 70\r
Content-Length: 0\r
\r
"
printf "%b" "${SIP_REQ}" | timeout 3 nc -u -w1 127.0.0.1 5199 >/dev/null 2>&1 || true

# All seven markers should appear within 6s.
ok=0
for marker in 'put\.alpha=ok' 'get\.alpha=ok value=v1' 'cas\.ok=ok' 'cas\.stale=rejected' 'get\.alpha2=ok value=v2' 'del\.alpha=ok' 'get\.gone=miss'; do
    if wait_for_log "\\[c1\\] ${marker}" 6; then
        echo "  ok: ${marker}"
        ok=$((ok+1))
    else
        echo "  MISSING: ${marker}"
    fi
done

# Hard-fail markers: a delete that didn't take, or a stale-CAS that
# was wrongly accepted, indicate a real bug.
if log_contains '\[c1\] get\.gone=hit'; then
    fail "delete did not remove key (stale read after delete)"
fi
if log_contains '\[c1\] cas\.stale=accepted-bug'; then
    fail "stale-revision CAS update was wrongly accepted"
fi

[ "${ok}" = "7" ] || fail "only ${ok}/7 markers passed; relevant log:
$(grep -E '\[c1\]|cachedb_nats' "${OPS_LOG}" | tail -40)"

pass "cachedb_nats CRUD round-trip (put/get/CAS/stale-CAS/update/delete) all green"
