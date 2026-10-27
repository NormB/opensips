#!/bin/bash
# test_usrloc_natping_e2e.sh -- NAT pinging works with usrloc in
# full-sharing-cachedb mode on cachedb_nats.
#
# nathelper's pinging timer asks usrloc for the contacts to ping, and in
# full-sharing-cachedb mode usrloc fetches them with a range query on the
# rows' integer "aorhash" field (min <= aorhash < max, one slice per
# tick).  cachedb_nats used to refuse that query -- with or without the
# cachedb_nats_fts index -- so no contact was ever pinged.
#
# A contact flagged for SIP pinging is registered against a private
# broker; it points at a local UDP listener, which must receive the OPTIONS
# pings.  Run with and without cachedb_nats_fts loaded.
#
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/../../nats/tests/nats_local_lib.sh"

require_opensips_built
require_cmd nats python3
command -v nats-server >/dev/null 2>&1 || skip "nats-server not in PATH (apt: nats-server; often /usr/sbin)"
require_modules_built usrloc registrar nathelper clusterer proto_bin sl tm signaling sipmsgops mi_fifo cachedb_nats_fts

PORT=4330
PRIV_URL="nats://127.0.0.1:${PORT}"
SIP_PORT=5490
UA_PORT=5491
CLUSTER_PORT=5492

mkworkdir usrloc_natping
NS_PID=""; LISTENER_PID=""
cleanup_all() {
    [ -n "${LISTENER_PID}" ] && kill "${LISTENER_PID}" 2>/dev/null
    stop_opensips
    [ -n "${NS_PID}" ] && kill "${NS_PID}" 2>/dev/null
    wait 2>/dev/null
    cleanup_workdir
}
trap cleanup_all EXIT

nats-server -a 127.0.0.1 -p "${PORT}" -js -sd "${WORK}/js" > "${WORK}/nats.log" 2>&1 &
NS_PID=$!
for _ in $(seq 1 50); do
    nats --server "${PRIV_URL}" rtt --timeout 200ms >/dev/null 2>&1 && break
    sleep 0.1
done

# the UA: counts the OPTIONS it receives, answers REGISTER-less
cat > "${WORK}/ua.py" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
n = 0
while True:
    data, peer = s.recvfrom(65535)
    if data.startswith(b"OPTIONS "):
        n += 1
        with open(sys.argv[2], "w") as f:
            f.write("%d\n" % n)
EOF

register() {  # register <aor-user>: one REGISTER from the UA's port
    python3 - "$1" <<EOF
import socket, sys, random
u = sys.argv[1]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
msg = ("REGISTER sip:127.0.0.1:${SIP_PORT} SIP/2.0\r\n"
       "Via: SIP/2.0/UDP 127.0.0.1:${UA_PORT};rport;branch=z9hG4bK%x\r\n"
       "From: <sip:%s@127.0.0.1>;tag=%x\r\n"
       "To: <sip:%s@127.0.0.1>\r\n"
       "Call-ID: %x@natping\r\n"
       "CSeq: 1 REGISTER\r\n"
       "Contact: <sip:%s@127.0.0.1:${UA_PORT}>\r\n"
       "Expires: 300\r\n"
       "Max-Forwards: 70\r\n"
       "Content-Length: 0\r\n\r\n") % (random.getrandbits(32), u,
       random.getrandbits(32), u, random.getrandbits(48), u)
s.sendto(msg.encode(), ("127.0.0.1", ${SIP_PORT}))
print(s.recv(65535).split(b"\r\n")[0].decode())
EOF
}

run_variant() {  # run_variant <label> <fts 0|1>
    local label="$1" fts="$2" bucket="OS_TEST_NATPING_$$_$2" status pings
    : > "${WORK}/pings"
    cat > "${WORK}/test.cfg" <<EOF
log_level=3
stderror_enabled=yes
udp_workers=1
socket=udp:127.0.0.1:${SIP_PORT}

mpath="${OPENSIPS_MPATH}"
loadmodule "proto_udp.so"
loadmodule "proto_bin.so"
socket=bin:127.0.0.1:${CLUSTER_PORT}
loadmodule "signaling.so"
loadmodule "sl.so"
loadmodule "tm.so"
loadmodule "sipmsgops.so"
loadmodule "mi_fifo.so"
modparam("mi_fifo", "fifo_name", "${OPS_FIFO}")

loadmodule "clusterer.so"
modparam("clusterer", "db_mode", 0)
modparam("clusterer", "my_node_id", 1)
modparam("clusterer", "my_node_info",
    "cluster_id=1, url=bin:127.0.0.1:${CLUSTER_PORT}, priority=50, no_ping=1")

loadmodule "nats.so"
loadmodule "cachedb_nats.so"
modparam("cachedb_nats", "cachedb_url", "nats:loc://127.0.0.1:${PORT}/")
modparam("cachedb_nats", "kv_bucket", "${bucket}")
modparam("cachedb_nats", "kv_replicas", 1)
modparam("cachedb_nats", "fts_json_prefix", "json_")
$( [ "$fts" = 1 ] && printf '%s\n%s\n' 'loadmodule "cachedb_nats_fts.so"' \
    'modparam("cachedb_nats", "kv_watch", "json_>")' )

loadmodule "usrloc.so"
modparam("usrloc", "cluster_mode", "full-sharing-cachedb")
modparam("usrloc", "location_cluster", 1)
modparam("usrloc", "cachedb_url", "nats:loc://127.0.0.1:${PORT}/")
modparam("usrloc", "nat_bflag", "NAT")
modparam("usrloc", "use_domain", 1)
loadmodule "registrar.so"

loadmodule "nathelper.so"
modparam("nathelper", "natping_interval", 1)
modparam("nathelper", "sipping_bflag", "SIPPING")
modparam("nathelper", "sipping_from", "sip:pinger@127.0.0.1")

route {
    if (is_method("REGISTER")) {
        setbflag("NAT");
        setbflag("SIPPING");
        if (!save("location"))
            sl_send_reply(500, "save failed");
        exit;
    }
    sl_send_reply(404, "Not here");
}
EOF
    python3 "${WORK}/ua.py" "${UA_PORT}" "${WORK}/pings" &
    LISTENER_PID=$!
    start_opensips "${WORK}/test.cfg"
    sleep 1
    assert_opensips_alive
    status=$(register bob)
    [ "${status#SIP/2.0 200}" != "${status}" ] \
        || fail "[$label] REGISTER not accepted: ${status}"

    pings=0
    for _ in $(seq 1 30); do
        pings=$(cat "${WORK}/pings" 2>/dev/null)
        [ "${pings:-0}" -ge 2 ] && break
        sleep 0.5
    done
    if [ "${pings:-0}" -lt 2 ]; then
        fail "[$label] the registered contact received ${pings:-0} OPTIONS ping(s); log:
$(grep -E 'ping|query|filter|scan' "${OPS_LOG}" | tail -8)"
    fi
    echo "  ok: [$label] the contact receives NAT pings (${pings} so far)"
    if grep -q "failed to fetch contacts to ping" "${OPS_LOG}"; then
        fail "[$label] usrloc logged 'failed to fetch contacts to ping'"
    fi
    echo "  ok: [$label] no pinging query failure in the log"

    stop_opensips
    kill "${LISTENER_PID}" 2>/dev/null; wait "${LISTENER_PID}" 2>/dev/null
    LISTENER_PID=""
}

run_variant "no search index" 0
run_variant "with cachedb_nats_fts" 1
pass "NAT pinging over cachedb_nats in full-sharing-cachedb mode"
