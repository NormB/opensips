#!/bin/bash
# test_srv_e2e.sh -- nats+srv:// server URLs resolved by the nats module against
# a real DNS answer and real nats-servers, with the vendor libnats.
#
# The test re-runs itself inside new mount and network namespaces (as an
# unprivileged user namespace, or with sudo where those are restricted):
# a private /etc/resolv.conf points at nats_srv_dns.py on 127.0.0.1:53,
# which serves the SRV records of _nats._tcp.srv.test.  Nothing outside
# the namespaces changes.  Checks:
#
#  1. nats_url "nats+srv://srv.test", records a.srv.test (priority 10)
#     and b.srv.test (priority 20), no_randomize left at 0: every
#     process connects to a.srv.test -- the lowest priority -- and none
#     to b.srv.test.
#  2. a.srv.test stops: the processes move to b.srv.test.
#  3. nats_url "nats+srv://none.test" (NXDOMAIN): opensips starts
#     degraded and warns which SRV URL gave no server.
#
# Skips (exit 77) without nats-server, curl, jq, python3, ip, or a way to
# create the namespaces.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ "${1:-}" != "--inner" ]; then
    . "${HERE}/nats_local_lib.sh"
    require_opensips_built
    require_cmd nats-server curl jq python3 ip
    if unshare --user --map-root-user --mount --net true 2>/dev/null; then
        exec unshare --user --map-root-user --mount --net bash "$0" --inner
    elif sudo -n unshare --mount --net true 2>/dev/null; then
        exec sudo -n --preserve-env=PATH,NATS_DL_LIBNATS_PATH,OPENSIPS_BIN,OPENSIPS_MPATH,OPENSIPS_LIBDIR \
            unshare --mount --net bash "$0" --inner
    fi
    skip "cannot create mount and network namespaces (unprivileged user namespaces disabled, no sudo)"
fi

# ---------- inside the namespaces ----------
. "${HERE}/nats_local_lib.sh"
ip link set lo up || fail "cannot bring up loopback in the network namespace"
mkworkdir srv_e2e >/dev/null
PA=14222
PB=14232
NS_PIDS=()
DNS_PID=""
trap 'stop_opensips; for p in "${NS_PIDS[@]}"; do kill "$p" 2>/dev/null; done; [ -n "${DNS_PID}" ] && kill "${DNS_PID}" 2>/dev/null; cleanup_workdir' EXIT

printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1\n' > "${WORK}/resolv.conf"
mount --bind "${WORK}/resolv.conf" /etc/resolv.conf || fail "cannot bind-mount /etc/resolv.conf"
# The SRV lookup (OpenSIPS core resolver) reads resolv.conf; libnats
# resolves the targets with getaddrinfo(), through NSS, which may ask
# systemd-resolved first ("resolve" in nsswitch.conf) and stop at its
# NXDOMAIN.  Inside the namespaces, host names come from DNS only.
printf 'hosts: files dns\n' > "${WORK}/nsswitch.conf"
mount --bind "${WORK}/nsswitch.conf" /etc/nsswitch.conf || fail "cannot bind-mount /etc/nsswitch.conf"

python3 -I "${HERE}/nats_srv_dns.py" 127.0.0.1 53 srv.test \
    "10,10,${PA},a.srv.test." "20,10,${PB},b.srv.test." > "${WORK}/dns.log" 2>&1 &
DNS_PID=$!
for i in $(seq 1 50); do grep -q ready "${WORK}/dns.log" && break; sleep 0.1; done
grep -q ready "${WORK}/dns.log" || fail "DNS responder did not start: $(cat "${WORK}/dns.log")"

start_ns() {   # start_ns <port>
    nats-server -a 127.0.0.1 -p "$1" -m $(($1 + 1)) -l "${WORK}/ns$1.log" &
    NS_PIDS+=($!)
    for i in $(seq 1 50); do
        curl -sf "http://127.0.0.1:$(($1 + 1))/varz" >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    fail "nats-server on $1 did not start"
}
conns() { curl -sf "http://127.0.0.1:$(($1 + 1))/connz" 2>/dev/null | jq -r '.num_connections // 0'; }

start_ns "${PA}"
A_PID=${NS_PIDS[0]}
start_ns "${PB}"

FAILS=0
check() {   # check <label> <expected> <actual>
    if [ "$2" = "$3" ]; then echo "  ok: $1"
    else echo "  FAIL: $1 (expected '$2', got '$3')"; FAILS=$((FAILS + 1)); fi
}

CASE=0
boot() {   # boot <nats_url>
    stop_opensips
    [ -f "${OPS_LOG}" ] && cp "${OPS_LOG}" "${WORK}/case${CASE}.log"
    CASE=$((CASE + 1))
    cat > "${WORK}/test.cfg" <<EOF
log_level=3
stderror_enabled=yes
syslog_facility=LOG_LOCAL0
udp_workers=4
socket=udp:127.0.0.1:15060
mpath="${OPENSIPS_MPATH}"
loadmodule "signaling.so"
loadmodule "sl.so"
loadmodule "proto_udp.so"
loadmodule "mi_fifo.so"
modparam("mi_fifo", "fifo_name", "${OPS_FIFO}")
loadmodule "nats.so"
loadmodule "event_nats.so"
modparam("event_nats", "nats_url", "$1")
modparam("event_nats", "reconnect_wait", 200)
route { sl_send_reply(200, "ok"); exit; }
EOF
    rm -f "${OPS_FIFO}"
    start_opensips "${WORK}/test.cfg"
}

echo "--- 1: priority order from the SRV records ---"
boot "nats+srv://srv.test"
for i in $(seq 1 100); do
    [ "$(grep -c 'NATS pool: connected to' "${OPS_LOG}")" -ge 5 ] && break
    sleep 0.1
done
sleep 0.5
N=$(grep -c 'NATS pool: connected to' "${OPS_LOG}")
echo "    ${N} processes connected; a.srv.test $(conns ${PA}), b.srv.test $(conns ${PB})"
check "processes connected" yes "$([ "${N}" -ge 5 ] && echo yes || echo "no (${N})")"
check "every process on the priority-10 target" yes \
    "$([ "${N}" -ge 5 ] && [ "$(conns ${PA})" = "${N}" ] && echo yes || echo "no (${N} connected, $(conns ${PA}) on it)")"
check "none on the priority-20 target" 0 "$(conns ${PB})"
check "the nats module looked up the SRV record" yes \
    "$(grep -q "Q 33 _nats._tcp.srv.test" "${WORK}/dns.log" && echo yes || echo no)"
check "the targets reach libnats as names (looked up as A records)" yes \
    "$(grep -q "Q 1 a.srv.test" "${WORK}/dns.log" && echo yes || echo no)"

echo "--- 2: the priority-10 target stops ---"
kill "${A_PID}" 2>/dev/null
for i in $(seq 1 150); do
    [ "$(conns ${PB})" -ge "${N}" ] && break
    sleep 0.1
done
check "every process moved to the priority-20 target" yes \
    "$([ "${N}" -ge 5 ] && [ "$(conns ${PB})" = "${N}" ] && echo yes || echo "no ($(conns ${PB}) of ${N})")"
assert_opensips_alive

echo "--- 3: an SRV domain with no records ---"
boot "nats+srv://none.test"
sleep 3
assert_opensips_alive
check "warning names the SRV URL that gave no server" yes \
    "$(log_contains 'DNS SRV lookup of nats\+srv://none.test gave no server' && echo yes || echo no)"
check "and says the process continues without NATS" yes \
    "$(log_contains 'no NATS server left after the DNS SRV lookups' && echo yes || echo no)"
stop_opensips

if [ "${FAILS}" -ne 0 ]; then
    cp "${OPS_LOG}" "${WORK}/case${CASE}.log"
    for f in "${WORK}"/case*.log; do
        echo "--- $(basename "$f") ---"
        grep -iE 'nats pool|srv|error' "$f" | head -12
    done
    echo "--- DNS queries ---"; head -20 "${WORK}/dns.log"
    fail "${FAILS} check(s) failed"
fi
pass "nats+srv:// resolved by the nats module: RFC 2782 priority order, failover, no-record warning"
