#!/bin/bash
# test_auth_e2e.sh -- the shared NATS connection authenticates with the
# credential modparams (no secret in the URL), against a real nats-server
# per method, and a wrong credential is refused:
#
#   user + password    authorization { user, password }
#   token              authorization { token }
#   nkey + seed file   authorization { users = [ { nkey } ] }
#   creds_file         operator mode (JWT), memory resolver
#   TLS client cert    tls { verify: true }: the tls_mgm "nats" domain's
#                      certificate is required (no URL or modparam secret)
#
# Each case boots opensips with event_nats and checks that the pool
# connects (log) and the server lists the connection (monitoring /connz);
# each negative case checks that it does not connect and that the server
# logged the refusal.  Two startup refusals: an incomplete pair (user
# without password) and credentials both in the URL and as modparams.
#
# Skips (exit 77) without nats-server, the nats CLI (0.3 or later, for
# `nats auth`), openssl, curl, jq or a built opensips with tls_mgm and
# tls_openssl.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/nats_local_lib.sh"

require_opensips_built
require_cmd nats nats-server openssl curl jq
nats auth --help >/dev/null 2>&1 || skip "nats CLI without 'nats auth'"
require_modules_built tls_mgm tls_openssl

mkworkdir nats_auth >/dev/null
PORT=$((22000 + ($$ % 15000)))
MPORT=$((PORT + 1))
SRV_PID=""
stop_srv() {
    [ -n "${SRV_PID}" ] || return 0
    kill "${SRV_PID}" 2>/dev/null || true
    wait "${SRV_PID}" 2>/dev/null || true
    SRV_PID=""
}
trap 'stop_opensips; stop_srv; cleanup_workdir' EXIT

FAILS=0
check() {   # check <label> <expected> <actual>
    if [ "$2" = "$3" ]; then echo "  ok: $1"
    else echo "  FAIL: $1 (expected '$2', got '$3')"; FAILS=$((FAILS + 1)); fi
}

start_srv() {   # start_srv <conf body>
    stop_srv
    printf 'listen: 127.0.0.1:%s\nhttp: 127.0.0.1:%s\n%s\n' "${PORT}" "${MPORT}" "$1" \
        > "${WORK}/srv.conf"
    : > "${WORK}/srv.log"
    nats-server -c "${WORK}/srv.conf" -l "${WORK}/srv.log" &
    SRV_PID=$!
    local i
    for i in $(seq 1 50); do
        curl -sf "http://127.0.0.1:${MPORT}/varz" >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    fail "nats-server did not start:\n$(cat "${WORK}/srv.log")"
}

conns() {
    curl -sf "http://127.0.0.1:${MPORT}/connz" | jq -r '.num_connections'
}

boot() {   # boot <modparams...>: opensips with event_nats and the given lines
    stop_opensips
    {
        cat <<EOF
log_level=3
stderror_enabled=yes
syslog_facility=LOG_LOCAL0
udp_workers=1
socket=udp:127.0.0.1:$((PORT + 2))
mpath="${OPENSIPS_MPATH}"
loadmodule "signaling.so"
loadmodule "sl.so"
loadmodule "proto_udp.so"
loadmodule "mi_fifo.so"
modparam("mi_fifo", "fifo_name", "${OPS_FIFO}")
EOF
        printf '%s\n' "$@"
        echo 'route { sl_send_reply(200, "ok"); exit; }'
    } > "${WORK}/test.cfg"
    rm -f "${OPS_FIFO}"
    "${OPENSIPS_BIN}" -F -f "${WORK}/test.cfg" > "${OPS_LOG}" 2>&1 &
    OPS_PID=$!
}

EN='loadmodule "nats.so"
loadmodule "event_nats.so"'
URL="modparam(\"event_nats\", \"nats_url\", \"nats://127.0.0.1:${PORT}\")"

# connects: the pool logged it and the server lists the connection
expect_connect() {   # expect_connect <label> <modparams...>
    local label=$1; shift
    boot "$@"
    if wait_for_log "NATS pool: connected to" 10 && [ "$(conns)" -ge 1 ]; then
        echo "  ok: ${label}: connected"
    else
        echo "  FAIL: ${label}: not connected; log:"; tail -5 "${OPS_LOG}" | sed 's/^/      /'
        FAILS=$((FAILS + 1))
    fi
}

# refused by the server: no connection, the server logged the refusal
expect_refused() {   # expect_refused <label> <server log pattern> <modparams...>
    local label=$1 pat=$2; shift 2
    boot "$@"
    sleep 3
    if ! log_contains "NATS pool: connected to" && [ "$(conns)" = 0 ] &&
       grep -qiE "${pat}" "${WORK}/srv.log"; then
        echo "  ok: ${label}: refused"
    else
        echo "  FAIL: ${label}: not refused as expected (conns=$(conns))"
        FAILS=$((FAILS + 1))
    fi
}

# opensips refuses to start, with the reason
expect_no_start() {   # expect_no_start <label> <log pattern> <modparams...>
    local label=$1 pat=$2; shift 2
    boot "$@"
    local i
    for i in $(seq 1 50); do
        kill -0 "${OPS_PID}" 2>/dev/null || break
        sleep 0.1
    done
    if ! kill -0 "${OPS_PID}" 2>/dev/null && log_contains "${pat}"; then
        echo "  ok: ${label}: startup refused"
    else
        echo "  FAIL: ${label}: startup not refused with '${pat}'"; tail -5 "${OPS_LOG}" | sed 's/^/      /'
        FAILS=$((FAILS + 1))
    fi
    OPS_PID=""
}

echo "--- user + password ---"
start_srv 'authorization { user: alice, password: "pa55word" }'
expect_connect "user/password" "${EN}" "${URL}" \
    'modparam("event_nats", "user", "alice")' 'modparam("event_nats", "password", "pa55word")'
check "the server authorized user alice" alice \
    "$(curl -sf "http://127.0.0.1:${MPORT}/connz?auth=1" | jq -r '.connections[0].authorized_user')"
check "the password is not in the opensips log" 0 "$(grep -c pa55word "${OPS_LOG}")"
expect_refused "wrong password" "authentication error|authorization violation" "${EN}" "${URL}" \
    'modparam("event_nats", "user", "alice")' 'modparam("event_nats", "password", "wrong")'
expect_no_start "user without password" "user and password must be set together" "${EN}" "${URL}" \
    'modparam("event_nats", "user", "alice")'
expect_no_start "credentials in the URL and as modparams" "both in a server URL and" "${EN}" \
    "modparam(\"event_nats\", \"nats_url\", \"nats://alice:pa55word@127.0.0.1:${PORT}\")" \
    'modparam("event_nats", "user", "alice")' 'modparam("event_nats", "password", "pa55word")'

echo "--- token ---"
start_srv 'authorization { token: "t0kenvalue" }'
expect_connect "token" "${EN}" "${URL}" 'modparam("event_nats", "token", "t0kenvalue")'
check "the token is not in the opensips log" 0 "$(grep -c t0kenvalue "${OPS_LOG}")"
expect_refused "wrong token" "authentication error|authorization violation" "${EN}" "${URL}" \
    'modparam("event_nats", "token", "other")'

echo "--- nkey ---"
export HOME="${WORK}/home" XDG_CONFIG_HOME="${WORK}/home/cfg" XDG_DATA_HOME="${WORK}/home/data"
mkdir -p "${HOME}"
nats auth nkey gen user --output "${WORK}/u.nk" >/dev/null 2>&1 || fail "nkey gen"
nats auth nkey gen user --output "${WORK}/other.nk" >/dev/null 2>&1 || fail "nkey gen"
UPUB=$(nats auth nkey show "${WORK}/u.nk" 2>/dev/null)
OPUB=$(nats auth nkey show "${WORK}/other.nk" 2>/dev/null)
start_srv "authorization { users = [ { nkey: ${UPUB} } ] }"
expect_connect "nkey" "${EN}" "${URL}" "modparam(\"event_nats\", \"nkey\", \"${UPUB}\")" \
    "modparam(\"event_nats\", \"nkey_seed_file\", \"${WORK}/u.nk\")"
expect_refused "an nkey the server does not know" "authentication error|authorization violation" \
    "${EN}" "${URL}" "modparam(\"event_nats\", \"nkey\", \"${OPUB}\")" \
    "modparam(\"event_nats\", \"nkey_seed_file\", \"${WORK}/other.nk\")"
expect_no_start "nkey_seed_file that cannot be read" "cannot be read" "${EN}" "${URL}" \
    "modparam(\"event_nats\", \"nkey\", \"${UPUB}\")" \
    "modparam(\"event_nats\", \"nkey_seed_file\", \"${WORK}/missing.nk\")"

echo "--- creds file (operator mode) ---"
jwtsub() {
    python3 -I -c 'import sys,json,base64; p=open(sys.argv[1]).read().strip().split(".")[1]; p+="="*(-len(p)%4); print(json.loads(base64.urlsafe_b64decode(p))["sub"])' "$1"
}
nats auth operator add OP >/dev/null 2>&1 || fail "operator add"
nats auth account add ACC --operator OP --defaults >/dev/null 2>&1 || fail "account add"
nats auth user add U ACC --operator OP --defaults >/dev/null 2>&1 || fail "user add"
nats auth user credential "${WORK}/u.creds" U ACC --operator OP >/dev/null 2>&1 || fail "creds"
nats auth operator add OP2 >/dev/null 2>&1 || fail "operator add"
nats auth account add ACC2 --operator OP2 --defaults >/dev/null 2>&1 || fail "account add"
nats auth user add U2 ACC2 --operator OP2 --defaults >/dev/null 2>&1 || fail "user add"
nats auth user credential "${WORK}/other.creds" U2 ACC2 --operator OP2 >/dev/null 2>&1 || fail "creds"
ST="${XDG_DATA_HOME}/nats/nsc/stores/OP"
ACC=$(jwtsub "${ST}/accounts/ACC/ACC.jwt"); SYS=$(jwtsub "${ST}/accounts/SYSTEM/SYSTEM.jwt")
start_srv "operator: ${ST}/OP.jwt
system_account: ${SYS}
resolver: MEMORY
resolver_preload: {
  ${ACC}: $(cat "${ST}/accounts/ACC/ACC.jwt")
  ${SYS}: $(cat "${ST}/accounts/SYSTEM/SYSTEM.jwt")
}"
expect_connect "creds file" "${EN}" "${URL}" \
    "modparam(\"event_nats\", \"creds_file\", \"${WORK}/u.creds\")"
expect_refused "creds of another operator" "authentication error|authorization violation" \
    "${EN}" "${URL}" "modparam(\"event_nats\", \"creds_file\", \"${WORK}/other.creds\")"
expect_no_start "creds file and token at once" "set only one" "${EN}" "${URL}" \
    "modparam(\"event_nats\", \"creds_file\", \"${WORK}/u.creds\")" \
    'modparam("event_nats", "token", "x")'

echo "--- TLS client certificate (verify: true) ---"
(
    cd "${WORK}" || exit 1
    openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 1 \
        -subj "/CN=test-ca" >/dev/null 2>&1
    printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > srv.ext
    openssl req -newkey rsa:2048 -nodes -keyout srv.key -out srv.csr -subj "/CN=localhost" >/dev/null 2>&1
    openssl x509 -req -in srv.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out srv.crt \
        -days 1 -extfile srv.ext >/dev/null 2>&1
    printf 'extendedKeyUsage=clientAuth\n' > cli.ext
    openssl req -newkey rsa:2048 -nodes -keyout cli.key -out cli.csr -subj "/CN=opensips" >/dev/null 2>&1
    openssl x509 -req -in cli.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out cli.crt \
        -days 1 -extfile cli.ext >/dev/null 2>&1
) || fail "certificate generation"
start_srv "tls {
  cert_file: \"${WORK}/srv.crt\"
  key_file: \"${WORK}/srv.key\"
  ca_file: \"${WORK}/ca.crt\"
  verify: true
  timeout: 2
}"
TLSM=(
    "loadmodule \"tls_mgm.so\""
    'modparam("tls_mgm", "client_domain", "nats")'
    "modparam(\"tls_mgm\", \"ca_list\", \"[nats]${WORK}/ca.crt\")"
    'modparam("tls_mgm", "verify_cert", "[nats]1")'
)
TLSURL="modparam(\"event_nats\", \"nats_url\", \"tls://localhost:${PORT}\")"
expect_connect "client certificate" "${TLSM[@]}" \
    "modparam(\"tls_mgm\", \"certificate\", \"[nats]${WORK}/cli.crt\")" \
    "modparam(\"tls_mgm\", \"private_key\", \"[nats]${WORK}/cli.key\")" \
    'loadmodule "tls_openssl.so"' "${EN}" "${TLSURL}"
expect_refused "no client certificate" "tls handshake error|certificate" "${TLSM[@]}" \
    'loadmodule "tls_openssl.so"' "${EN}" "${TLSURL}"

stop_opensips
stop_srv
[ "${FAILS}" -eq 0 ] || fail "${FAILS} check(s) failed"
pass "user/password, token, nkey, creds file and TLS client certificate authenticate; wrong ones are refused"
