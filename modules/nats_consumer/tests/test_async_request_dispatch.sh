#!/bin/bash
# test_async_request_dispatch.sh -- phase-1 dispatch validation for
# the async nats_request acmd.
#
# Drives OpenSIPS's own config-checker (opensips -C) against three
# minimal scripts.  No NATS broker required; we only verify that the
# parser, the module load path, and the cmds/acmds route-mask
# enforcement agree on which contexts may call which form:
#
#   A.  async(nats_request(...), rt)  inside the main script route
#         -> MUST PARSE     (acmd path; async() gates worker safety)
#   B.  nats_request(...)              inside the main script route
#         -> MUST BE REJECTED with "Command <nats_request> cannot be
#                                   used in the block"
#   C.  nats_request(...)              inside startup_route
#         -> MUST PARSE     (sync path is allowed from non-worker
#                            contexts; route mask explicitly permits
#                            STARTUP_ROUTE)
#
# A failure of any of these three assertions means the phase-1
# dispatch plumbing is broken even though the source-pattern unit
# test (test_async_request_skeleton.c) still happens to pass: e.g.
# the acmd entry was removed, the route mask widened, or the cmd
# was given ALL_ROUTES by accident.
#
# Skips with exit 77 if the opensips binary or _modules/ directory
# is not present in the tree -- this lets a Makefile target like
# `make check` run the rest of the suite on a partial build.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
TREE_ROOT="$(cd "${HERE}/../../.." && pwd)"

OPENSIPS_BIN="${TREE_ROOT}/opensips"
MOD_DIR="${TREE_ROOT}/_modules"
LIB_NATS="${TREE_ROOT}/lib/nats"

if [ ! -x "${OPENSIPS_BIN}" ]; then
    echo "skip: ${OPENSIPS_BIN} not built"
    exit 77
fi
if [ ! -d "${MOD_DIR}" ]; then
    echo "skip: ${MOD_DIR} missing (run make modules first)"
    exit 77
fi
for m in nats_consumer.so proto_bin.so signaling.so sl.so tm.so \
         maxfwd.so rr.so sipmsgops.so; do
    if [ ! -e "${MOD_DIR}/${m}" ]; then
        echo "skip: ${MOD_DIR}/${m} missing"
        exit 77
    fi
done

WORKDIR="$(mktemp -d -t nats-phase1-dispatch.XXXXXX)"
trap 'rm -rf "${WORKDIR}"' EXIT

cat > "${WORKDIR}/common.head" <<EOF
log_level=3
stderror_enabled=yes
syslog_enabled=no
udp_workers=1
tcp_workers=0
socket=bin:127.0.0.1:55060

mpath="${MOD_DIR}/"

loadmodule "signaling.so"
loadmodule "sl.so"
loadmodule "tm.so"
loadmodule "maxfwd.so"
loadmodule "rr.so"
loadmodule "sipmsgops.so"
loadmodule "proto_bin.so"
loadmodule "nats_consumer.so"
modparam("nats_consumer", "fetch_batch", 10)
modparam("nats_consumer", "fetch_timeout_ms", 1000)
EOF

cat "${WORKDIR}/common.head" - > "${WORKDIR}/A.cfg" <<'EOF'

route[handle_reply] { xlog("L_INFO", "reply: $nats_data()\n"); }
route { async(nats_request("rpc.lookup", "ping", 200), handle_reply); }
EOF

cat "${WORKDIR}/common.head" - > "${WORKDIR}/B.cfg" <<'EOF'

route {
    if (nats_request("rpc.lookup", "ping", 200)) {
        xlog("L_INFO", "got reply\n");
    }
}
EOF

cat "${WORKDIR}/common.head" - > "${WORKDIR}/C.cfg" <<'EOF'

startup_route { nats_request("rpc.health", "ping", 1000); }
route { sl_send_reply(404, "no route"); }
EOF

export LD_LIBRARY_PATH="${LIB_NATS}:${LD_LIBRARY_PATH:-}"

g_fails=0
check() {
    local label="$1" cfg="$2" expect_rc="$3" expect_grep="$4"
    local out="${WORKDIR}/${label}.out"

    "${OPENSIPS_BIN}" -C -f "${cfg}" > "${out}" 2>&1
    local rc=$?

    if [ "${rc}" = "${expect_rc}" ]; then
        echo "  ok: ${label} opensips -C exit=${rc} (expected ${expect_rc})"
    else
        echo "FAIL: ${label} opensips -C exit=${rc} (expected ${expect_rc})"
        sed -n '1,12p' "${out}" >&2
        g_fails=$((g_fails + 1))
    fi

    if [ -n "${expect_grep}" ]; then
        if grep -qF "${expect_grep}" "${out}"; then
            echo "  ok: ${label} output contains \"${expect_grep}\""
        else
            echo "FAIL: ${label} output missing \"${expect_grep}\""
            sed -n '1,12p' "${out}" >&2
            g_fails=$((g_fails + 1))
        fi
    fi
}

echo "=== phase-1 dispatch ==="
check A "${WORKDIR}/A.cfg" 0   ""
check B "${WORKDIR}/B.cfg" 255 "Command <nats_request> cannot be used in the block"
check C "${WORKDIR}/C.cfg" 0   ""

if [ "${g_fails}" = 0 ]; then
    echo
    echo "=== ALL PASS (fails=0) ==="
    exit 0
fi
echo
echo "=== FAILURES (fails=${g_fails}) ==="
exit 1
