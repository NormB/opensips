# nats_local_lib.sh -- shared helpers for NATS module integration tests
# that run against a host-local nats-server (NOT the docker-compose stack
# under modules/nats_consumer/tests/).
#
# Sourced, not run.  Tests skip with exit 77 (autotools "skip") if any
# prerequisite is missing.
#
# Required tools on PATH:
#   - nats         (NATS CLI)
#   - nats-server  (broker, used by tests that start their own private instance)
#   - opensips     (the freshly built binary; located via OPENSIPS_BIN)
#
# Required env (auto-populated if unset):
#   OPENSIPS_BIN     -- path to opensips binary       [auto: ../../../opensips]
#   OPENSIPS_MPATH   -- module search path             [auto: ../../../modules]
#   OPENSIPS_LIBDIR  -- $LD_LIBRARY_PATH for libnats_pool.so [auto: ../../../lib/nats]
#   NATS_URL         -- shared cluster URL              [default: nats://127.0.0.1:4222]

set -u

# --- locate repo paths from the sourcing test's directory ---------------
_local_lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${_local_lib_dir}/../../.." && pwd)"
: "${OPENSIPS_BIN:=${REPO_ROOT}/opensips}"
: "${OPENSIPS_MPATH:=${REPO_ROOT}/modules}"
: "${OPENSIPS_LIBDIR:=${REPO_ROOT}/lib/nats}"
: "${NATS_URL:=nats://127.0.0.1:4222}"

# /usr/local/lib is where the upstream `cmake --install` for libnats
# lands by default; on hosts that also have a stale libnats from a
# system package (e.g., libnats3.7 in /lib/aarch64-linux-gnu) the
# upstream-installed version wins via this path order.  Without
# this, nats_dl_load picks the system libnats whose older minor
# version is missing kvStore_WatchMulti, kvStore_WatchAll, and other
# symbols added in 3.10+.
export LD_LIBRARY_PATH="${OPENSIPS_LIBDIR}:/usr/local/lib:${LD_LIBRARY_PATH:-}"

# --- skip / fail helpers -------------------------------------------------
skip() { echo "SKIP: $*"; exit 77; }
pass() { echo "PASS: $*"; exit 0; }
fail() { echo "FAIL: $*"; exit 1; }

require_cmd() {
    local c
    for c in "$@"; do
        command -v "${c}" >/dev/null 2>&1 || skip "missing tool: ${c}"
    done
}

require_opensips_built() {
    [ -x "${OPENSIPS_BIN}" ] || skip "opensips binary not found at ${OPENSIPS_BIN} -- run 'make' at repo root"
    [ -f "${OPENSIPS_LIBDIR}/libnats_pool.so" ] || \
        skip "libnats_pool.so not built at ${OPENSIPS_LIBDIR}"
}

require_nats_reachable() {
    require_cmd nats
    nats --server "${NATS_URL}" rtt --timeout 2s >/dev/null 2>&1 || \
        skip "no NATS server reachable at ${NATS_URL}"
}

# --- per-test workspace --------------------------------------------------
# Each test gets a unique /tmp dir that's cleaned up on EXIT.
mkworkdir() {
    local prefix="${1:-natstest}"
    WORK="$(mktemp -d "/tmp/${prefix}.XXXXXX")"
    OPS_LOG="${WORK}/opensips.log"
    OPS_FIFO="${WORK}/opensips_fifo"
    OPS_PID=""
    trap 'cleanup_workdir' EXIT
    echo "${WORK}"
}

cleanup_workdir() {
    [ -n "${OPS_PID:-}" ] && kill "${OPS_PID}" 2>/dev/null || true
    sleep 0.5
    [ -n "${OPS_PID:-}" ] && kill -9 "${OPS_PID}" 2>/dev/null || true
    [ -n "${PRIVATE_NATS_PID:-}" ] && kill "${PRIVATE_NATS_PID}" 2>/dev/null || true
    rm -rf "${WORK:-/no-such-dir}"
}

# --- opensips lifecycle --------------------------------------------------
start_opensips() {
    local cfg="$1"
    "${OPENSIPS_BIN}" -F -f "${cfg}" >"${OPS_LOG}" 2>&1 &
    OPS_PID=$!
    # Spin up to 5s for the FIFO to appear (mi_fifo creates it from a worker).
    local i
    for i in $(seq 1 50); do
        [ -p "${OPS_FIFO}" ] && return 0
        sleep 0.1
    done
    fail "opensips did not create FIFO ${OPS_FIFO} within 5s; log:\n$(tail -20 "${OPS_LOG}")"
}

stop_opensips() {
    [ -n "${OPS_PID:-}" ] || return 0
    kill "${OPS_PID}" 2>/dev/null || true
    local i
    for i in $(seq 1 50); do
        kill -0 "${OPS_PID}" 2>/dev/null || { OPS_PID=""; return 0; }
        sleep 0.1
    done
    kill -9 "${OPS_PID}" 2>/dev/null || true
    OPS_PID=""
}

assert_opensips_alive() {
    [ -n "${OPS_PID:-}" ] && kill -0 "${OPS_PID}" 2>/dev/null || \
        fail "opensips died unexpectedly; log:\n$(tail -40 "${OPS_LOG}")"
}

# --- MI over FIFO (JSON-RPC) --------------------------------------------
# Reply files must live in /tmp/ and have no '.', '/', '\' (mi_fifo restriction).
# We create one per call as a named pipe and read it to a buffer.
mi_call() {
    local method="$1"; shift
    local params_json="${1:-}"
    local reply_id; reply_id="r$(printf '%(%N)T' -1)$$"
    local reply_path="/tmp/${reply_id}"
    rm -f "${reply_path}"
    mkfifo "${reply_path}"
    ( timeout 5 cat "${reply_path}" ) > "${WORK}/mi_reply.${reply_id}" 2>&1 &
    local rcat=$!

    if [ -n "${params_json}" ]; then
        printf ':%s:{"jsonrpc":"2.0","id":1,"method":"%s","params":%s}\n' \
            "${reply_id}" "${method}" "${params_json}" > "${OPS_FIFO}"
    else
        printf ':%s:{"jsonrpc":"2.0","id":1,"method":"%s"}\n' \
            "${reply_id}" "${method}" > "${OPS_FIFO}"
    fi
    wait "${rcat}" 2>/dev/null || true
    rm -f "${reply_path}"
    cat "${WORK}/mi_reply.${reply_id}"
}

# --- log assertions ------------------------------------------------------
log_contains() { grep -qE "$1" "${OPS_LOG}"; }
wait_for_log() {
    local pattern="$1"; local secs="${2:-10}"
    local i
    for i in $(seq 1 $((secs * 10))); do
        log_contains "${pattern}" && return 0
        sleep 0.1
    done
    return 1
}

# --- private nats-server (used by the disconnect test) ------------------
start_private_nats() {
    local port="${1:-14222}"
    local jsdir="${WORK}/jetstream"
    mkdir -p "${jsdir}"
    nats-server --port "${port}" --js --store_dir "${jsdir}" \
        --pid "${WORK}/nats.pid" --log "${WORK}/nats.log" --addr 127.0.0.1 \
        > "${WORK}/nats.stdout" 2>&1 &
    PRIVATE_NATS_PID=$!
    PRIVATE_NATS_URL="nats://127.0.0.1:${port}"
    # wait for accept
    local i
    for i in $(seq 1 50); do
        nats --server "${PRIVATE_NATS_URL}" rtt --timeout 200ms >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    fail "private nats-server did not become reachable on ${PRIVATE_NATS_URL}; log:\n$(cat "${WORK}/nats.log" 2>/dev/null)"
}

stop_private_nats() {
    [ -n "${PRIVATE_NATS_PID:-}" ] || return 0
    kill "${PRIVATE_NATS_PID}" 2>/dev/null || true
    wait "${PRIVATE_NATS_PID}" 2>/dev/null || true
    PRIVATE_NATS_PID=""
}
