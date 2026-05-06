#!/bin/bash
# End-to-end test for the bidirectional SIP <-> NATS path.
#
#   A) sipp REGISTER -> opensips route -> nats_publish ->
#      `nats sub test.sip.register` reader sees the payload.
#
#   B) `nats kv put TESTKV <key> <value>` ->
#      cachedb_nats KV watcher pthread (rank-1 worker) ->
#      ipc_dispatch_rpc -> SIP worker raises E_NATS_KV_CHANGE ->
#      event_route[E_NATS_KV_CHANGE] xlog.
#
# Required tools on $PATH:
#   - opensips  (binary built from this branch)
#   - sipp      (3.x; tested with 3.7.2)
#   - nats      (CLI; https://github.com/nats-io/natscli)
#   - docker    (used only to launch a throw-away nats:2.10-alpine
#                container if no broker is reachable on $NATS_URL)
#
# Environment overrides:
#   OPENSIPS_BIN       path to the opensips binary
#                      (default: ../../../../opensips, i.e. the
#                      build tree's top-level binary)
#   OPENSIPS_LIB_NATS  directory containing libnats_pool.so
#                      (default: ../../../../lib/nats)
#   OPENSIPS_MODULES   directory containing flat-symlinked module
#                      .so files (default: ../../../../_modules)
#   NATS_URL           NATS server URL
#                      (default: nats://127.0.0.1:4322)
#
# Exit:
#   0 if both directions pass; non-zero with detail otherwise.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
TREE_ROOT="$(cd "${HERE}/../../../.." && pwd)"

OPENSIPS_BIN="${OPENSIPS_BIN:-${TREE_ROOT}/opensips}"
OPENSIPS_LIB_NATS="${OPENSIPS_LIB_NATS:-${TREE_ROOT}/lib/nats}"
OPENSIPS_MODULES="${OPENSIPS_MODULES:-${TREE_ROOT}/_modules}"
NATS_URL="${NATS_URL:-nats://127.0.0.1:4322}"

WORKDIR="$(mktemp -d -t sip-nats-e2e.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

PASS=0
FAIL=0
note()   { echo "[$(date +%H:%M:%S)] $*"; }
record() {
    local name=$1 ok=$2
    if [ "$ok" = ok ]; then echo "  PASS: $name"; PASS=$((PASS+1))
    else echo "  FAIL: $name"; FAIL=$((FAIL+1))
    fi
}

# ─── prerequisite checks ─────────────────────────────────────────
need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing required tool: $1"
        exit 77   # autotools "skip" code; CI can detect
    }
}
need sipp; need nats

if [ ! -x "$OPENSIPS_BIN" ]; then
    echo "opensips binary not found at $OPENSIPS_BIN"
    echo "  build the tree first, or set OPENSIPS_BIN"
    exit 77
fi
if [ ! -d "$OPENSIPS_MODULES" ]; then
    echo "module directory not found at $OPENSIPS_MODULES"
    echo "  build the tree first, or set OPENSIPS_MODULES"
    echo "  (run.sh expects flat-symlinked module .so files; mkdir +"
    echo "   ln -sf modules/*/*.so lib/nats/libnats_pool.so works)"
    exit 77
fi

# ─── ensure a NATS broker is reachable ───────────────────────────
if ! nats --server "$NATS_URL" server check connection \
        > "$WORKDIR/conn.out" 2>&1; then
    note "no NATS broker on $NATS_URL; starting throw-away container"
    need docker
    NATS_PORT="${NATS_URL##*:}"
    NATS_PORT="${NATS_PORT%%/*}"
    docker run -d --rm --name sip-nats-e2e-natstest \
        -p "${NATS_PORT}:4222" nats:2.10-alpine -js >/dev/null
    trap 'docker rm -f sip-nats-e2e-natstest >/dev/null 2>&1; rm -rf "$WORKDIR"' EXIT
    for i in 1 2 3 4 5 6 7 8 9 10; do
        nats --server "$NATS_URL" server check connection \
            >/dev/null 2>&1 && break
        sleep 1
    done
fi

# Ensure the TESTKV bucket exists.  Idempotent.
nats --server "$NATS_URL" kv add TESTKV --history=5 --replicas=1 \
    > "$WORKDIR/kv_add.out" 2>&1 || true

# ─── render opensips.cfg from template ───────────────────────────
sed -e "s|@@MODULES@@|${OPENSIPS_MODULES}|g" \
    -e "s|@@NATS_URL@@|${NATS_URL}|g" \
    "${HERE}/opensips.cfg.in" > "$WORKDIR/opensips.cfg"

# ─── start opensips ──────────────────────────────────────────────
note "starting opensips"
LD_LIBRARY_PATH="${OPENSIPS_LIB_NATS}:${LD_LIBRARY_PATH:-}" \
    "$OPENSIPS_BIN" -F -f "$WORKDIR/opensips.cfg" -m 64 -M 4 \
    > "$WORKDIR/opensips.log" 2>&1 &
OPENSIPS_PID=$!
sleep 3

if ! kill -0 "$OPENSIPS_PID" 2>/dev/null; then
    echo "FATAL: opensips died on startup"
    tail -25 "$WORKDIR/opensips.log"
    exit 1
fi

cleanup() {
    [ -n "${OPENSIPS_PID:-}" ] && kill "$OPENSIPS_PID" 2>/dev/null
    [ -n "${SUB_PID:-}" ] && kill "$SUB_PID" 2>/dev/null
    docker rm -f sip-nats-e2e-natstest >/dev/null 2>&1 || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# ─── Direction A: SIP -> NATS ────────────────────────────────────
note "[A] subscribe to test.sip.register, send SIP REGISTER via sipp"
nats --server "$NATS_URL" sub "test.sip.register" --count=1 \
    > "$WORKDIR/sub.out" 2>&1 &
SUB_PID=$!
sleep 1

sipp -sf "${HERE}/sipp_register.xml" -m 1 -r 1 -i 127.0.0.1 -p 5071 \
     -timeout 10s -nostdin \
     127.0.0.1:5072 > "$WORKDIR/sipp.out" 2>&1
note "  sipp exit=$?"

for i in 1 2 3 4 5; do
    kill -0 "$SUB_PID" 2>/dev/null || break
    sleep 1
done

if grep -q 'method=REGISTER' "$WORKDIR/sub.out" && \
   grep -q 'from=sipp' "$WORKDIR/sub.out"; then
    record "Direction A: SIP REGISTER -> opensips -> nats_publish" ok
else
    record "Direction A: SIP REGISTER -> opensips -> nats_publish" fail
    echo "    sub.out:"; sed 's/^/      /' "$WORKDIR/sub.out"
fi

# ─── Direction B: NATS KV -> watcher -> event_route ──────────────
KEY="sipuser-$(date +%s%N)"
VAL="alice-$(date +%s%N)"
note "[B] kv put TESTKV/${KEY}=${VAL}, await event_route xlog"
nats --server "$NATS_URL" kv put TESTKV "$KEY" "$VAL" \
    > "$WORKDIR/kv_put.out" 2>&1 || true
sleep 3

if grep -q "E_NATS_KV_CHANGE op=put key=${KEY} value=${VAL}" \
        "$WORKDIR/opensips.log"; then
    record "Direction B: NATS KV put -> watcher -> event_route" ok
else
    record "Direction B: NATS KV put -> watcher -> event_route" fail
    echo "    looking for: E_NATS_KV_CHANGE op=put key=${KEY} value=${VAL}"
    echo "    opensips.log tail:"
    tail -25 "$WORKDIR/opensips.log" | sed 's/^/      /'
fi

echo
echo "=== summary: pass=$PASS fail=$FAIL ==="
exit $FAIL
