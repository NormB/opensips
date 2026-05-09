# 150 — Item 4 dedicated-watcher orphan reap on master death.
#
# When the OpenSIPS master aborts after the dedicated watcher has
# been forked (e.g., a sibling module's pre-fork hook fails, or
# anything that triggers an unclean exit before destroy() runs),
# the kernel must reap the watcher.  Without PR_SET_PDEATHSIG the
# watcher is reparented to PID 1 and runs forever, racing the next
# OpenSIPS startup which allocates fresh SHM that the stale watcher
# is still writing to.
#
# This case spins up its own opensips on isolated ports
# (independent of the suite's instance A/B), forces
# DEDICATED_WATCHER=1 regardless of the suite-level env, finds the
# real master PID via /proc/<watcher>/status (OpenSIPS double-forks
# at startup, so $! from `&` is the bootstrap, not the master),
# SIGKILLs the master, and asserts the watcher dies within 5s.
#
# Skipped silently when ENABLE_INDEX=0 (no dedicated proc to test)
# or when the suite doesn't have permission to fork an extra
# opensips on these ports.
case_begin "150_orphan_watcher_reap"

if [ "${ENABLE_INDEX:-1}" = "0" ]; then
    check "skipped: ENABLE_INDEX=0 (no dedicated proc to test)" ok
    return 0
fi

ORPHAN_SIP_PORT=5078
ORPHAN_MI_PORT=8895
ORPHAN_CLUSTER_PORT=5669
ORPHAN_CFG="$WORKDIR/opensips_orphan.cfg"
ORPHAN_LOG="$WORKDIR/opensips_orphan.log"

sed -e "s|@@MODULES@@|${OPENSIPS_MODULES}|g" \
    -e "s|@@NATS_URL@@|${NATS_URL}|g" \
    -e "s|@@CACHEDB_URL@@|${CACHEDB_URL}|g" \
    -e "s|@@SIP_PORT@@|${ORPHAN_SIP_PORT}|g" \
    -e "s|@@MI_PORT@@|${ORPHAN_MI_PORT}|g" \
    -e "s|@@CLUSTER_PORT@@|${ORPHAN_CLUSTER_PORT}|g" \
    -e "s|@@NODE_ID@@|7|g" \
    -e "s|@@KV_BUCKET@@|${KV_BUCKET}|g" \
    -e "s|@@INSTANCE@@|ORPHAN|g" \
    -e "s|@@ENABLE_INDEX@@|1|g" \
    -e "s|@@INDEX_BUCKETS@@|4096|g" \
    -e "s|@@DEDICATED_WATCHER@@|1|g" \
    "${HERE}/opensips.cfg.in" > "$ORPHAN_CFG"

# Start opensips directly (no wrapper traps).  Keep stdout / stderr
# in a per-case log so we can post-mortem on failure.
LD_LIBRARY_PATH="${OPENSIPS_LIB_NATS}:${LD_LIBRARY_PATH:-}" \
    "$OPENSIPS_BIN" -F -f "$ORPHAN_CFG" -s HP_MALLOC -m 256 -M 8 \
    > "$ORPHAN_LOG" 2>&1 &

# Wait for the watcher proc to log its own startup.  We need its pid
# to find the actual master (OpenSIPS daemonizes via a bootstrap
# fork, so $! from `&` is the bootstrap that exits seconds later, not
# the long-lived master).
WATCHER=""
for i in $(seq 1 20); do
    # Pin the digit run with sed -- grep -oE "(pid=[0-9]+" leaves
    # the literal "(pid=" prefix, and earlier attempts using `tr`
    # to strip non-digits left whitespace from neighbouring tokens.
    # sed is the unambiguous extraction here.
    WATCHER=$(sed -nE 's/.*watcher proc starting \(pid=([0-9]+).*/\1/p' \
        "$ORPHAN_LOG" 2>/dev/null | tail -1)
    [ -n "$WATCHER" ] && break
    sleep 0.5
done

if [ -z "$WATCHER" ]; then
    check "dedicated watcher proc forked + logged startup" fail \
        "log tail: $(tail -20 "$ORPHAN_LOG" | tr '\n' ' ')"
    pkill -9 -f "opensips -F -f $ORPHAN_CFG" 2>/dev/null
    return 0
fi
check "dedicated watcher proc forked + logged startup" ok \
    "watcher pid=$WATCHER"

# Real master = watcher's parent.  /proc/<pid>/status PPid: line is
# the canonical kernel-truth source.
MASTER=$(awk '/^PPid:/ {print $2; exit}' "/proc/$WATCHER/status" 2>/dev/null)
if [ -z "$MASTER" ] || ! kill -0 "$MASTER" 2>/dev/null; then
    check "located live master process" fail \
        "watcher=$WATCHER ppid_lookup='$MASTER'"
    pkill -9 -f "opensips -F -f $ORPHAN_CFG" 2>/dev/null
    return 0
fi
check "located live master process" ok "master pid=$MASTER"

# SIGKILL: bypass any signal handlers, simulating the worst-case
# crash scenario.  Real-world equivalents: OOM kill, kernel panic,
# operator pkill -9.  All collapse to "master suddenly gone."
kill -9 "$MASTER" 2>/dev/null

# Watcher should be reaped within ~1s by PR_SET_PDEATHSIG SIGKILL.
# The 5s timeout is generous; on a healthy system this fires in
# <100ms.  If it doesn't fire, the inner-loop getppid()==1 polling
# backstop catches it on the next 500ms tick.
DEADLINE=$(($(date +%s) + 5))
REAPED=fail
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if ! kill -0 "$WATCHER" 2>/dev/null; then
        REAPED=ok
        break
    fi
    sleep 0.2
done
check "watcher reaped within 5s of master SIGKILL" "$REAPED" \
    "watcher pid=$WATCHER ppid_at_check=$(awk '/^PPid:/ {print $2}' /proc/$WATCHER/status 2>/dev/null)"

# Belt-and-suspenders: if it's still alive, kill it so the suite
# doesn't leave an orphan polluting the next case.
if kill -0 "$WATCHER" 2>/dev/null; then
    kill -9 "$WATCHER" 2>/dev/null
fi
pkill -9 -f "opensips -F -f $ORPHAN_CFG" 2>/dev/null

# Bucket cleanup -- the case used the suite's KV_BUCKET so just let
# the next kv_clear in the test loop handle it.
