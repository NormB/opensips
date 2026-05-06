# 310 — concurrent kv puts: 20 keys hit the watcher event_route.
case_begin "310_kv_concurrent"

run_id=$$
pids=()
for i in $(seq 1 20); do
    kv_put TESTKV "concur-${run_id}-${i}" "v-${i}" &
    pids+=( $! )
done
# Wait ONLY for the kv_put pids, NOT the bare `wait` which would
# block on the parent opensips process.
for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done
sleep 3

# Count distinct put events for our run_id.
got=$(grep -c "E_NATS_KV_CHANGE op=put key=concur-${run_id}-" \
        "$WORKDIR/opensips.log" 2>/dev/null || echo 0)
if [ "$got" -ge 20 ]; then
    check "20 concurrent kv puts all observed by watcher" ok
else
    check "20 concurrent kv puts all observed by watcher" fail \
        "observed $got of 20"
fi
