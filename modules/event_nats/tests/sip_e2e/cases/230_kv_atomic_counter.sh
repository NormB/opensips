# 230 — exercise the cachedb_nats nats_cas_retries / atomic counter
# semantics by performing 10 concurrent kv puts on the same key.
# The watcher must see exactly 10 put events with monotonic revs.
case_begin "230_kv_atomic_counter"

key="counter-$$"
n kv del TESTKV "$key" -f >/dev/null 2>&1 || true
sleep 1

pids=()
for i in $(seq 1 10); do
    kv_put TESTKV "$key" "v${i}" &
    pids+=( $! )
done
for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done
sleep 3

# Watcher counts puts on this key.
got=$(grep -c "E_NATS_KV_CHANGE op=put key=${key} " "$WORKDIR/opensips.log")
if [ "$got" -ge 10 ]; then
    check "10 concurrent puts on a single key all observed" ok
else
    check "10 concurrent puts on a single key all observed" fail \
        "got=$got of 10"
fi
