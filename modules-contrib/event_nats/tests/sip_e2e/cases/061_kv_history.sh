# 061 — nats kv history: multiple puts on the same key produce
# multiple watcher events with increasing rev numbers.
case_begin "061_kv_history"

key="hist-$$"
for i in 1 2 3; do
    kv_put TESTKV "$key" "v${i}-${$}"
    sleep 0.4
done

# Wait for the watcher to see all three.
sleep 2

# Each put fires E_NATS_KV_CHANGE with revision increment.
seen=0
for i in 1 2 3; do
    if log_contains "E_NATS_KV_CHANGE op=put key=${key} value=v${i}-${$}"; then
        seen=$((seen + 1))
    fi
done

if [ $seen -eq 3 ]; then
    check "watcher emits 3 distinct put events for 3 revs" ok
else
    check "watcher emits 3 distinct put events for 3 revs" fail \
        "seen=$seen of 3"
fi

# Verify that history returns 3 entries via nats CLI (kv history).
hist_count=$(n kv history TESTKV "$key" 2>/dev/null | grep -c "PUT\|put") || true
if [ "$hist_count" -ge 3 ]; then
    check "nats kv history returns >= 3 entries" ok
else
    check "nats kv history returns >= 3 entries" fail "hist_count=$hist_count"
fi
