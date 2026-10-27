# 120 — Concurrent same-AoR REGISTERs from two instances exercise
# inter-instance CAS contention. The CAS retry loop in
# nats_cache_update is the only synchronization between A and B for
# this AoR; if the backoff + retry budget is well-tuned, both
# REGISTERs succeed (last-write-wins via revision) with zero
# exhaustion and exactly one final KV doc.
case_begin "120_concurrent_two_instances"

kv_clear

start_opensips_b
wait_for 10 mi_ready "$MI_PORT_B"
check "instance B boots" \
    $([ -n "$OPENSIPS_PID_B" ] && echo ok || echo fail)

# Capture cas_retry baselines from both instances
a_before=$(mi_cdb_stats "$MI_PORT_A")
b_before=$(mi_cdb_stats "$MI_PORT_B")
a_retry_before=$(printf '%s' "$a_before" | sed -n 's/.*cas_retry=\([0-9]*\).*/\1/p')
b_retry_before=$(printf '%s' "$b_before" | sed -n 's/.*cas_retry=\([0-9]*\).*/\1/p')

# Fire 10 REGISTERs at A and 10 at B, all for the same AoR, in parallel
pids=""
for i in $(seq 1 10); do
    register_one shared 3600 "$SIP_PORT_A" &
    pids="$pids $!"
done
for i in $(seq 1 10); do
    register_one shared 3600 "$SIP_PORT_B" &
    pids="$pids $!"
done
for p in $pids; do wait "$p"; done
wait_kv_aor "shared@127.0.0.1"

a_after=$(mi_cdb_stats "$MI_PORT_A")
b_after=$(mi_cdb_stats "$MI_PORT_B")
a_retry_after=$(printf '%s' "$a_after" | sed -n 's/.*cas_retry=\([0-9]*\).*/\1/p')
b_retry_after=$(printf '%s' "$b_after" | sed -n 's/.*cas_retry=\([0-9]*\).*/\1/p')
a_exh=$(printf '%s' "$a_after" | sed -n 's/.*cas_exhausted=\([0-9]*\).*/\1/p')
b_exh=$(printf '%s' "$b_after" | sed -n 's/.*cas_exhausted=\([0-9]*\).*/\1/p')

a_delta=$(( ${a_retry_after:-0} - ${a_retry_before:-0} ))
b_delta=$(( ${b_retry_after:-0} - ${b_retry_before:-0} ))
total_exh=$(( ${a_exh:-0} + ${b_exh:-0} ))

check "neither instance exhausts CAS budget" \
    $([ "$total_exh" = 0 ] && echo ok || echo fail) \
    "a_exh=${a_exh:-0} b_exh=${b_exh:-0}"

# Exactly one shared AoR doc in the bucket
n_keys=$(kv_aor_count)
check "exactly one AoR doc despite cross-instance contention" \
    $([ "$n_keys" = 1 ] && echo ok || echo fail) "n_keys=$n_keys"

# The doc identity is intact
doc=$(kv_aor_get "shared@127.0.0.1")
echo "$doc" | grep -q '"aor":"shared@127.0.0.1"'
check "shared AoR doc has the right identity" \
    $([ "$?" = 0 ] && echo ok || echo fail)

echo "  info: cas_retry deltas A=$a_delta B=$b_delta exhausted=$total_exh"

stop_opensips_b
