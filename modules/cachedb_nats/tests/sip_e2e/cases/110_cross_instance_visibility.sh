# 110 — Two-instance visibility: REGISTER on instance A, instance B's
# in-memory JSON index sees the new key after a settle interval (or
# immediately, since the cachedb backing is shared).
#
# This case validates the basic full-sharing-cachedb promise: two
# OpenSIPS nodes with the same cachedb_url + bucket converge on the
# same usrloc state without any clusterer-driven binary replication.
case_begin "110_cross_instance_visibility"

kv_clear

start_opensips_b
wait_for 10 mi_ready "$MI_PORT_B"
check "instance B boots" \
    $([ -n "$OPENSIPS_PID_B" ] && echo ok || echo fail) \
    "pid=$OPENSIPS_PID_B"

# Register alice on A
register_one alice 3600 "$SIP_PORT_A"
check "REGISTER alice on instance A" \
    $([ "$?" = 0 ] && echo ok || echo fail)
wait_kv_aor "alice@127.0.0.1"

# alice's KV doc must be visible to anyone reading the bucket
doc=$(kv_aor_get "alice@127.0.0.1")
echo "$doc" | grep -q '"aor":"alice@127.0.0.1"'
check "alice's KV doc readable from the shared bucket" \
    $([ "$?" = 0 ] && echo ok || echo fail) \
    "doc=$(printf '%s' "$doc" | head -c 80)..."

# Register bob on B; both A and B should now see both AoRs in the bucket
register_one bob 3600 "$SIP_PORT_B"
wait_kv_aor "bob@127.0.0.1"

bob_doc=$(kv_aor_get "bob@127.0.0.1")
echo "$bob_doc" | grep -q '"aor":"bob@127.0.0.1"'
check "bob's KV doc readable from the shared bucket" \
    $([ "$?" = 0 ] && echo ok || echo fail)

n_keys=$(kv_aor_count)
check "shared bucket holds both AoRs" \
    $([ "$n_keys" -ge 2 ] && echo ok || echo fail) "n_keys=$n_keys"

stop_opensips_b
