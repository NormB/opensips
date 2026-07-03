# 060 — history-keeping bucket under reaper-only expiry (P1.5): on a
# PRE-EXISTING bucket that keeps old revisions (MaxMsgsPerSubject=3) the
# reaper must reclaim an expired row cleanly — CAS-prune then delete, with
# NO revision rollback resurrecting an older doc (the failure mode that
# made the deleted native-TTL path unsafe on history buckets, spec §0 E1).
# Runs with a 5 s reaper so the bound (expires + grace + 2*interval)
# stays testable.
case_begin "060_ttl_history_gate"

stop_opensips_a

# a TTL-capable but history-keeping bucket -- exactly the misconfiguration
"$KVCTL" rm "$NATS_URL" "$KV_BUCKET" >/dev/null 2>&1
"$KVCTL" mk "$NATS_URL" "$KV_BUCKET" 3 30 >/dev/null 2>&1
check "history=3 bucket created" $([ "$?" = 0 ] && echo ok || echo fail)

REAP_INTERVAL=5 start_opensips_a
sleep 1

register_one ttl060 3
check "REGISTER ttl060 expires=3 accepted" \
    $([ "$?" = 0 ] && echo ok || echo fail)
sleep 0.5

doc=$(kv_aor_get "ttl060@127.0.0.1")
check "doc present right after REGISTER" \
    $([ -n "$doc" ] && echo ok || echo fail)

# reaper-only reclamation: expires(3) + grace(5) + 2*interval(5) + slack
wait_kv_gone "ttl060@127.0.0.1" 30
check "reaper reclaimed the row on the history bucket (no rollback doc)" \
    $([ "$?" = 0 ] && echo ok || echo fail) \
    "doc=$(kv_aor_get "ttl060@127.0.0.1" | head -c 80)"

n_keys=$(kv_aor_count)
check "no rolled-back/leftover AoR key remains" \
    $([ "$n_keys" = 0 ] && echo ok || echo fail) "n_keys=$n_keys"

# restore: default-shaped bucket (history=1) + default instance
stop_opensips_a
kv_clear
start_opensips_a
sleep 1
