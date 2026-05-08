# 020 — Cold-start hydration: register N users, kill opensips, restart,
# verify the KV bucket retained all N AoR docs and the new instance
# rebuilt its index from them.
#
# This is the canonical "NATS as backend store" test — the truth lives
# in JetStream KV, opensips just rehydrates from it on every cold start.
case_begin "020_cold_start_hydration"

kv_clear
sleep 0.5

# Register 5 distinct users on instance A
register_n_parallel "user" 5
sleep 0.5

before=$(kv_aor_count)
check "5 AoR docs in KV before restart" \
    $([ "$before" -ge 5 ] && echo ok || echo fail) "before=$before"

# Kill opensips A
stop_opensips_a
sleep 1

# KV should still hold the entries
between=$(kv_aor_count)
check "KV bucket persists across opensips restart" \
    $([ "$between" -ge "$before" ] && echo ok || echo fail) \
    "before=$before between=$between"

# Restart instance A — its child_init must rebuild the index from KV
start_opensips_a
sleep 1

# index_build log line records how many docs were rehydrated
indexed=$(grep -c "search index built:" "$WORKDIR/opensips.log" 2>/dev/null || echo 0)
check "new instance rebuilds the index from KV on cold start" \
    $([ "$indexed" -ge 1 ] && echo ok || echo fail) "indexed=$indexed"

# index_build line should report >=5 documents
hits=$(grep -E "search index built: ([5-9]|[1-9][0-9]+) documents" \
    "$WORKDIR/opensips.log" 2>/dev/null | wc -l)
check "rebuilt index sees the persisted AoRs" \
    $([ "$hits" -ge 1 ] && echo ok || echo fail) "hits=$hits"
