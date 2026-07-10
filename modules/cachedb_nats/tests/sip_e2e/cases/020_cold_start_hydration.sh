# 020 — Cold-start hydration: register N users, kill opensips, restart,
# verify the KV bucket retained all N AoR docs and the new instance
# rebuilt its index from them.
#
# This is the canonical "NATS as backend store" test — the truth lives
# in JetStream KV, opensips just rehydrates from it on every cold start.
case_begin "020_cold_start_hydration"

kv_clear

# Register 5 distinct users on instance A
register_n_parallel "user" 5
wait_for 5 kv_count_ge 5

before=$(kv_aor_count)
check "5 AoR docs in KV before restart" \
    $([ "$before" -ge 5 ] && echo ok || echo fail) "before=$before"

# Kill opensips A
stop_opensips_a

# KV should still hold the entries
between=$(kv_aor_count)
check "KV bucket persists across opensips restart" \
    $([ "$between" -ge "$before" ] && echo ok || echo fail) \
    "before=$before between=$between"

# Restart instance A — its child_init must rebuild the index from KV
start_opensips_a
wait_for 10 mi_ready

# When the index is enabled, child_init logs the number of docs
# it rehydrated from KV.  When ENABLE_INDEX=0 the module skips the
# index entirely and there's nothing to rebuild -- the canonical
# "NATS as backend store" property still holds because reads go
# through the PK fast path against KV directly, so we assert that
# instead.
if [ "${ENABLE_INDEX:-1}" = "0" ]; then
    disabled=$(grep -c "cachedb_nats_fts not loaded; query/update accept PK-only" \
        "$WORKDIR/opensips.log" 2>/dev/null || echo 0)
    check "restart skips index build when index is disabled" \
        $([ "$disabled" -ge 1 ] && echo ok || echo fail) \
        "disabled_logs=$disabled"
    after=$(kv_aor_count)
    check "KV-side AoRs still present after restart (PK path will serve them)" \
        $([ "$after" -ge "$before" ] && echo ok || echo fail) \
        "before=$before after=$after"
else
    # index_build log line records how many docs were rehydrated
    indexed=$(grep -c "search index built:" \
        "$WORKDIR/opensips.log" 2>/dev/null || echo 0)
    check "new instance rebuilds the index from KV on cold start" \
        $([ "$indexed" -ge 1 ] && echo ok || echo fail) \
        "indexed=$indexed"

    # index_build line should report >=5 documents
    hits=$(grep -E "search index built: ([5-9]|[1-9][0-9]+) documents" \
        "$WORKDIR/opensips.log" 2>/dev/null | wc -l)
    check "rebuilt index sees the persisted AoRs" \
        $([ "$hits" -ge 1 ] && echo ok || echo fail) "hits=$hits"
fi
