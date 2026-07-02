# 070 — [HREV-2/RC-2] seedless first insert: a cold REGISTER lands as exactly
# ONE revision (the full row, TTL attached), never the old two-step
# seed-write + CAS-update whose un-TTL'd seed revision resurrected when the
# TTL'd head expired.
case_begin "070_first_insert_seedless"

kv_clear
sleep 0.5

register_one seed070 3600
check "cold REGISTER seed070 accepted" \
    $([ "$?" = 0 ] && echo ok || echo fail)
sleep 0.5

revs=$(kv_aor_revisions "seed070@127.0.0.1")
check "AoR key holds exactly ONE revision (no standalone seed write)" \
    $([ "$revs" = 1 ] && echo ok || echo fail) "revs=$revs"

doc=$(kv_aor_get "seed070@127.0.0.1")
echo "$doc" | grep -q '"contacts"'
check "the single revision is the FULL row (has contacts), not a bare seed" \
    $([ "$?" = 0 ] && echo ok || echo fail) \
    "doc=$(printf '%s' "$doc" | head -c 120)"

echo "$doc" | grep -q '"aor":"seed070@127.0.0.1"'
check "row still carries the seed identity field" \
    $([ "$?" = 0 ] && echo ok || echo fail)

# create_doc still counts first inserts (stat semantics preserved)
stats=$(mi_cdb_stats)
cd=$(printf '%s' "$stats" | sed -n 's/.*create_doc=\([0-9]*\).*/\1/p')
check "create_doc counted the seedless first insert" \
    $([ "${cd:-0}" -ge 1 ] && echo ok || echo fail) "stats=$stats"
