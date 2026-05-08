# 010 — REGISTER roundtrip: SIP REGISTER → usrloc save → cachedb_nats
# write → key visible in JetStream KV with the expected AoR identity.
#
# In cluster_mode=full-sharing-cachedb the in-memory urecord is freed
# after flush, so ul_dump is always empty; the truth lives in the KV.
case_begin "010_register_roundtrip"

kv_clear
sleep 0.5

register_one alice 3600
rc=$?
check "sipsak REGISTER alice exits 0" \
    $([ "$rc" = 0 ] && echo ok || echo fail) "rc=$rc"

sleep 0.5

# KV bucket should have one json_-prefixed doc
n_keys=$(kv_aor_count)
check "JetStream KV holds one AoR doc" \
    $([ "$n_keys" -ge 1 ] && echo ok || echo fail) "n_keys=$n_keys"

# The alice doc must contain the original (unencoded) AoR identity
doc=$(kv_aor_get "alice@127.0.0.1")
echo "$doc" | grep -q '"aor":"alice@127.0.0.1"'
check "alice doc carries the SIP-form AoR identity" \
    $([ "$?" = 0 ] && echo ok || echo fail) "doc=$(printf '%s' "$doc" | head -c 120)..."

# create_doc counter bumped at least once
stats=$(mi_cdb_stats)
cd=$(printf '%s' "$stats" | sed -n 's/.*create_doc=\([0-9]*\).*/\1/p')
check "nats_cdb_stats.create_doc bumped on first REGISTER" \
    $([ "${cd:-0}" -ge 1 ] && echo ok || echo fail) "stats=$stats"
