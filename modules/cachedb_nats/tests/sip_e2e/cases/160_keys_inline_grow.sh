# 160 -- keys[] grows past NATS_IDX_KEYS_INLINE.
#
# The single-allocation entry blob inlines an 8-slot keys[] array.
# When more than 8 distinct AoRs share the same indexed (field, value),
# _entry_add_key must (a) shm_malloc a fresh keys[] array,
# (b) memcpy the inline contents over, (c) clear the keys_inline flag,
# (d) free the new keys[] separately on _free_entry.
#
# This case drives 12 distinct AoRs from the same domain so the
# domain-field entry's keys[] is forced past the 8-slot inline limit.
# The test is a behavioural smoke test: if the inline -> external
# transition is broken (off-by-one, missing memcpy, double-free)
# the regression typically shows as either lost AoRs (KV count
# mismatch) or an opensips abort logged in the worker log.
#
# Skipped silently when ENABLE_INDEX=0 (no index, no keys[] to grow).
case_begin "160_keys_inline_grow"

if [ "${ENABLE_INDEX:-1}" = "0" ]; then
    check "skipped: ENABLE_INDEX=0 (no index path to exercise)" ok
    return 0
fi

kv_clear
sleep 0.5

# Pre-clean: capture stat baseline so a partial earlier-case state
# doesn't leak into the assertion.  kv_aor_count's `|| echo 0`
# fallback can produce multi-line output ("0\n0") when the bucket
# is empty -- pipe through head -1 to flatten before arithmetic.
before_count=$(kv_aor_count | head -1)

# Drive 12 sequential REGISTERs from distinct users that should
# all map to the same (field=domain, value=127.0.0.1) entry.  12 >
# NATS_IDX_KEYS_INLINE (8), so the inline -> external grow path must
# trigger.  Sequential not concurrent: this case is about the grow
# transition, not CAS contention (covered by 030_concurrent_reregister).
for i in $(seq 1 12); do
    register_one "growuser${i}" 3600
    sleep 0.02
done

# Each REGISTER lands one KV doc; the bucket should now hold 12 more
# json_-prefixed AoR docs than it had at case start.
after_count=$(kv_aor_count | head -1)
delta=$(( ${after_count:-0} - ${before_count:-0} ))
check "12 distinct AoRs landed despite keys[] grow transition" \
    $([ "$delta" = 12 ] && echo ok || echo fail) \
    "before=$before_count after=$after_count delta=$delta"

# Sanity-check one of the doc contents to confirm full round-trip
# (the grow code rewrites e->keys; readers must see consistent state).
doc=$(kv_aor_get "growuser5@127.0.0.1")
echo "$doc" | grep -q '"aor":"growuser5@127.0.0.1"'
check "doc readable after keys[] grow (no torn pointer)" \
    $([ "$?" = 0 ] && echo ok || echo fail) \
    "doc=$(printf '%s' "$doc" | head -c 80)..."

# opensips A must still be alive.  A double-free or off-by-one in
# the grow path typically segfaults the worker or the watcher.
opensips_running "$OPENSIPS_PID"
check "opensips A still alive after keys[] grow transition" \
    $([ "$?" = 0 ] && echo ok || echo fail) \
    "OPENSIPS_PID=$OPENSIPS_PID"

# Cleanup is left to the next case's kv_clear.
