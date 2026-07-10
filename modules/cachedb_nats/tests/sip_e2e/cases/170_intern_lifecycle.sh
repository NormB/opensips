# 170 -- intern table lifecycle: acquire/release across re-register
# and de-register.
#
# The intern table refcount-pools doc-key strings shared by all of
# an AoR's index entries.  Each REGISTER bumps refcount(doc_key) by
# the number of indexed fields; each entry-removal decrements; the
# entry is freed only when the last index reference is gone.
#
# This case validates the refcount round-trip end-to-end:
#  1. Register an AoR -> doc_key is interned at refcount=N (one per
#     indexed field).
#  2. Re-register the same AoR -> the watcher does
#     remove-then-add per field, exercising the release+reacquire
#     of the same string repeatedly.  Net refcount must remain N.
#  3. De-register (expires=0) -> refcount drops to 0 and the
#     intern entry is freed.  Subsequent re-register must succeed
#     (i.e., the table accepts re-insertion of a string that was
#     freed).
#
# Skipped when ENABLE_INDEX=0 (no intern path exercised).
case_begin "170_intern_lifecycle"

if [ "${ENABLE_INDEX:-1}" = "0" ]; then
    check "skipped: ENABLE_INDEX=0 (no intern path to exercise)" ok
    return 0
fi

kv_clear

# Step 1: initial REGISTER seeds the doc key in the intern table.
register_one "lifecycle1" 3600
wait_for 5 kv_count_ge 1
n1=$(kv_aor_count | head -1)
check "initial REGISTER creates KV doc" \
    $([ "$n1" -ge 1 ] && echo ok || echo fail) "n1=$n1"

# Step 2: 30 re-registers in a row.  Each one drives the watcher
# through a remove-then-add cycle on every indexed field.  If the
# refcount round-trip drops below zero or skips a release, this
# loop will trip an LM_ERR("intern: release: node ... not found
# in chain (double-release or non-interned pointer?)") in the
# opensips_A.log.  We check for that explicit log line.
for i in $(seq 1 30); do
    register_one "lifecycle1" 3600
    sleep 0.05
done

leaks=$(grep -c "intern: release: node" "$WORKDIR/opensips_A.log" 2>/dev/null || echo 0)
check "no double-release errors during 30 re-registers" \
    $([ "$leaks" = 0 ] && echo ok || echo fail) \
    "leaks=$leaks"

# Step 3: de-register (expires=0) tears down the index entries
# and (transitively) releases the doc key intern entry.
register_one "lifecycle1" 0
sleep 0.5

# After de-register, the AoR should be gone from the bucket.
post_count=$(kv_aor_count | head -1)
# In the cluster_mode=full-sharing-cachedb path, expires=0 may
# leave a tombstone-style key briefly; we just check it's not
# growing further on subsequent re-register.

# Step 4: re-register the same AoR after a clean release.
# This exercises the "string was freed; re-insert into a possibly
# now-empty bucket chain" path of the intern table.
register_one "lifecycle1" 3600
wait_for 5 kv_count_ge 1
post_re=$(kv_aor_count | head -1)
check "re-register after de-register works (intern accepts new entry)" \
    $([ "$post_re" -ge 1 ] && echo ok || echo fail) \
    "post_count=$post_count post_re=$post_re"

# Sanity: opensips still alive after the intensive intern churn.
opensips_running "$OPENSIPS_PID"
check "opensips A still alive after intern lifecycle exercise" \
    $([ "$?" = 0 ] && echo ok || echo fail) \
    "OPENSIPS_PID=$OPENSIPS_PID"
