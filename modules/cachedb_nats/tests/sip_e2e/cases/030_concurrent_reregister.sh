# 030 — Concurrent REGISTERs for the same AoR drive CAS contention.
# Acceptance: cas_exhausted == 0 (the configured budget + jittered
# backoff is sufficient for a contended single-AoR storm), and the
# AoR's KV doc exists with one contact recorded.
case_begin "030_concurrent_reregister"

kv_clear
sleep 0.5

before_stats=$(mi_cdb_stats)
before_retry=$(printf '%s' "$before_stats" | sed -n 's/.*cas_retry=\([0-9]*\).*/\1/p')
before_exhausted=$(printf '%s' "$before_stats" | sed -n 's/.*cas_exhausted=\([0-9]*\).*/\1/p')

# Fire 20 concurrent re-REGISTERs for the same AoR
register_same_aor_concurrent contended 20
sleep 1

after_stats=$(mi_cdb_stats)
after_retry=$(printf '%s' "$after_stats" | sed -n 's/.*cas_retry=\([0-9]*\).*/\1/p')
after_exhausted=$(printf '%s' "$after_stats" | sed -n 's/.*cas_exhausted=\([0-9]*\).*/\1/p')

retry_delta=$(( ${after_retry:-0} - ${before_retry:-0} ))
exh_delta=$(( ${after_exhausted:-0} - ${before_exhausted:-0} ))

check "no CAS exhaustion under contended REGISTER storm" \
    $([ "$exh_delta" = 0 ] && echo ok || echo fail) \
    "exh_delta=$exh_delta"

# The contended AoR should have exactly one KV doc
doc=$(kv_aor_get "contended@127.0.0.1")
echo "$doc" | grep -q '"aor":"contended@127.0.0.1"'
check "contended AoR has a KV doc with the right identity" \
    $([ "$?" = 0 ] && echo ok || echo fail) \
    "doc=$(printf '%s' "$doc" | head -c 80)..."

# All 20 sipsak processes should have hit the same KV doc, so the bucket
# must hold exactly one json_-prefixed key for this AoR
n_keys=$(kv_aor_count)
check "exactly one AoR doc after the storm" \
    $([ "$n_keys" = 1 ] && echo ok || echo fail) "n_keys=$n_keys"

echo "  info: cas_retry delta=$retry_delta exhausted delta=$exh_delta"
