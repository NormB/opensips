# 085 — [REV-6/F6] multi-contact row with UNIFORM expiry: the all_same
# eligibility arm.  Two contacts sharing one absolute expiry are safe under a
# single row TTL (nothing live gets tombstoned), so the write MUST carry
# no Nats-TTL (reaper-only, P1.5); the reaper reclaims the whole row
# (this runs on the default 30 s reaper; native TTL beats its first tick).
case_begin "085_multi_contact_same_expiry"

kv_clear
sleep 0.5

# Same expires on both REGISTERs.  The stored absolute expiry is computed
# per-write (now+6), so both must land within one wall-clock second or the
# row is mixed (ineligible) and the whole case would test the wrong arm.
# Retry the pair (bounded) until the stored expires values are equal.
rc1=1; rc2=1; t0=0
for attempt in 1 2 3; do
    register_contact ms085 6083 6; rc1=$?
    register_contact ms085 6084 6; rc2=$?
    t0=$(date +%s)
    sleep 0.5
    n_exp=$(kv_aor_get "ms085@127.0.0.1" \
        | grep -o '"expires":[0-9]*' | sort -u | wc -l)
    [ "$rc1" = 0 ] && [ "$rc2" = 0 ] && [ "$n_exp" = 1 ] && break
    echo "  (attempt $attempt: expires values differ / rc=$rc1,$rc2 -- retrying)"
done
check "both REGISTERs (expires=6, contacts 6083/6084) accepted with EQUAL expiry" \
    $([ "$rc1" = 0 ] && [ "$rc2" = 0 ] && [ "$n_exp" = 1 ] && echo ok || echo fail) \
    "rc1=$rc1 rc2=$rc2 distinct_expires=$n_exp"

doc=$(kv_aor_get "ms085@127.0.0.1")
echo "$doc" | grep -q '127.0.0.1:6083' && echo "$doc" | grep -q '127.0.0.1:6084'
check "row holds BOTH contacts" \
    $([ "$?" = 0 ] && echo ok || echo fail) \
    "doc=$(printf '%s' "$doc" | head -c 160)"

hdrs=$(kv_last_headers "ms085@127.0.0.1")
echo "$hdrs" | grep -q "Nats-TTL"
check "uniform-expiry multi-contact write carries NO Nats-TTL (reaper-only)" \
    $([ "$?" != 0 ] && echo ok || echo fail) "hdrs=$hdrs"

vis=$(probe_binding ms085)
check "lookup serves while live (202)" \
    $([ "$vis" = 202 ] && echo ok || echo fail) "vis=$vis"

# expires(6) + grace(5) = native TTL ~11 s; well before the 30 s reaper tick
wait_kv_gone "ms085@127.0.0.1" 45
check "whole row reclaimed by the reaper (gone by expires+grace+interval)" \
    $([ "$?" = 0 ] && echo ok || echo fail) \
    "doc=$(kv_aor_get "ms085@127.0.0.1" | head -c 80)"

vis=$(probe_binding ms085)
check "no binding served after expiry (404)" \
    $([ "$vis" = 404 ] && echo ok || echo fail) "vis=$vis"
