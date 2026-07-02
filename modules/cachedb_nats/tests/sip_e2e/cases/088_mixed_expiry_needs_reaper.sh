# 088 — FAILURE-MODE probe [REV-2/PREV-26]: WHY the reaper is refused-off by
# default.  With nats_reap_interval=0 (acknowledged via nats_unsafe_ttl_only,
# TTL-only mode):
#
#   - an ELIGIBLE row (single contact) still self-expires via its native TTL
#     -- the acknowledged mode works for what it covers;
#   - an INELIGIBLE mixed-expiry row is written with NO TTL and NOTHING ever
#     physically reclaims it: the documented leak, demonstrated live.  SIP
#     stays correct throughout (the read filter hides expired contacts), so
#     the damage is storage/monitoring only -- exactly what the docs claim.
#
# Both arms are asserted, then the default instance is restored.
case_begin "088_mixed_expiry_needs_reaper"

stop_opensips_a
REAP_INTERVAL=0 UNSAFE_TTL_ONLY=1 start_opensips_a
sleep 1

wait_for_log 10 "reaper DISABLED"
check "instance boots reaper-off with the unsafe ack (WARN logged)" \
    $([ "$?" = 0 ] && echo ok || echo fail)

kv_clear
sleep 0.5

# arm 1: eligible single-contact row -- native TTL alone must reclaim it
register_one solo088 3
check "REGISTER solo088 expires=3 accepted" \
    $([ "$?" = 0 ] && echo ok || echo fail)

# arm 2: ineligible mixed-expiry row -- no TTL, no reaper, nothing reclaims
register_contact mix088 6085 4
rc1=$?
register_contact mix088 6086 25
rc2=$?
t0=$(date +%s)
check "mixed-expiry REGISTERs accepted" \
    $([ "$rc1" = 0 ] && [ "$rc2" = 0 ] && echo ok || echo fail)
sleep 0.5

hdrs=$(kv_last_headers "mix088@127.0.0.1")
echo "$hdrs" | grep -q "Nats-TTL"
check "mixed row written with NO Nats-TTL (as designed)" \
    $([ "$?" != 0 ] && echo ok || echo fail) "hdrs=$hdrs"

wait_kv_gone "solo088@127.0.0.1" 20
check "eligible row STILL self-expires in TTL-only mode (native TTL works)" \
    $([ "$?" = 0 ] && echo ok || echo fail)

# let EVERY contact of the mixed row expire logically (25+5=30 s), then give
# any hypothetical reclaimer 10 more seconds to act.  Nothing may act.
now=$(date +%s); [ $((now - t0)) -lt 40 ] && sleep $(( 40 - (now - t0) ))

doc=$(kv_aor_get "mix088@127.0.0.1")
check "FAILURE MODE CONFIRMED: fully-expired mixed row still physically present" \
    $([ -n "$doc" ] && echo ok || echo fail) \
    "doc=$(printf '%s' "$doc" | head -c 120)"

vis=$(probe_binding mix088)
check "...but SIP stays correct: expired contacts not served (404)" \
    $([ "$vis" = 404 ] && echo ok || echo fail) "vis=$vis"

# restore the default (reaper-on) instance; its first tick reclaims the leak
stop_opensips_a
start_opensips_a
sleep 1

wait_kv_gone "mix088@127.0.0.1" 45
check "restored reaper reclaims the leaked row (recovery path)" \
    $([ "$?" = 0 ] && echo ok || echo fail) \
    "doc=$(kv_aor_get "mix088@127.0.0.1" | head -c 80)"

kv_clear
