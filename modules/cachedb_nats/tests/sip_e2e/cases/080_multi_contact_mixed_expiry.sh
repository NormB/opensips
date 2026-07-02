# 080 — [REV-6/F6 / §2.0] multi-contact row with DIFFERING expiries: the
# TTL-ineligible path, end-to-end.  A min-derived row TTL would tombstone the
# still-live contact, so the write must carry NO Nats-TTL and the reaper owns
# the row: it prunes the expired contact (keeping the live one) and its
# survivor-write must RE-ASSERT Nats-TTL (the #1994 protection) so the final
# single-contact row expires natively.  Runs on a 5 s reaper so every stage
# fits the case budget; restores the default instance after.
#
# Timeline (t0 = second REGISTER):  c1 expires 25, c2 expires 4, grace 5.
#   t0        row {c1,c2}, mixed -> last msg has NO Nats-TTL header
#   t0+9      c2 logically expired: lookup still 202 (c1 live), row intact
#   <= t0+16  reaper prunes c2 -> row {c1}, survivor msg HAS Nats-TTL
#   ~t0+30    c1's TTL fires -> row physically gone, 404
case_begin "080_multi_contact_mixed_expiry"

stop_opensips_a
REAP_INTERVAL=5 start_opensips_a
sleep 1

kv_clear
sleep 0.5

register_contact mc080 6081 25
check "REGISTER contact#1 (port 6081, expires=25) accepted" \
    $([ "$?" = 0 ] && echo ok || echo fail)
register_contact mc080 6082 4
check "REGISTER contact#2 (port 6082, expires=4) accepted" \
    $([ "$?" = 0 ] && echo ok || echo fail)
t0=$(date +%s)
sleep 0.5

doc=$(kv_aor_get "mc080@127.0.0.1")
echo "$doc" | grep -q '127.0.0.1:6081' && echo "$doc" | grep -q '127.0.0.1:6082'
check "row holds BOTH contacts" \
    $([ "$?" = 0 ] && echo ok || echo fail) \
    "doc=$(printf '%s' "$doc" | head -c 160)"

hdrs=$(kv_last_headers "mc080@127.0.0.1")
echo "$hdrs" | grep -q "Nats-TTL"
check "mixed-expiry write carries NO Nats-TTL (ineligible, reaper-owned)" \
    $([ "$?" != 0 ] && echo ok || echo fail) "hdrs=$hdrs"

vis=$(probe_binding mc080)
check "lookup serves while both live (202)" \
    $([ "$vis" = 202 ] && echo ok || echo fail) "vis=$vis"

# past c2's logical expiry (4+5=9 s), before c1's
now=$(date +%s); [ $((now - t0)) -lt 10 ] && sleep $(( 10 - (now - t0) ))

vis=$(probe_binding mc080)
check "lookup still 202 after ONLY c2 expired (partial expiry)" \
    $([ "$vis" = 202 ] && echo ok || echo fail) "vis=$vis"

# reaper (5 s) prunes c2 by ~t0+16; poll to t0+22 for the survivor row
pruned=""
while [ $(( $(date +%s) - t0 )) -le 22 ]; do
    doc=$(kv_aor_get "mc080@127.0.0.1")
    if [ -n "$doc" ] && ! echo "$doc" | grep -q '127.0.0.1:6082'; then
        pruned=1; break
    fi
    sleep 1
done
check "reaper pruned the expired contact (survivor-write)" \
    $([ -n "$pruned" ] && echo ok || echo fail) \
    "doc=$(printf '%s' "$doc" | head -c 160)"

echo "$doc" | grep -q '127.0.0.1:6081'
check "the still-live contact SURVIVED the prune (no collateral delete)" \
    $([ "$?" = 0 ] && echo ok || echo fail)

hdrs=$(kv_last_headers "mc080@127.0.0.1")
echo "$hdrs" | grep -q "Nats-TTL"
check "survivor-write RE-ASSERTED Nats-TTL (§2.0 / #1994 protection)" \
    $([ "$?" = 0 ] && echo ok || echo fail) "hdrs=$hdrs"

vis=$(probe_binding mc080)
check "survivor still served after the prune (202)" \
    $([ "$vis" = 202 ] && echo ok || echo fail) "vis=$vis"

# c1's own expiry: t0+25+5=30; the survivor row's re-asserted TTL fires then
timeout=$(( 42 - ($(date +%s) - t0) ))
[ "$timeout" -lt 10 ] && timeout=10
wait_kv_gone "mc080@127.0.0.1" "$timeout"
check "row physically gone after the last contact expired" \
    $([ "$?" = 0 ] && echo ok || echo fail) \
    "doc=$(kv_aor_get "mc080@127.0.0.1" | head -c 80)"

vis=$(probe_binding mc080)
check "no binding served at the end (404)" \
    $([ "$vis" = 404 ] && echo ok || echo fail) "vis=$vis"

# restore the default instance
stop_opensips_a
start_opensips_a
sleep 1
kv_clear
