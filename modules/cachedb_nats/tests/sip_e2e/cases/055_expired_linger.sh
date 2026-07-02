# 055 — [HREV-3/D6] nats_expired_linger: an expired registration stops being
# SERVED at expires+grace exactly as with linger=0, but its record stays
# PHYSICALLY readable in the bucket for ~linger more seconds; a re-REGISTER
# during the window cleanly overwrites (CAS at the lingering revision, no
# lockout).  Restarts instance A with linger=30 and restores it after.
case_begin "055_expired_linger"

stop_opensips_a
EXPIRED_LINGER=30 start_opensips_a
sleep 1

kv_clear
sleep 0.5

register_one ttl055 3
check "REGISTER ttl055 expires=3 accepted" \
    $([ "$?" = 0 ] && echo ok || echo fail)
register_one lng055 3
check "REGISTER lng055 expires=3 accepted" \
    $([ "$?" = 0 ] && echo ok || echo fail)

# past logical expiry (3+5=8 s) but well inside the 30 s linger window
sleep 12

vis=$(probe_binding ttl055)
check "expired binding NOT served during linger (MESSAGE -> 404)" \
    $([ "$vis" = 404 ] && echo ok || echo fail) "vis=$vis"

doc=$(kv_aor_get "ttl055@127.0.0.1")
check "record still PHYSICALLY present during linger (hidden-but-present)" \
    $([ -n "$doc" ] && echo ok || echo fail)

# a re-REGISTER mid-linger must overwrite cleanly, not be locked out
register_one lng055 3600
rc=$?
check "re-REGISTER during linger accepted (no lockout)" \
    $([ "$rc" = 0 ] && echo ok || echo fail) "rc=$rc"
sleep 0.5
vis=$(probe_binding lng055)
check "re-registered binding served again (MESSAGE -> 202)" \
    $([ "$vis" = 202 ] && echo ok || echo fail) "vis=$vis"

# ttl055's TTL = expires(3) + grace(5) + linger(30) = 38 s from REGISTER;
# ~13 s have elapsed, so poll the remaining ~25 s + 15 s slack.
wait_kv_gone "ttl055@127.0.0.1" 40
check "record reclaimed after the linger window" \
    $([ "$?" = 0 ] && echo ok || echo fail) \
    "doc=$(kv_aor_get "ttl055@127.0.0.1" | head -c 80)"

# restore the default instance (linger=0) for the rest of the suite
stop_opensips_a
start_opensips_a
sleep 1
kv_clear
