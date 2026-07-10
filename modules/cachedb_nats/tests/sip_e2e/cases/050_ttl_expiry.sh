# 050 — [HREV-1/2/3] native per-key TTL expiry, the case this suite was
# missing: a REGISTER with a short Expires must PHYSICALLY leave the bucket
# once expired -- Get fails, the key is not listed, and SIP lookup finds no
# binding.  Runs at nats_expired_linger=0 (the default instance): removal is
# expected at the first reaper pass after expires + grace(5)
# (reaper-only expiry, P1.5; default scan interval 30 s).
case_begin "050_ttl_expiry"

kv_clear

register_one ttl050 3
rc=$?
check "REGISTER ttl050 expires=3 accepted" \
    $([ "$rc" = 0 ] && echo ok || echo fail) "rc=$rc"

wait_kv_aor "ttl050@127.0.0.1" 2
doc=$(kv_aor_get "ttl050@127.0.0.1")
check "doc present right after REGISTER" \
    $([ -n "$doc" ] && echo ok || echo fail)

vis=$(probe_binding ttl050)
check "binding served while live (MESSAGE -> 202)" \
    $([ "$vis" = 202 ] && echo ok || echo fail) "vis=$vis"

# expires(3) + grace(5) = TTL 8 s; give the broker sweep +12 s of slack.
# reaper-only (P1.5): reclaim lands on the first reaper pass after
# expires(3)+grace(5); default REAP_INTERVAL=30 -> poll to 45 s.
wait_kv_gone "ttl050@127.0.0.1" 45
check "doc PHYSICALLY gone within expires+grace+interval" \
    $([ "$?" = 0 ] && echo ok || echo fail) \
    "doc=$(kv_aor_get "ttl050@127.0.0.1" | head -c 80)"

n_keys=$(kv_aor_count)
check "bucket lists no AoR key after expiry" \
    $([ "$n_keys" = 0 ] && echo ok || echo fail) "n_keys=$n_keys"

vis=$(probe_binding ttl050)
check "no binding served after expiry (MESSAGE -> 404)" \
    $([ "$vis" = 404 ] && echo ok || echo fail) "vis=$vis"
