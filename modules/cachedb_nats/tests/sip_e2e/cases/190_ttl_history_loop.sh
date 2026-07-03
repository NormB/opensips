# 190 — [TREV-11 §8.3(f) / REV-27] register/expire/re-register loop on ONE
# AoR: every cycle the key physically expires (the reaper CAS-deletes it --
# reaper-only expiry, P1.5), and the next REGISTER must create over
# whatever the delete left behind first-attempt -- no lockout, no lost
# value, and the bucket returns to empty after the final expiry.
case_begin "190_ttl_history_loop"

kv_clear
sleep 0.5

CYCLES=4
lost=0
for i in $(seq 1 "$CYCLES"); do
    register_one loop190 3
    rc=$?
    if [ "$rc" != 0 ]; then
        lost=$((lost + 1))
        echo "  cycle $i: REGISTER rc=$rc"
        continue
    fi
    sleep 0.3
    if [ -z "$(kv_aor_get "loop190@127.0.0.1")" ]; then
        lost=$((lost + 1))
        echo "  cycle $i: value lost right after REGISTER"
    fi
    # expires(3) + grace(5) + up to REAP_INTERVAL(30) => poll to 45 s.
    if ! wait_kv_gone "loop190@127.0.0.1" 45; then
        lost=$((lost + 1))
        echo "  cycle $i: key never expired"
    fi
done

check "all $CYCLES register/expire cycles clean (no lockout, no lost value)" \
    $([ "$lost" = 0 ] && echo ok || echo fail) "lost=$lost"

n_keys=$(kv_aor_count)
check "bucket back to empty after the final expiry" \
    $([ "$n_keys" = 0 ] && echo ok || echo fail) "n_keys=$n_keys"
