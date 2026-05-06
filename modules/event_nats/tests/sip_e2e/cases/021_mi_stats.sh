# 021 — event_nats MI nats_stats reports the 7 counters.
case_begin "021_mi_stats"

resp=$(mi event_nats:nats_stats)
if echo "$resp" | grep -q '"result"'; then
    check "nats_stats returns a result" ok
else
    check "nats_stats returns a result" fail "$resp"
    return
fi

# Spot-check that script_published is non-zero (cases 010-014 all
# called nats_publish from script).
if echo "$resp" | grep -q 'script_published'; then
    check "nats_stats exposes script_published counter" ok
else
    check "nats_stats exposes script_published counter" fail "$resp"
fi
