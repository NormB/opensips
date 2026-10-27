# 160 — nats_consumer_health MI returns the heartbeat tick.
case_begin "160_consumer_health"

resp=$(mi nats_consumer:nats_consumer_health)
if echo "$resp" | grep -q '"result"' && \
   echo "$resp" | grep -qi 'heart\|tick\|consumer_pid\|alive\|ok\|stale'; then
    check "nats_consumer_health returns heartbeat info" ok
else
    check "nats_consumer_health returns heartbeat info" fail "$resp"
fi
