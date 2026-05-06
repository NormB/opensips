# 140 — nats_consumer_unbind on a non-existent id returns an error.
case_begin "140_consumer_unbind_unknown"

resp=$(mi nats_consumer:nats_consumer_unbind "no-such-handle-${$}")
if echo "$resp" | grep -q '"error"' || \
   echo "$resp" | grep -qi 'not found\|missing\|unknown'; then
    check "unbind of unknown id returns error" ok
else
    check "unbind of unknown id returns error" fail "$resp"
fi
