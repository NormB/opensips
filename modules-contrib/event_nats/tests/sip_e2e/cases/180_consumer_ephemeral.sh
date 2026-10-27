# 180 — bind an ephemeral consumer (no durable name).
case_begin "180_consumer_ephemeral"

unbind_consumer eph 2>/dev/null || true
sleep 1

# `ephemeral=1` instead of `durable=...`
resp=$(mi nats_consumer:nats_consumer_bind \
    "id=eph;stream=TEST;ephemeral=1;filter=test.sip.command")
if echo "$resp" | grep -q '"result"'; then
    check "ephemeral bind succeeds" ok
else
    check "ephemeral bind succeeds" fail "$resp"
    return
fi

sleep 2
list=$(mi nats_consumer:nats_consumer_list)
if echo "$list" | grep -q '"id":"eph"' || \
   echo "$list" | grep -q "eph"; then
    check "ephemeral handle present in list" ok
else
    check "ephemeral handle present in list" fail "$list"
fi

unbind_consumer eph
