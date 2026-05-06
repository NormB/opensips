# 141 — nats_consumer_bind rejects malformed config (no id).
case_begin "141_consumer_bind_bad_config"

# Missing id= entirely.
resp=$(mi nats_consumer:nats_consumer_bind \
    "stream=TEST;durable=x;filter=test.sip.command")
if echo "$resp" | grep -q '"error"' || \
   echo "$resp" | grep -qi 'missing id\|invalid'; then
    check "bind without id is rejected" ok
else
    check "bind without id is rejected" fail "$resp"
fi

# id present but stream missing.
resp2=$(mi nats_consumer:nats_consumer_bind \
    "id=x-${$};durable=x;filter=test.sip.command")
if echo "$resp2" | grep -q '"error"' || \
   echo "$resp2" | grep -qi 'missing stream'; then
    check "bind without stream is rejected" ok
else
    check "bind without stream is rejected" fail "$resp2"
fi

# Mutually-exclusive durable + ephemeral.
resp3=$(mi nats_consumer:nats_consumer_bind \
    "id=x2-${$};stream=TEST;durable=d;ephemeral=1;filter=test.sip.command")
if echo "$resp3" | grep -q '"error"' || \
   echo "$resp3" | grep -qi 'mutually exclusive\|both'; then
    check "bind with both durable + ephemeral is rejected" ok
else
    check "bind with both durable + ephemeral is rejected" fail "$resp3"
fi
