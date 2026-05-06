# 100 — nats_consumer_bind/list MI commands
# Exercises: MI surface for managing handles + JSON-RPC over UDP.
case_begin "100_consumer_bind_list"

# Clean any stale durable consumer from prior runs.
consumer_rm TEST cmd

resp=$(bind_consumer cmd TEST cmd "test.sip.command" "ack_wait=30s")

# Wait for the consumer process to actually create the JS consumer
sleep 2

list_resp=$(mi nats_consumer:nats_consumer_list)

if echo "$list_resp" | grep -q '"result"'; then
    check "nats_consumer_list returns a result envelope" ok
else
    check "nats_consumer_list returns a result envelope" fail "$list_resp"
fi

if echo "$list_resp" | grep -q '"id":"cmd"' || \
   echo "$list_resp" | grep -q '"id": "cmd"' || \
   echo "$list_resp" | grep -q 'cmd'; then
    check "nats_consumer_list includes the bound 'cmd' handle" ok
else
    check "nats_consumer_list includes the bound 'cmd' handle" fail \
        "$list_resp"
fi
