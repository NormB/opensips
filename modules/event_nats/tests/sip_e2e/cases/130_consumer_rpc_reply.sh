# 130 — request/reply via timer_route[drain_rpc].
#
# Bind 'rpc' handle to a JetStream subject; an external publisher
# sends a message with a `Nats-Reply-To` header set to a private
# inbox.  The script's drain timer fetches the message and calls
# `nats_reply($payload)`, which publishes to $nats_reply_to.  We
# subscribe to the inbox first and assert the reply arrives.
#
# Why the header (and not `nats request` / `nats pub --reply`):
#   JetStream pull-delivered messages have natsMsg_GetReply() set to
#   the per-delivery $JS.ACK.<...> ack subject, NOT the publisher's
#   reply.  The application-level reply must be carried in headers
#   (the standard NATS pattern for JS request/reply).  See the
#   $JS.ACK. handling in nats_consumer_proc.c::pull_one_batch.

case_begin "130_consumer_rpc_reply"

unbind_consumer rpc 2>/dev/null || true
sleep 1
consumer_rm TEST rpc
bind_consumer rpc TEST rpc "test.sip.rpc" "ack_wait=10s"
sleep 2

payload="ping-${$}"
inbox="_INBOX.rpc-test.${$}"

# Pre-subscribe to the private inbox.
( timeout 10 nats --server "$NATS_URL" sub "$inbox" --count=1 \
    > "$WORKDIR/130_reply.out" 2>&1 ) &
sub_pid=$!
sleep 0.5

# Publish to the JS-bound subject WITH a Nats-Reply-To header, so the
# consumer's pull_one_batch can extract it as the application reply.
nats --server "$NATS_URL" pub -H "Nats-Reply-To: $inbox" \
    test.sip.rpc "$payload" >/dev/null 2>&1

# Wait for the inbox subscriber to receive the reply (or timeout).
for i in $(seq 1 10); do
    kill -0 "$sub_pid" 2>/dev/null || break
    sleep 1
done

if grep -q "pong:${payload}" "$WORKDIR/130_reply.out"; then
    check "request/reply via nats_reply round-trips through Nats-Reply-To header" ok
else
    check "request/reply via nats_reply round-trips through Nats-Reply-To header" fail \
        "$(head -10 "$WORKDIR/130_reply.out")"
fi

unbind_consumer rpc
