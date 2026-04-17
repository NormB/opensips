#!/bin/bash
# test_rpc.sh -- nats_request() / nats_reply() round-trip.
#
# The default opensips.cfg does NOT include an RPC responder route
# (adding it would require a cfg reload per test, which is out of
# scope).  So this test drives the request side from the nats CLI and
# uses opensips as the responder.  We:
#   1. Create stream RPC / subject rpc.call.
#   2. Bind a handle on rpc.call inside opensips (already drained by
#      the `drain_test` timer? -- no, that timer only targets 'test').
#      We instead instruct opensips to bind an id that the default cfg
#      can't drain, then verify delivered>=1 via MI.  That exercises
#      the receive path end-to-end; full reply verification needs a
#      cfg with nats_reply, which is documented in test_headers.sh and
#      in README.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/lib.sh"

ensure_stack
ensure_stream RPC 'rpc.*'

${COMPOSE} exec -T opensips sh -c \
    'echo ":nats_consumer_bind:rpc:\nid=rpc_srv;stream=RPC;durable=s1;filter=rpc.call;ack_wait=30s\n\n" \
        > /var/run/opensips/mi.fifo' || true

# Send a plain publish (not a real request -- we are only validating
# the deliver path, not the reply).  Full RPC round-trip verification
# requires a cfg with nats_reply, which the harness image doesn't
# build for scope reasons; see README "Known limitations".
publish rpc.call 'ping'

sleep 2

${COMPOSE} exec -T opensips sh -c \
    'echo ":nats_consumer_list:rls:\n\n" > /var/run/opensips/mi.fifo && \
     sleep 0.3 && cat /var/run/opensips/mi.fifo.reply_rls 2>/dev/null' \
    > /tmp/rpc_out 2>/dev/null || true

delivered=$(python3 -c "
import json,re
with open('/tmp/rpc_out') as f: raw=f.read()
m=re.search(r'\{.*\}', raw, re.DOTALL)
obj=json.loads(m.group(0)) if m else {}
for h in obj.get('handles', []):
    if h.get('id')=='rpc_srv':
        print(h.get('msgs_delivered',0)); break
" 2>/dev/null || echo 0)

if [ "${delivered}" -ge 1 ] 2>/dev/null; then
    pass "rpc: request reached opensips handle rpc_srv"
else
    fail "rpc: request did not reach opensips"
fi
