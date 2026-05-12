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

nats_bind rpc_srv RPC durable=s1 filter=rpc.call ack_wait=30s >/dev/null

# Send a plain publish (not a real request -- we are only validating
# the deliver path, not the reply).  Full RPC round-trip verification
# requires a cfg with nats_reply, which the harness image doesn't
# build for scope reasons; see README "Known limitations".
publish rpc.call 'ping'

deadline=$(( $(date +%s) + 8 ))
delivered=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    delivered=$(nats_list_field "$(nats_list)" rpc_srv msgs_delivered 2>/dev/null)
    delivered=${delivered:-0}
    [ "${delivered}" -ge 1 ] && break
    sleep 0.5
done

if [ "${delivered}" -ge 1 ] 2>/dev/null; then
    pass "rpc: request reached opensips handle rpc_srv"
else
    fail "rpc: request did not reach opensips"
fi
