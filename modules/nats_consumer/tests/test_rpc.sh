#!/bin/sh
#
# test_rpc.sh -- integration test for nats_request() + nats_reply()
# request/reply round-trip.
#
# PHASE 6 STATUS: stubbed.  CI wiring lands with Phase 9 integration
# automation.  The flow below is the manual procedure used during
# Phase 6 development.
#
# Coverage:
#   - Two OpenSIPS instances (or two routes on the same instance):
#     a "server" that nats_fetch + nats_reply, and a "client" that
#     invokes nats_request() and verifies the reply payload.
#   - Sync-only semantics: nats_request blocks the calling worker --
#     the client-side callsite MUST be timer_route or startup_route,
#     not a SIP request_route.
#
# Manual procedure:
#
#   1. cd modules/nats_consumer/tests && docker compose up -d
#   2. Create a JetStream stream that captures the requests:
#        docker exec $NATS_CTR nats stream add RPC \
#            --subjects 'rpc.call' --storage memory --defaults
#
#   3. Server-side opensips (bind + reply loop):
#        modparam("nats_consumer", ...)
#        bind rpc_srv id=s1;stream=RPC;filter=rpc.call;durable=s1
#        timer_route[rpc_srv] {
#          while (nats_fetch("s1", 250) > 0) {
#            $var(body) = "echo: $nats_data";
#            if (nats_reply("$var(body)")) nats_ack();
#            else nats_nak();
#          }
#        }
#
#   4. Client-side opensips (sync call on a timer):
#        timer_route[rpc_cli] {
#          if (nats_request("rpc.call", "ping", 2000)) {
#            xlog("got reply: $nats_data\n");    # expect 'echo: ping'
#          } else {
#            xlog("RPC failed rc=$rc\n");
#          }
#        }
#
#   5. Run both instances; after ~1 second the client should log:
#        got reply: echo: ping
#
# Failure modes to exercise (optional):
#   - Kill the server; client's nats_request times out, rc=0,
#     $var(nats_data) unchanged.
#   - Misspell the subject ("rpc.nope"); same timeout behaviour.
#   - Stage headers via nats_hdr_set() before nats_request(); the
#     server's $nats_hdr(X-...) reads them.  Staging is cleared by
#     nats_request regardless of success/timeout.
#
# Notes:
#   - nats_request() uses PLAIN CORE NATS (not JetStream), so the
#     stream definition above is optional -- it only helps MI / nats
#     CLI observers inspect the request traffic.  The reply hop never
#     touches JetStream.
#   - Async nats_request is a Phase 7/8 concern.  Until it lands,
#     DO NOT call nats_request() from a SIP request route.

echo "TODO: wire up in CI -- Phase 9 follow-up"
exit 0
