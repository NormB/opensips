#!/bin/sh
#
# test_headers.sh -- integration test for NATS message headers.
#
# PHASE 6 STATUS: stubbed.  CI wiring (docker-compose bring-up,
# publish, verify) lands with Phase 9 integration automation.  The
# flow below is the manual procedure used during Phase 6 development.
#
# Coverage:
#   - Inbound: publish a message with headers, fetch it, and verify
#     $nats_hdr(Name) returns the right value.  Also verifies case-
#     insensitive name match.
#   - Outbound: stage a header via nats_hdr_set(), reply, and consume
#     the reply on a side subscription to verify the staged header
#     round-tripped to the wire.
#
# Manual procedure:
#
#   1. cd modules/nats_consumer/tests && docker compose up -d
#   2. docker exec $NATS_CTR nats stream add HDR \
#          --subjects 'hdr.*' --storage memory --defaults
#
#   3. Load opensips with a route that:
#        bind -> hdr_in  (stream=HDR, filter=hdr.in,   durable=hi)
#        bind -> hdr_out (stream=HDR, filter=hdr.reply, durable=ho)
#
#      timer_route {
#        if (nats_fetch("hdr_in", 1000)) {
#          xlog("trace: $nats_hdr(X-Trace-Id)\n");       # expect 'abc123'
#          xlog("type:  $nats_hdr(content-type)\n");    # case-insensitive
#          nats_hdr_set("X-Response-Code", "200");
#          nats_hdr_set("X-Trace-Id", "$nats_hdr(X-Trace-Id)");
#          if (nats_reply("pong")) { nats_ack(); }
#        }
#      }
#
#   4. Publish a message with headers:
#        docker exec $NATS_CTR nats publish hdr.in 'ping' \
#            -H X-Trace-Id:abc123 -H Content-Type:application/json \
#            --reply hdr.reply
#
#   5. Subscribe side-channel to verify the reply headers:
#        docker exec $NATS_CTR nats subscribe 'hdr.reply'
#      Expect to see a message body 'pong' with X-Response-Code=200
#      and X-Trace-Id=abc123 (round-tripped).
#
#   6. MI verify:
#        opensips-cli -x mi nats_consumer_info hdr_in
#      Expect msgs_delivered=1 acks=1.
#
# Failure modes to exercise (optional):
#   - Publish a message with no headers; $nats_hdr(Foo) must read NULL.
#   - Stage 20 headers, only the first NATS_MAX_STAGED_HDRS (=16) are
#     accepted; nats_hdr_set returns -1 on the overflow attempts.
#   - Publish with > NATS_RING_HEADERS_MAX (=1024 B) of headers; the
#     worker still serves the message with headers_truncated=1 in the
#     slot (reads for dropped headers return NULL).

echo "TODO: wire up in CI -- Phase 9 follow-up"
exit 0
