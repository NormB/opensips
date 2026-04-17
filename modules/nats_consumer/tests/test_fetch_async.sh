#!/bin/sh
#
# test_fetch_async.sh -- integration test for async(nats_fetch(...)).
#
# PHASE 4 STATUS: stubbed.  The CI harness (docker-compose bring-up,
# SIP request injection to exercise the request_route async() path,
# and verification that the worker does NOT block) lands in a Phase 5
# follow-up.
#
# Manual procedure:
#   1. docker compose up -d
#   2. Publish a delayed message (sleep 2; nats pub test.async hello)
#   3. From opensips cfg:
#        async(nats_fetch("t1", 5000), on_nats_msg);
#      on_nats_msg handles $nats_subject / $nats_data and calls nats_ack().
#   4. Verify worker count stays high during the 2s wait (worker yielded).
#   5. Verify on_nats_msg ran after the publish.

echo "TODO: wire up in CI -- Phase 5 follow-up"
exit 0
