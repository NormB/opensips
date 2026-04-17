#!/bin/sh
#
# test_max_deliver.sh -- integration test for max_deliver + backoff.
#
# PHASE 5 STATUS: stubbed.  CI lands in Phase 9.  Verifies that the
# broker stops redelivering after max_deliver attempts and that
# backoff= causes the expected inter-redelivery spacing.
#
# Manual procedure:
#   1. cd modules/nats_consumer/tests && docker compose up -d
#   2. docker exec $NATS_CTR nats stream add MX \
#          --subjects 'mx.>' --storage memory --defaults
#   3. opensips-cli -x mi nats_consumer_bind \
#          'id=m1;stream=MX;filter=mx.msg;durable=m1;'\
# 'ack_wait=1s;max_deliver=3;backoff=500ms,1s,2s'
#   4. docker exec $NATS_CTR nats publish mx.msg 'test'
#
#   # Loop nak()s; expect exactly 3 deliveries then silence.
#   5. Call nats_fetch() repeatedly from a script:
#        attempt 1: $nats_delivered == 1; nak()
#        attempt 2 (after 500ms): $nats_delivered == 2; nak()
#        attempt 3 (after 1s):    $nats_delivered == 3; nak()
#        attempt 4: no message.  Broker has flagged the message
#                   undeliverable and (depending on server config) may
#                   move it to the dead-letter subject.
#
#   6. Verify MI metrics:
#         naks           == 3
#         redeliveries   == 2      (deliveries 2 and 3)
#         max_deliver    == 3
#
# Edge cases to cover manually:
#   - backoff shorter than ack_wait is respected.
#   - backoff list shorter than max_deliver: last element repeats.

echo "TODO: wire up in CI -- Phase 9 follow-up"
exit 0
