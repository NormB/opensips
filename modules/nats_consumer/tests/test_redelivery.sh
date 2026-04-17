#!/bin/sh
#
# test_redelivery.sh -- integration test for nak / nak_delay / redelivery
#                        counters.
#
# PHASE 5 STATUS: stubbed.  CI lands in Phase 9.  Verifies that a
# NAK'd message is redelivered after ack_wait / nak_delay and that
# $nats_delivered reflects the redelivery count.
#
# Manual procedure:
#   1. cd modules/nats_consumer/tests && docker compose up -d
#   2. docker exec $NATS_CTR nats stream add RED \
#          --subjects 'red.>' --storage memory --defaults
#   3. opensips-cli -x mi nats_consumer_bind \
#          'id=r1;stream=RED;filter=red.msg;durable=r1;ack_wait=2s'
#   4. docker exec $NATS_CTR nats publish red.msg 'test'
#
#   # First delivery: nak with no delay -> broker redelivers after ack_wait.
#   5. Trigger nats_fetch("r1", 2000); expect $nats_delivered == 1; nak().
#   6. Wait > 2s.
#   7. Trigger nats_fetch again; expect $nats_delivered == 2.
#
#   # NAK with explicit delay:
#   8. nak_delay(500) -- broker schedules redelivery 500ms later.
#   9. Within 500ms, fetch returns 0.  After 500ms+ack_wait, fetch
#      returns the message with $nats_delivered incremented.
#
#  10. Verify MI metrics:
#         naks          increments by 2
#         redeliveries  increments by 2

echo "TODO: wire up in CI -- Phase 9 follow-up"
exit 0
