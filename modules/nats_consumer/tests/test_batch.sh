#!/bin/sh
#
# test_batch.sh -- integration test for nats_fetch_batch / nats_batch_select.
#
# PHASE 5 STATUS: stubbed.  CI lands in Phase 9.  Manual procedure
# exercises the batch path and the per-worker batch state.
#
# Manual procedure:
#   1. cd modules/nats_consumer/tests && docker compose up -d
#   2. docker exec $NATS_CTR nats stream add BATCH \
#          --subjects 'batch.>' --storage memory --defaults
#   3. opensips-cli -x mi nats_consumer_bind \
#          'id=b1;stream=BATCH;filter=batch.in;durable=b1;ack_wait=30s'
#   4. for i in $(seq 1 10); do
#          docker exec $NATS_CTR nats publish batch.in "msg-$i"
#      done
#   5. Trigger a timer_route:
#          $var(n) = nats_fetch_batch("b1", "count=10;expires=2s");
#          # expect $var(n) == 10
#          $var(i) = 0;
#          while ($var(i) < $var(n)) {
#              nats_batch_select($var(i));
#              xlog("got subject=$nats_subject seq=$nats_seq\n");
#              nats_ack();
#              $var(i) = $var(i) + 1;
#          }
#   6. Verify MI metrics:
#         msgs_delivered >= 10
#         acks           >= 10
#         nats_consumer_info b1 -> ring depth returns to 0
#
# Edge-cases to cover manually:
#   - count=1 behaves identically to nats_fetch().
#   - no_wait=1 returns immediately with whatever is ready (possibly 0).
#   - Re-calling nats_batch_select($var(i)) on the same index after
#     ack_i is a no-op (returns -1, finalize_current invalidated it).

echo "TODO: wire up in CI -- Phase 9 follow-up"
exit 0
