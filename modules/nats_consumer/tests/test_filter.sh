#!/bin/sh
#
# test_filter.sh -- integration test for multi-subject filtering
#                    (filter= and filters= bind keys).
#
# PHASE 5 STATUS: stubbed.  The CI harness (docker-compose bring-up of
# nats-server + opensips, MI invocation, message publish, and log
# verification) lands in a Phase 9 follow-up.  The script path is
# exercised manually today using the in-repo docker-compose.yaml.
#
# Manual procedure:
#   1. cd modules/nats_consumer/tests && docker compose up -d
#   2. docker exec $NATS_CTR nats stream add CALLS \
#          --subjects 'calls.>' --storage memory --defaults
#
#   # Single-subject filter:
#   3. opensips-cli -x mi nats_consumer_bind \
#          'id=billing;stream=CALLS;filter=calls.ended;durable=b1'
#   4. docker exec $NATS_CTR nats publish calls.ended '{"id":"c1"}'
#   5. docker exec $NATS_CTR nats publish calls.started '{"id":"c2"}'
#   6. Trigger a timer_route: nats_fetch("billing", 2000).
#      Expect $nats_subject == "calls.ended"; second fetch returns 0.
#
#   # Multi-subject filter (nats.c 3.13 FilterSubjects):
#   7. opensips-cli -x mi nats_consumer_unbind 'id=billing'
#   8. opensips-cli -x mi nats_consumer_bind \
#          'id=multi;stream=CALLS;filters=calls.ended,calls.failed;'\
# 'durable=m1'
#   9. Publish to both filters -- expect both drained, ordering by
#      stream seq.
#  10. Verify MI metrics:
#         msgs_delivered  matches the number of matching publishes
#         acks            matches msgs_delivered after script acks

echo "TODO: wire up in CI -- Phase 9 follow-up"
exit 0
