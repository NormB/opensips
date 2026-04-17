#!/bin/sh
#
# test_fetch_sync.sh -- integration test for nats_fetch() (sync path).
#
# PHASE 4 STATUS: stubbed.  The CI harness (docker-compose bring-up of
# nats-server + opensips, MI invocation, message publish, and log
# verification) lands in a Phase 5 follow-up.  The script path is
# exercised manually today using the in-repo docker-compose.yaml.
#
# Manual procedure:
#   1. cd modules/nats_consumer/tests && docker compose up -d
#   2. docker exec $NATS_CTR nats stream add TEST --subjects 'test.*' \
#          --storage memory --defaults
#   3. opensips-cli -x mi nats_consumer_bind \
#          'id=t1;stream=TEST;filter=test.sync;durable=t1;ack_wait_ms=30000'
#   4. docker exec $NATS_CTR nats publish test.sync 'hello'
#   5. Trigger a timer_route that calls nats_fetch("t1", 2000) + nats_ack().
#   6. Check MI:  opensips-cli -x mi nats_consumer_info t1
#      Expect:    acks=1 msgs_delivered=1

echo "TODO: wire up in CI -- Phase 5 follow-up"
exit 0
