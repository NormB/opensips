#!/bin/bash
# Phase 7 manual reconnect test.
#
# 1. Start nats-server + opensips with nats_consumer loaded.
# 2. Bind handle: opensips-cli -x mi nats_consumer_bind 'id=r;stream=T;durable=d'
# 3. Publish 10 msgs; verify they arrive + ack (nats_consumer_info r shows acks=10).
# 4. Stop nats-server (docker stop nats); wait 5s.
# 5. From a worker-driven timer_route, attempt nats_fetch("r", 1000).
#    Expected: $rc == -2, nats_last_error() == "connection lost".
# 6. Restart nats-server (docker start nats).
# 7. Publish another 10 msgs.
# 8. Verify the durable consumer picks up where it left off (no loss, no dups).
# 9. Verify LM_INFO log contains "reconnect detected (epoch X -> Y)".
echo "TODO: automate in Phase 9 CI"
exit 0
