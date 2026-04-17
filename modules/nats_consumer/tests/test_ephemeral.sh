#!/bin/bash
# Phase 7 manual ephemeral recreation test.
#
# 1. Start nats-server + opensips.
# 2. Bind handle: opensips-cli -x mi nats_consumer_bind \
#      'id=e;stream=T;ephemeral=1;inactive_threshold=3s'
# 3. Publish a message; verify it arrives.
# 4. Idle for 5 seconds (no fetches). Broker GC's the ephemeral consumer.
# 5. Publish another message.
# 6. nats_fetch("e", 1000) -- should transparently recreate the consumer
#    and deliver the new message.
# 7. Verify LM_INFO log contains "re-creating ephemeral consumer for e"
#    or "consumer for e vanished; will recreate".
echo "TODO: automate in Phase 9 CI"
exit 0
