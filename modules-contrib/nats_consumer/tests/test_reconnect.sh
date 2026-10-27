#!/bin/bash
# test_reconnect.sh -- surviving a broker restart.
#
# 1. Bind a durable handle 'rc' on stream RC.
# 2. Publish + drain a few messages (test timer is bound only to 'test';
#    we use 'rc' so we can observe counters without interference).
# 3. docker compose restart nats.
# 4. After nats is back, publish another message.
# 5. Verify the delivered counter for 'rc' monotonically increased
#    across the restart (durable state preserved + consumer process
#    resubscribed transparently).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/lib.sh"

ensure_stack
ensure_stream RC 'rc.*'

nats_bind rc RC durable=rc filter=rc.msg ack_wait=30s >/dev/null

publish rc.msg 'pre'

sleep 2

read_delivered() {
    local v
    v=$(nats_list_field "$(nats_list)" rc msgs_delivered 2>/dev/null)
    echo "${v:-0}"
}

before=$(read_delivered)
${COMPOSE} restart nats >/dev/null 2>&1 || true
# wait for nats to come back (healthcheck) + consumer process to resubscribe
sleep 8

# The test broker uses memory storage, so a restart wipes streams.
# Recreate RC (idempotent) so the durable can re-attach.
ensure_stream RC 'rc.*'

publish rc.msg 'post'

deadline=$(( $(date +%s) + 15 ))
after="${before}"
while [ "$(date +%s)" -lt "$deadline" ]; do
    after=$(read_delivered)
    [ "${after}" -gt "${before}" ] && break
    sleep 1
done

if [ "${after}" -gt "${before}" ] 2>/dev/null; then
    pass "reconnect: delivered grew ${before} -> ${after}"
else
    fail "reconnect: delivered ${before} -> ${after} (expected growth)"
fi
