#!/bin/bash
# test_redelivery.sh -- ack_wait expiry triggers redelivery.
#
# Binds a durable with a 2s ack_wait.  Publishes a message.  The drain
# timer in the default cfg for handle `test` is not what we want (it
# acks).  So we use a dedicated id + the fact that nothing drains it
# from script: the consumer process still pulls and rings it, but
# without a script handler nothing acks it, so after ack_wait the
# broker redelivers and the delivered counter ticks to 2.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/lib.sh"

ensure_stack
ensure_stream RED 'red.>'

nats_bind r1 RED durable=r1 filter=red.msg ack_wait=2s max_deliver=3 >/dev/null

publish red.msg 'hello'

# The broker redelivers every ack_wait until max_deliver (3) is
# reached.  Wait for redeliveries >= 1 (first + one redelivery)
# within 12s = 2x ack_wait plus tolerance.
deadline=$(( $(date +%s) + 12 ))
redeliveries=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    redeliveries=$(nats_list_field "$(nats_list)" r1 redeliveries 2>/dev/null)
    redeliveries=${redeliveries:-0}
    if [ "${redeliveries}" -ge 1 ]; then
        pass "redelivery observed (count=${redeliveries})"
        exit 0
    fi
    sleep 1
done

fail "redelivery did not register for handle r1 within 12s (last=${redeliveries})"
