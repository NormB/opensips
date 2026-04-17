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

${COMPOSE} exec -T opensips sh -c \
    'echo ":nats_consumer_bind:rd:\nid=r1;stream=RED;durable=r1;filter=red.msg;ack_wait=2s;max_deliver=3\n\n" \
        > /var/run/opensips/mi.fifo' || true

publish red.msg 'hello'

# The broker redelivers every ack_wait until max_deliver (3) is
# reached.  At max_deliver the JS.API advisory fires.  We only check
# that msgs_delivered reports >= 2 (first + one redelivery) within
# 10 seconds, which is 2x ack_wait plus tolerance.
deadline=$(( $(date +%s) + 12 ))
while [ $(date +%s) -lt ${deadline} ]; do
    ${COMPOSE} exec -T opensips sh -c \
        'echo ":nats_consumer_list:rls:\n\n" > /var/run/opensips/mi.fifo && \
         sleep 0.3 && cat /var/run/opensips/mi.fifo.reply_rls 2>/dev/null' \
        > /tmp/rls_out 2>/dev/null || true
    redeliveries=$(python3 -c "
import json,re
with open('/tmp/rls_out') as f: raw=f.read()
m=re.search(r'\{.*\}', raw, re.DOTALL)
obj=json.loads(m.group(0)) if m else {}
for h in obj.get('handles', []):
    if h.get('id')=='r1':
        print(h.get('redeliveries',0)); break
" 2>/dev/null || echo 0)
    [ "${redeliveries}" -ge 1 ] 2>/dev/null && {
        pass "redelivery observed (count=${redeliveries})"
        exit 0
    }
    sleep 1
done

fail "redelivery did not register for handle r1 within 12s"
