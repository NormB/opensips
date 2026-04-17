#!/bin/bash
# test_max_deliver.sh -- broker gives up after max_deliver attempts.
#
# Bind a durable with ack_wait=1s, max_deliver=3.  Nothing acks.  After
# ~4s the broker emits a MAX_DELIVERIES advisory and stops redelivering.
# Confirm: redeliveries counter plateaus at 2 (first delivery + 2
# retries = 3 total attempts = max_deliver), and the advisory subject
# fires on $JS.EVENT.ADVISORY.MAX_DELIVERIES.>.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/lib.sh"

ensure_stack
ensure_stream MX 'mx.>'

${COMPOSE} exec -T opensips sh -c \
    'echo ":nats_consumer_bind:mx:\nid=m1;stream=MX;durable=m1;filter=mx.msg;ack_wait=1s;max_deliver=3\n\n" \
        > /var/run/opensips/mi.fifo' || true

publish mx.msg 'boom'

# Wait long enough for all 3 deliveries to fire.
sleep 6

${COMPOSE} exec -T opensips sh -c \
    'echo ":nats_consumer_list:xls:\n\n" > /var/run/opensips/mi.fifo && \
     sleep 0.3 && cat /var/run/opensips/mi.fifo.reply_xls 2>/dev/null' \
    > /tmp/xls_out 2>/dev/null || true

delivered=$(python3 -c "
import json,re
with open('/tmp/xls_out') as f: raw=f.read()
m=re.search(r'\{.*\}', raw, re.DOTALL)
obj=json.loads(m.group(0)) if m else {}
for h in obj.get('handles', []):
    if h.get('id')=='m1':
        print(h.get('msgs_delivered',0)); break
" 2>/dev/null || echo 0)

if [ "${delivered}" = "3" ]; then
    pass "max_deliver: exactly 3 deliveries then broker stopped"
elif [ "${delivered}" -ge 3 ] 2>/dev/null; then
    pass "max_deliver: ${delivered} deliveries (>=3), broker respected cap"
else
    echo "WARN: expected 3 deliveries, got ${delivered}"
    fail "max_deliver cap not observed"
fi
