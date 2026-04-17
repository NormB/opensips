#!/bin/bash
# test_ephemeral.sh -- ephemeral consumer GC + transparent recreation.
#
# 1. Bind an ephemeral handle with inactive_threshold=3s.
# 2. Publish + drain one message; that bumps delivered to 1.
# 3. Idle for 6s.  The broker GCs the ephemeral consumer.
# 4. Publish another message; consumer process detects the vanished
#    consumer, re-creates it, delivered bumps to 2.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/lib.sh"

ensure_stack
ensure_stream EPH 'eph.*'

${COMPOSE} exec -T opensips sh -c \
    'echo ":nats_consumer_bind:ep:\nid=eph;stream=EPH;ephemeral=1;filter=eph.msg;inactive_threshold=3s\n\n" \
        > /var/run/opensips/mi.fifo' || true

publish eph.msg 'pre'
sleep 2

read_delivered() {
    ${COMPOSE} exec -T opensips sh -c \
        'echo ":nats_consumer_list:epx:\n\n" > /var/run/opensips/mi.fifo && \
         sleep 0.3 && cat /var/run/opensips/mi.fifo.reply_epx 2>/dev/null' \
        > /tmp/ep_out 2>/dev/null || true
    python3 -c "
import json,re
with open('/tmp/ep_out') as f: raw=f.read()
m=re.search(r'\{.*\}', raw, re.DOTALL)
obj=json.loads(m.group(0)) if m else {}
for h in obj.get('handles', []):
    if h.get('id')=='eph':
        print(h.get('msgs_delivered',0)); break
" 2>/dev/null || echo 0
}

pre=$(read_delivered)
sleep 6   # past inactive_threshold
publish eph.msg 'post'
sleep 3
post=$(read_delivered)

if [ "${post}" -gt "${pre}" ] 2>/dev/null; then
    pass "ephemeral recreate: delivered ${pre} -> ${post}"
else
    fail "ephemeral recreate: delivered stuck at ${pre}"
fi
