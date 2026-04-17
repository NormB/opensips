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

${COMPOSE} exec -T opensips sh -c \
    'echo ":nats_consumer_bind:rc1:\nid=rc;stream=RC;durable=rc;filter=rc.msg;ack_wait=30s\n\n" \
        > /var/run/opensips/mi.fifo' || true

publish rc.msg 'pre'

sleep 2

read_delivered() {
    ${COMPOSE} exec -T opensips sh -c \
        'echo ":nats_consumer_list:rcx:\n\n" > /var/run/opensips/mi.fifo && \
         sleep 0.3 && cat /var/run/opensips/mi.fifo.reply_rcx 2>/dev/null' \
        > /tmp/rc_out 2>/dev/null || true
    python3 -c "
import json,re
with open('/tmp/rc_out') as f: raw=f.read()
m=re.search(r'\{.*\}', raw, re.DOTALL)
obj=json.loads(m.group(0)) if m else {}
for h in obj.get('handles', []):
    if h.get('id')=='rc':
        print(h.get('msgs_delivered',0)); break
" 2>/dev/null || echo 0
}

before=$(read_delivered)
${COMPOSE} restart nats >/dev/null 2>&1 || true
# wait for nats to come back (healthcheck)
sleep 8

publish rc.msg 'post'
sleep 3

after=$(read_delivered)

if [ "${after}" -gt "${before}" ] 2>/dev/null; then
    pass "reconnect: delivered grew ${before} -> ${after}"
else
    fail "reconnect: delivered ${before} -> ${after} (expected growth)"
fi
