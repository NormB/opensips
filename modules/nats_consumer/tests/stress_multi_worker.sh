#!/bin/bash
# stress_multi_worker.sh -- multiple SIP workers draining the same durable.
#
# The opensips image is configured with udp_workers=4.  We publish
# N_MESSAGES onto a stream, bind a single durable consumer 'mw' to it,
# and rely on the timer_route[drain_test] being reachable from any of
# the 4 workers (opensips fires the timer_route in one worker per tick
# but the JetStream consumer under the hood balances across all
# workers that pull).  We then assert:
#   - total acks for id=mw equal N_MESSAGES (no losses)
#   - no redeliveries (implies no worker double-processed)
#
# This is a smoke-level stress test; 10k messages finishes in ~20s on
# a local compose stack.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/lib.sh"

ensure_stack

N_MESSAGES="${N_MESSAGES:-10000}"

ensure_stream MW 'mw.>'

${COMPOSE} exec -T opensips sh -c \
    'echo ":nats_consumer_bind:mw:\nid=mw;stream=MW;durable=mw;filter=mw.job;ack_wait=30s;max_ack_pending=512\n\n" \
        > /var/run/opensips/mi.fifo' || true

echo "publishing ${N_MESSAGES} messages..."
for i in $(seq 1 "${N_MESSAGES}"); do
    publish mw.job "job-${i}" >/dev/null 2>&1
done

# Wait for delivery counter to reach target.
deadline=$(( $(date +%s) + 120 ))
while [ $(date +%s) -lt ${deadline} ]; do
    ${COMPOSE} exec -T opensips sh -c \
        'echo ":nats_consumer_list:mwx:\n\n" > /var/run/opensips/mi.fifo && \
         sleep 0.3 && cat /var/run/opensips/mi.fifo.reply_mwx 2>/dev/null' \
        > /tmp/mw_out 2>/dev/null || true
    read -r delivered redeliveries <<EOF
$(python3 -c "
import json,re
with open('/tmp/mw_out') as f: raw=f.read()
m=re.search(r'\{.*\}', raw, re.DOTALL)
obj=json.loads(m.group(0)) if m else {}
for h in obj.get('handles', []):
    if h.get('id')=='mw':
        print(h.get('msgs_delivered',0), h.get('redeliveries',0)); break
" 2>/dev/null || echo "0 0")
EOF
    if [ "${delivered:-0}" -ge "${N_MESSAGES}" ] 2>/dev/null; then
        if [ "${redeliveries:-0}" -eq 0 ] 2>/dev/null; then
            pass "multi_worker: ${delivered} delivered, 0 redeliveries"
            exit 0
        else
            fail "multi_worker: ${redeliveries} redeliveries (expected 0)"
        fi
    fi
    sleep 2
done

fail "multi_worker: did not reach ${N_MESSAGES} deliveries in 120s"
