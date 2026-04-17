#!/bin/bash
# test_filter.sh -- integration test for single + multi subject filters.
#
# Binds two handles:
#   billing: stream=CALLS, filter=calls.ended
#   multi:   stream=CALLS, filters=calls.ended,calls.failed
# Publishes messages on calls.ended + calls.started, asserts each handle
# receives only what its filter allows.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/lib.sh"

ensure_stack
ensure_stream CALLS 'calls.>'

${COMPOSE} exec -T opensips sh -c \
    'echo ":nats_consumer_bind:1:\nid=billing;stream=CALLS;durable=b1;filter=calls.ended;ack_wait=30s\n\n" \
        > /var/run/opensips/mi.fifo' || true
${COMPOSE} exec -T opensips sh -c \
    'echo ":nats_consumer_bind:2:\nid=multi;stream=CALLS;durable=m1;filters=calls.ended,calls.failed;ack_wait=30s\n\n" \
        > /var/run/opensips/mi.fifo' || true

publish calls.started '{"id":"x"}'
publish calls.ended   '{"id":"y"}'
publish calls.failed  '{"id":"z"}'

sleep 3

# billing should have seen exactly 1 message (calls.ended).
# multi    should have seen exactly 2 (calls.ended + calls.failed).
#
# We observe via the opensips log drain: the default cfg only drains
# 'test'.  For this test we read counters via MI list output.

count_acks() {
    local id="$1"
    ${COMPOSE} exec -T opensips sh -c \
        'echo ":nats_consumer_list:lst:\n\n" > /var/run/opensips/mi.fifo && \
         sleep 0.5 && cat /var/run/opensips/mi.fifo.reply_lst 2>/dev/null' \
        | python3 -c "import sys,json,re
raw=sys.stdin.read()
m=re.search(r'\{.*\}', raw, re.DOTALL)
if not m: sys.exit(0)
obj=json.loads(m.group(0))
for h in obj.get('handles', []):
    if h.get('id') == '${id}':
        print(h.get('msgs_delivered', 0))
        break" 2>/dev/null || echo 0
}

b_delivered=$(count_acks billing || echo 0)
m_delivered=$(count_acks multi   || echo 0)

if [ "${b_delivered}" = "1" ] && [ "${m_delivered}" = "2" ]; then
    pass "filter: billing=1 multi=2"
else
    echo "WARN: expected billing=1/multi=2 but got billing=${b_delivered} multi=${m_delivered}"
    echo "      (MI scraping uses a best-effort FIFO readback; if 0 either test is failing or FIFO read raced)"
    fail "filter counts did not match"
fi
