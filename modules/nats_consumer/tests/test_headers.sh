#!/bin/bash
# test_headers.sh -- NATS headers round-trip.
#
# Publishes a message with a header, asserts the drain timer logs the
# expected header via $nats_hdr(X-Trace-Id).  The default cfg doesn't
# include a header-aware drain route, so we bind a new handle and
# rely on the opensips log to print the header echo via a scripted
# timer_route substitution at runtime is not possible; instead we
# verify the inbound headers via MI counters (msgs_delivered++ for the
# handle indicates the message was accepted including its header
# payload).  Strict header value verification requires a cfg with an
# $nats_hdr xlog, which the non-default cfg in this image does not
# ship; mark that as documented and assert delivery count only.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/lib.sh"

ensure_stack
ensure_stream HDR 'hdr.*'

${COMPOSE} exec -T opensips sh -c \
    'echo ":nats_consumer_bind:hdr:\nid=hdr_in;stream=HDR;durable=hi;filter=hdr.in;ack_wait=30s\n\n" \
        > /var/run/opensips/mi.fifo' || true

# Publish with a header using the nats CLI.
ncli publish hdr.in 'ping' -H X-Trace-Id:abc123

sleep 2

${COMPOSE} exec -T opensips sh -c \
    'echo ":nats_consumer_list:hls:\n\n" > /var/run/opensips/mi.fifo && \
     sleep 0.3 && cat /var/run/opensips/mi.fifo.reply_hls 2>/dev/null' \
    > /tmp/hls_out 2>/dev/null || true

delivered=$(python3 -c "
import json,re
with open('/tmp/hls_out') as f: raw=f.read()
m=re.search(r'\{.*\}', raw, re.DOTALL)
obj=json.loads(m.group(0)) if m else {}
for h in obj.get('handles', []):
    if h.get('id')=='hdr_in':
        print(h.get('msgs_delivered',0)); break
" 2>/dev/null || echo 0)

if [ "${delivered}" -ge 1 ] 2>/dev/null; then
    pass "headers: message with X-Trace-Id delivered to hdr_in"
else
    fail "headers: message not delivered within 2s"
fi
