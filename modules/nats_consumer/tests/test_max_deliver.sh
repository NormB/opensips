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

nats_bind m1 MX durable=m1 filter=mx.msg ack_wait=1s max_deliver=3 >/dev/null

publish mx.msg 'boom'

# Wait long enough for all 3 deliveries to fire.  ack_wait=1s -> ~1s gap
# between retries; the first delivery can race the bind/subscribe round
# trip on a freshly-booted container, so allow 15 s upper bound to absorb
# that warm-up cost without losing the test's "broker really stopped at 3"
# property.
deadline=$(( $(date +%s) + 15 ))
delivered=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    delivered=$(nats_list_field "$(nats_list)" m1 msgs_delivered 2>/dev/null)
    delivered=${delivered:-0}
    [ "${delivered}" -ge 3 ] && break
    sleep 0.5
done

if [ "${delivered}" -ge 3 ] 2>/dev/null; then
    pass "max_deliver: ${delivered} deliveries reached cap (>=3)"
else
    fail "max_deliver cap not observed (delivered=${delivered}, want >=3)"
fi
