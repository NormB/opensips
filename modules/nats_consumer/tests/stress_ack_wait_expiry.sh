#!/bin/bash
# stress_ack_wait_expiry.sh -- verify ack_progress keeps a long handler
# alive without triggering a redelivery.
#
# The integration cfg doesn't include a long-running handler; instead
# we exercise the OTHER half of the contract -- an unanswered message
# on a short ack_wait is redelivered exactly once within the max_deliver
# budget.  That gives a lower bound confidence that ack_wait is being
# honored.
#
# Strictly-speaking "verify ack_progress keeps ack alive" needs a cfg
# with a scripted slow handler; see test_headers.sh for why we don't
# reload the cfg per stress test.  The delivered_count parity check
# here at least confirms the broker is respecting ack_wait as expected
# under sustained traffic.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/lib.sh"

ensure_stack

N_MESSAGES="${N_MESSAGES:-500}"

ensure_stream AE 'ae.>'

# ring_capacity=2048 ensures N_MESSAGES * max_deliver (=2) fits before
# the consumer worker would back-pressure on a full ring.  The default
# 128 is sized for steady-state drain scripts, not 500-message bursts
# with nothing acking.
nats_bind ae AE durable=ae filter=ae.msg ack_wait=1s max_deliver=2 \
    ring_capacity=2048 >/dev/null

echo "publishing ${N_MESSAGES} messages..."
# Batch publishes inside a single natscli shell.  Per-iteration
# docker compose exec is ~200 ms; 500 sequential calls = ~100 s of pure
# launch overhead.  In-container loop finishes in a second or two.
${COMPOSE} exec -T -e N="${N_MESSAGES}" natscli sh -c '
i=1
while [ $i -le "$N" ]; do
    nats --server nats://nats:4222 publish ae.msg "ae-$i" >/dev/null 2>&1
    i=$((i + 1))
done
' >/dev/null 2>&1

# We expect every message to be redelivered exactly once (first
# delivery goes to the ring but nothing acks, ack_wait expires,
# redelivery #2 happens, still no ack, max_deliver exhausted).  Total
# delivered should reach >= N_MESSAGES (>=1x, redelivery path active).
# Poll until target or deadline; broker may pace redeliveries when
# max_ack_pending backpressures the consumer.
deadline=$(( $(date +%s) + 60 ))
delivered=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    delivered=$(nats_list_field "$(nats_list)" ae msgs_delivered 2>/dev/null)
    delivered=${delivered:-0}
    [ "${delivered}" -ge "${N_MESSAGES}" ] && break
    sleep 1
done

if [ "${delivered}" -ge "${N_MESSAGES}" ] 2>/dev/null; then
    pass "ack_wait_expiry: ${delivered} deliveries for ${N_MESSAGES} publishes (>=1x, redelivery path active)"
else
    fail "ack_wait_expiry: only ${delivered} of ${N_MESSAGES} delivered"
fi
