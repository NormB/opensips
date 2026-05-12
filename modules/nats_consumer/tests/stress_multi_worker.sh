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

# ring_capacity=16384 fits a 10k burst comfortably even without per-message
# script acks.  Default ring (128) would backpressure-drop everything past
# the 128th delivery and the test would never reach N_MESSAGES.
# max_ack_pending must be >= N_MESSAGES so the broker doesn't block
# waiting for acks before delivering the full burst.  ack_wait=600s
# makes sure that any message that arrives in the ring has plenty of
# time to be drained + acked by the drain_mw timer (which runs at 1 Hz
# with a 16-call unroll, so the worst-case latency from ring-push to
# ack is ~1 s, but a stalled drain can fall behind under bursty load
# from the producer side).  Without this, the broker considers any
# message older than ack_wait as a redelivery candidate and the test
# fails its "0 redeliveries" assertion.
nats_bind mw MW durable=mw filter=mw.job ack_wait=600s \
    max_ack_pending=16384 ring_capacity=16384 >/dev/null

echo "publishing ${N_MESSAGES} messages..."
# One docker exec amortises the publish overhead -- 10000 individual
# `docker compose exec natscli` calls take ~30 minutes; batched in-line
# inside a single natscli shell it takes ~20 seconds.
${COMPOSE} exec -T -e N="${N_MESSAGES}" natscli sh -c '
i=1
while [ $i -le "$N" ]; do
    nats --server nats://nats:4222 publish mw.job "job-$i" >/dev/null 2>&1
    i=$((i + 1))
done
' >/dev/null 2>&1

# Wait for delivery counter to reach target.
deadline=$(( $(date +%s) + 120 ))
delivered=0; redeliveries=0
while [ $(date +%s) -lt ${deadline} ]; do
    list_out=$(nats_list 2>/dev/null)
    delivered=$(nats_list_field "${list_out}" mw msgs_delivered 2>/dev/null)
    redeliveries=$(nats_list_field "${list_out}" mw redeliveries 2>/dev/null)
    delivered=${delivered:-0}
    redeliveries=${redeliveries:-0}
    if [ "${delivered}" -ge "${N_MESSAGES}" ] 2>/dev/null; then
        if [ "${redeliveries}" -eq 0 ] 2>/dev/null; then
            pass "multi_worker: ${delivered} delivered, 0 redeliveries"
            exit 0
        else
            fail "multi_worker: ${redeliveries} redeliveries (expected 0)"
        fi
    fi
    sleep 2
done

fail "multi_worker: did not reach ${N_MESSAGES} deliveries in 120s (last delivered=${delivered})"
