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
# Clear the OpenSIPS handle registry before binding: stale handles
# from prior tests whose broker-side consumers are gone retry their
# js_PullSubscribe every ~4 s and starve the worker tick that creates
# new consumers, pushing broker-readiness past any reasonable wait.
restart_opensips_clean

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
# from the producer side).
#
# The compose stack outlives test runs and js_AddConsumer falls back to
# js_UpdateConsumer for an existing durable -- but a JetStream durable
# is created with its initial config and the broker silently ignores
# most subsequent updates (max_ack_pending, ack_wait, ...).  A prior
# run that booted with stale max_ack_pending=1024 would therefore
# remain capped at 1024 even after this bind requests 16384, and the
# burst would stall on backpressure for minutes.
#
# Drop the durable on the broker and unbind any OpenSIPS-side handle
# so the bind below creates a fresh consumer at the current stream
# tip (deliver_policy=new) with exactly the configuration we ask for.
nats_unbind mw >/dev/null 2>&1 || true
ncli consumer rm MW mw -f >/dev/null 2>&1 || true

#
# fetch_batch=256 is what the proc-level comment in nats_consumer_proc.c
# cites as 'loopback measures ~89 000 msgs/sec vs. ~2 000 at the default
# of 10' -- the module-wide default is intentionally low (favors latency
# for trickle workloads), but a 10k-message stress burst at 10 msgs per
# 1 Hz tick caps at ~10 msgs/sec and would run for 16 min.
nats_bind mw MW durable=mw filter=mw.job ack_wait=600s \
    deliver_policy=new \
    fetch_batch=256 \
    max_ack_pending=16384 ring_capacity=16384 >/dev/null

# Wait for the worker tick (~1s) to actually call js_AddConsumer +
# js_PullSubscribe before we publish.  Without this, publishes can
# land before the DeliverPolicy=New snapshot point and disappear.
# 60 s upper bound -- when run as part of the full suite the opensips
# container has ~12 prior-test handles in the registry and the per-tick
# foreach is materially slower; in isolation the consumer shows up
# under a second.
readiness_wait=60
deadline=$(( $(date +%s) + readiness_wait ))
broker_ready=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    names=$(ncli consumer ls MW --names 2>/dev/null || true)
    case "$names" in
        *mw*) broker_ready=1; break ;;
    esac
    sleep 0.5
done
if [ "${broker_ready}" != "1" ]; then
    fail "multi_worker: broker did not create consumer 'mw' on MW within ${readiness_wait}s"
    exit 1
fi

# Fresh durable -> counters start at 0.  Keep snapshotting in case the
# OpenSIPS-side msgs_delivered field carries over for some reason.
list_start=$(nats_list 2>/dev/null || true)
start_delivered=$(nats_list_field "${list_start}" mw msgs_delivered 2>/dev/null || echo 0)
start_redeliveries=$(nats_list_field "${list_start}" mw redeliveries 2>/dev/null || echo 0)
start_delivered=${start_delivered:-0}
start_redeliveries=${start_redeliveries:-0}

echo "publishing ${N_MESSAGES} messages (start_delivered=${start_delivered}, start_redeliveries=${start_redeliveries})..."
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

# Wait for the per-run delivery delta to reach N_MESSAGES, then check
# per-run redelivery delta is zero.
deadline=$(( $(date +%s) + 120 ))
delivered=0; redeliveries=0
delta_delivered=0; delta_redeliveries=0
while [ $(date +%s) -lt ${deadline} ]; do
    list_out=$(nats_list 2>/dev/null)
    delivered=$(nats_list_field "${list_out}" mw msgs_delivered 2>/dev/null)
    redeliveries=$(nats_list_field "${list_out}" mw redeliveries 2>/dev/null)
    delivered=${delivered:-0}
    redeliveries=${redeliveries:-0}
    delta_delivered=$(( delivered - start_delivered ))
    delta_redeliveries=$(( redeliveries - start_redeliveries ))
    if [ "${delta_delivered}" -ge "${N_MESSAGES}" ] 2>/dev/null; then
        if [ "${delta_redeliveries}" -eq 0 ] 2>/dev/null; then
            pass "multi_worker: ${delta_delivered} delivered (cumulative ${delivered}), 0 redeliveries this run"
            exit 0
        else
            fail "multi_worker: ${delta_redeliveries} redeliveries this run (expected 0; cumulative ${redeliveries})"
        fi
    fi
    sleep 2
done

fail "multi_worker: did not reach ${N_MESSAGES} new deliveries in 120s (last delta=${delta_delivered}, cumulative=${delivered})"
