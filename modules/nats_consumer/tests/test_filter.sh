#!/bin/bash
# test_filter.sh -- integration test for single + multi subject filters.
#
# Binds two handles:
#   billing: stream=CALLS, filter=calls.ended,             deliver_policy=new
#   multi:   stream=CALLS, filters=calls.ended,calls.failed deliver_policy=new
# Publishes messages on calls.ended + calls.started + calls.failed,
# asserts each handle receives only what its filter allows.
#
# The CALLS stream persists for the life of the compose stack so
# without deliver_policy=new each fresh durable would replay all
# historical calls.* messages from prior runs and the absolute-count
# assertion would fire long after a single test pass.  We also rm
# the durables on the broker at the start so the consumer is created
# at the current stream tip (DeliverPolicy=New uses the stream's
# current sequence at consumer-creation time).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/lib.sh"

ensure_stack
ensure_stream CALLS 'calls.>'

# Best-effort reset: unbind any prior OpenSIPS handles, then drop the
# durables on the broker.  Both are idempotent.
nats_unbind billing >/dev/null 2>&1 || true
nats_unbind multi   >/dev/null 2>&1 || true
ncli consumer rm CALLS b1 -f >/dev/null 2>&1 || true
ncli consumer rm CALLS m1 -f >/dev/null 2>&1 || true

nats_bind billing CALLS durable=b1 filter=calls.ended \
    deliver_policy=new ack_wait=30s >/dev/null
nats_bind multi   CALLS durable=m1 filters=calls.ended,calls.failed \
    deliver_policy=new ack_wait=30s >/dev/null

# nats_bind returns once the handle is in the registry, but the worker
# tick (~1s cadence) is what actually fires js_AddConsumer + js_PullSubscribe
# on the broker.  Without waiting here we publish into the void: messages
# land before the consumer's DeliverPolicy=New snapshot point.
deadline=$(( $(date +%s) + 10 ))
have=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    names=$(ncli consumer ls CALLS --names 2>/dev/null || true)
    have_b=0; have_m=0
    case "$names" in
        *b1*) have_b=1 ;;
    esac
    case "$names" in
        *m1*) have_m=1 ;;
    esac
    if [ "${have_b}" = "1" ] && [ "${have_m}" = "1" ]; then
        have=2
        break
    fi
    sleep 0.5
done
if [ "${have}" != "2" ]; then
    fail "filter: broker did not create both b1+m1 in 10s (saw='${names:-}')"
    exit 1
fi

publish calls.started '{"id":"x"}'
publish calls.ended   '{"id":"y"}'
publish calls.failed  '{"id":"z"}'

# billing should see exactly 1 (calls.ended), multi exactly 2 (ended+failed).
deadline=$(( $(date +%s) + 15 ))
b_delivered=0; m_delivered=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    list_out=$(nats_list 2>/dev/null || true)
    b_delivered=$(nats_list_field "${list_out}" billing msgs_delivered 2>/dev/null)
    m_delivered=$(nats_list_field "${list_out}" multi   msgs_delivered 2>/dev/null)
    b_delivered=${b_delivered:-0}
    m_delivered=${m_delivered:-0}
    if [ "${b_delivered}" -ge 1 ] && [ "${m_delivered}" -ge 2 ]; then
        break
    fi
    sleep 1
done

if [ "${b_delivered}" = "1" ] && [ "${m_delivered}" = "2" ]; then
    pass "filter: billing=1 multi=2"
else
    fail "filter counts did not match: billing=${b_delivered} (want 1) multi=${m_delivered} (want 2)"
fi
