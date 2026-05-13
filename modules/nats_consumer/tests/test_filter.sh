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

nats_bind billing CALLS durable=b1 filter=calls.ended ack_wait=30s >/dev/null
nats_bind multi   CALLS durable=m1 filters=calls.ended,calls.failed ack_wait=30s >/dev/null

publish calls.started '{"id":"x"}'
publish calls.ended   '{"id":"y"}'
publish calls.failed  '{"id":"z"}'

# billing should see exactly 1 (calls.ended), multi exactly 2 (ended+failed).
# Poll counters until both reach their targets or we time out.
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

# Known flake: test passes on a fresh compose stack but the durable
# 'billing'/'multi' consumers accumulate cumulative msgs_delivered
# across runs.  Attempts to use run-unique ephemeral consumers with
# deliver_policy=new showed that the multi-subject `filters=` flow
# delivers 0 messages even with the consumer freshly created from the
# stream tip, suggesting a deeper bug in nats_consumer_proc's
# js_AddConsumer wiring for FilterSubjects[].  Leaving the original
# absolute-count assertion in place pending that investigation.
if [ "${b_delivered}" = "1" ] && [ "${m_delivered}" = "2" ]; then
    pass "filter: billing=1 multi=2"
else
    fail "filter counts did not match: billing=${b_delivered} (want 1) multi=${m_delivered} (want 2)"
fi
