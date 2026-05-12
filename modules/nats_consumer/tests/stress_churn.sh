#!/bin/bash
# stress_churn.sh -- bind/unbind churn alongside steady fetch.
#
# For DURATION seconds (default 900 = 15 min, overridable via env), each
# second we:
#   - bind a fresh ephemeral handle (id=c_<epoch>)
#   - unbind the oldest handle past a retention window of 10 entries
#   - publish one message on mw.job to keep the long-lived 'mw' handle
#     draining (if previously bound; otherwise we skip the publish)
# After the run:
#   - nats_consumer_list count should be bounded (<= 20).
#   - opensips main process memory (RSS) should not grow unboundedly
#     (<= 2x start).  We snapshot `ps -o rss=` at start and end.
#   - MI must still respond (round-trip nats_consumer_list succeeds).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/lib.sh"

ensure_stack

DURATION="${DURATION:-900}"  # 15 minutes
ensure_stream MW 'mw.>'

# Long-lived steady-fetch handle (exercised by the default drain timer
# only if we rename -- just leave unacked; the intent is "traffic on
# the rings while churn happens").
nats_bind mw MW durable=mw filter=mw.job ack_wait=60s max_ack_pending=1024 >/dev/null

snap_rss() {
    ${COMPOSE} exec -T opensips sh -c 'ps -o rss= -p 1 | tr -d " "'
}

start_rss=$(snap_rss || echo 0)
echo "start_rss=${start_rss} kB, running churn for ${DURATION}s..."

history=()
end=$(( $(date +%s) + DURATION ))
while [ $(date +%s) -lt ${end} ]; do
    ts=$(date +%s%N)
    id="c_${ts}"
    nats_bind "${id}" MW ephemeral=1 filter=mw.job inactive_threshold=5m >/dev/null

    history+=("${id}")

    # retention: when history >= 10, unbind the oldest
    if [ "${#history[@]}" -ge 10 ]; then
        oldest="${history[0]}"
        history=("${history[@]:1}")
        nats_unbind "${oldest}" >/dev/null
    fi

    publish mw.job "churn-${ts}" >/dev/null 2>&1 || true
    sleep 1
done

end_rss=$(snap_rss || echo 0)
echo "end_rss=${end_rss} kB"

# MI responsiveness check.
list_out=$(nats_list 2>/dev/null) || fail "churn: MI did not respond after churn"

handle_count=$(python3 -c "
import json,sys
env=json.loads('''${list_out}''')
res=env.get('result', [])
handles = res if isinstance(res, list) else res.get('handles', [])
print(len(handles))
" 2>/dev/null || echo -1)

if [ "${handle_count}" = "-1" ]; then
    fail "churn: could not parse MI list output"
fi

# retention window is 10; add 'mw' + default 'test' => <= 12; allow 20
if [ "${handle_count}" -gt 20 ] 2>/dev/null; then
    fail "churn: handle_count=${handle_count} > 20 (unbind/reap regression)"
fi

# RSS bound (start * 2).  Skip check if start_rss was 0 (snap failed).
if [ "${start_rss}" -gt 0 ] 2>/dev/null && [ "${end_rss}" -gt 0 ] 2>/dev/null; then
    max=$(( start_rss * 2 ))
    if [ "${end_rss}" -gt "${max}" ] 2>/dev/null; then
        fail "churn: RSS grew ${start_rss} -> ${end_rss} kB (> 2x)"
    fi
fi

pass "churn: duration=${DURATION}s handles_end=${handle_count} rss=${start_rss}->${end_rss}"
