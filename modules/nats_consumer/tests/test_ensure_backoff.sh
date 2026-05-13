#!/bin/bash
# test_ensure_backoff.sh -- pin the per-handle backoff for
# ensure_subscription_for_handle() failures.
#
# Before the backoff landed, a handle whose broker-side consumer was
# deleted (operator typed `nats consumer rm`, or a prior test left the
# registry pointing at a now-gone durable) would retry its
# js_AddConsumer / js_PullSubscribe sequence every reconcile tick
# (IDLE_RETRY_MS = 1 s default) for as long as opensips ran -- floods
# the log and starves real work.  See nats_consumer_proc.c
# reconcile_subs_cb() + ensure_backoff_seconds() for the schedule
# (1, 2, 4, 8, 16, 32, then capped at 60 s).
#
# What this test pins:
#
#   - In a 25 s window after the durable is deleted, the worker logs
#     at most ENSURE_MAX_ATTEMPTS attempts.  Without backoff that
#     window would produce ~25 attempts; with the schedule the worker
#     fires at t=0, +1, +2, +4, +8, +16 -- i.e. <= 6 inside 25 s.
#
#   - After a successful rebind (we recreate the broker-side consumer
#     and watch for the "recovered after N failed ensure attempt(s)"
#     INFO line), the backoff resets so the next failure starts at
#     the 1 s base again.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/lib.sh"

ensure_stack
# Wipe the handle registry so prior tests don't bias the timing.
restart_opensips_clean

STREAM="EB_NOPE"             # intentionally not created
DURABLE="eb"
ID="eb"
ENSURE_MAX_ATTEMPTS=8           # generous: cap is 6 retries in 25 s + jitter
OBSERVE_S=25

# Clean slate -- prior runs may have left the handle behind.  Also make
# sure no stream by this name exists (defensive against test ordering).
nats_unbind "${ID}" >/dev/null 2>&1 || true
ncli stream rm "${STREAM}" -f >/dev/null 2>&1 || true

# Bind a handle pointing at a stream that does NOT exist on the broker.
# Every reconcile tick the worker will call js_AddConsumer against the
# missing stream and the broker will return "stream not found" -- a
# hard failure that exercises the backoff path without needing the
# fetch-side "consumer vanished" trigger.
nats_bind "${ID}" "${STREAM}" durable="${DURABLE}" filter=eb.msg \
    deliver_policy=new ack_wait=5s max_deliver=1 >/dev/null
echo "[$(date +%s)] bound handle pointing at missing stream '${STREAM}'; "
echo "  observing for ${OBSERVE_S}s"

# Anchor: the mi_consumer_bind INFO line for this bind is unique per
# run (carries the handle id + stream).  Count failures AFTER that
# line.  We rely on the line being unique within the current run --
# the loop above wiped the handle and there's no other bind in this
# test, so the very first bind log line is ours.
BIND_ANCHOR="bound handle id=${ID} stream=${STREAM}"

sleep "${OBSERVE_S}"

# Count ensure_subscription failures after the bind anchor.  The
# error line is emitted from ensure_subscription_for_handle()'s
# failure branches -- either js_AddConsumer or js_PullSubscribe (the
# broker may reject at either step; missing-stream surfaces as
# js_PullSubscribe).  The parenthesised argument is the durable
# name, which here equals our ID.
attempts=$(${COMPOSE} logs --no-color opensips 2>/dev/null \
    | awk -v anchor="${BIND_ANCHOR}" -v id="${ID}" '
        # Reset on every anchor match.  Container logs span multiple
        # test runs (compose restart doesnt truncate journald output);
        # we want failures only after the most recent bind.
        index($0, anchor) > 0 { seen=1; n=0; next }
        seen && /ERROR:nats_consumer:ensure_subscription_for_handle/ &&
                index($0, "(\047" id "\047)") > 0 { n++ }
        END { print n+0 }')

echo "  attempts in ${OBSERVE_S}s window: ${attempts}"
if [ "${attempts}" -gt "${ENSURE_MAX_ATTEMPTS}" ]; then
    fail "backoff: ${attempts} attempts in ${OBSERVE_S}s (expected <= ${ENSURE_MAX_ATTEMPTS})"
fi
if [ "${attempts}" -lt 2 ]; then
    # Less than 2 means we never saw a real retry -- the test would be
    # trivially passing without exercising the backoff at all.
    fail "backoff: only ${attempts} attempts in ${OBSERVE_S}s; expected >= 2 (test is not exercising the path)"
fi
pass "attempts respect backoff schedule (${attempts} in ${OBSERVE_S}s, cap=${ENSURE_MAX_ATTEMPTS})"

# MI surface: nats_consumer_list must expose ensure_failures and
# ensure_next_retry_at per-handle so operators can spot a wedged
# handle without grepping the log.  Non-zero ensure_failures on a
# handle whose stream doesn't exist is the load-bearing signal.
list_env=$(nats_list)
ensure_failures=$(nats_list_field "${list_env}" "${ID}" ensure_failures)
ensure_next=$(nats_list_field "${list_env}" "${ID}" ensure_next_retry_at)
if [ -z "${ensure_failures}" ] || [ "${ensure_failures}" = "0" ]; then
    fail "MI: nats_consumer_list returned ensure_failures='${ensure_failures}' for wedged handle (expected non-zero)"
fi
if [ -z "${ensure_next}" ] || [ "${ensure_next}" = "0" ]; then
    fail "MI: nats_consumer_list returned ensure_next_retry_at='${ensure_next}' for wedged handle (expected non-zero unix-time)"
fi
pass "MI list exposes ensure_failures=${ensure_failures} ensure_next_retry_at=${ensure_next}"

# Recovery: create the stream that's been missing.  The next reconcile
# tick succeeds (js_AddConsumer creates the durable inline now that the
# stream exists), the recovery INFO fires, and the counter resets.
ensure_stream "${STREAM}" 'eb.>'
echo "[$(date +%s)] created broker-side stream; waiting for recovery"

# At cap the next retry is up to 60 s away, so allow that plus a bit
# of slack for the broker-side AddConsumer to take effect.
deadline=$(( $(date +%s) + 75 ))
recovered=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    if ${COMPOSE} logs --no-color opensips 2>/dev/null \
        | grep -q "handle '${ID}' recovered after"; then
        recovered=1; break
    fi
    sleep 1
done
[ "${recovered}" = "1" ] || fail "backoff: no 'recovered after N failed ensure attempt(s)' log line within 75 s"
pass "handle reported recovery after broker-side durable was recreated"

# Cleanup
nats_unbind "${ID}" >/dev/null 2>&1 || true
ncli consumer rm "${STREAM}" "${DURABLE}" -f >/dev/null 2>&1 || true
echo "==== ensure_backoff OK ===="
