#!/bin/bash
# test_ephemeral.sh -- ephemeral consumer GC + transparent recreation.
#
# 1. Bind an ephemeral handle with inactive_threshold=3s.
# 2. Publish + drain one message; that bumps delivered to 1.
# 3. Idle for 6s.  The broker GCs the ephemeral consumer.
# 4. Publish another message; consumer process detects the vanished
#    consumer, re-creates it, delivered bumps to 2.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/lib.sh"

ensure_stack
ensure_stream EPH 'eph.*'

nats_bind eph EPH ephemeral=1 filter=eph.msg inactive_threshold=3s >/dev/null

publish eph.msg 'pre'
sleep 2

read_delivered() {
    nats_list_field "$(nats_list)" eph msgs_delivered 2>/dev/null
}

pre=$(read_delivered)
pre=${pre:-0}
sleep 6   # past inactive_threshold
publish eph.msg 'post'
sleep 3
post=$(read_delivered)
post=${post:-0}

if [ "${post}" -gt "${pre}" ] 2>/dev/null; then
    pass "ephemeral recreate: delivered ${pre} -> ${post}"
else
    fail "ephemeral recreate: delivered stuck at ${pre} (post=${post})"
fi
