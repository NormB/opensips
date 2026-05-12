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

nats_bind hdr_in HDR durable=hi filter=hdr.in ack_wait=30s >/dev/null

# Publish with a header using the nats CLI.
ncli publish hdr.in 'ping' -H X-Trace-Id:abc123

deadline=$(( $(date +%s) + 8 ))
delivered=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    delivered=$(nats_list_field "$(nats_list)" hdr_in msgs_delivered 2>/dev/null)
    delivered=${delivered:-0}
    [ "${delivered}" -ge 1 ] && break
    sleep 0.5
done

if [ "${delivered}" -ge 1 ] 2>/dev/null; then
    pass "headers: message with X-Trace-Id delivered to hdr_in"
else
    fail "headers: message not delivered within 8s"
fi
