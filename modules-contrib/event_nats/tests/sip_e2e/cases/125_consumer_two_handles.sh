# 125 — two consumer handles, each filtering a different subject.
# Both deliver independently.
case_begin "125_consumer_two_handles"

# 'cmd' is still bound from 120; unbind it first via MI (otherwise
# the rebind returns 409 dup), then drop the server-side JS consumer
# state.
unbind_consumer cmd
unbind_consumer cmd2
sleep 1
consumer_rm TEST cmd
consumer_rm TEST cmd2
bind_consumer cmd  TEST cmd  "test.sip.command" "ack_wait=30s"
bind_consumer cmd2 TEST cmd2 "test.sip.alt"     "ack_wait=30s"
sleep 2

# We can't test cmd2 via the timer drain since the cfg only drains
# 'cmd'.  Instead, verify cmd2 sees deliveries on the JS side
# (consumer_info ack-floor advances) and cmd does too on the
# expected subject.

publish_subject "test.sip.command" "for-cmd-${$}"
publish_subject "test.sip.alt"     "for-cmd2-${$}"

# 'cmd' has the timer drain; wait for its log line.
if wait_for_log 8 "got NATS command: for-cmd-${$}"; then
    check "handle 'cmd' delivers test.sip.command" ok
else
    check "handle 'cmd' delivers test.sip.command" fail
fi

# 'cmd2' has no script drain; check the JS server-side that the
# consumer received its message.
delivered=$(n consumer info TEST cmd2 --json 2>/dev/null | \
    python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get("delivered", {}).get("stream_seq", 0))
except Exception:
    print(0)
' 2>/dev/null)

if [ "${delivered:-0}" -ge 1 ]; then
    check "handle 'cmd2' receives its message server-side" ok \
        "delivered_stream_seq=$delivered"
else
    check "handle 'cmd2' receives its message server-side" fail \
        "delivered=$delivered"
fi

unbind_consumer cmd2
