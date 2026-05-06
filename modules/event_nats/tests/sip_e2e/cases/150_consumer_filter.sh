# 150 — bind with filter X.spec; only matching subject delivers.
case_begin "150_consumer_filter"

unbind_consumer cmd 2>/dev/null || true
sleep 1
consumer_rm TEST cmd
bind_consumer cmd TEST cmd "test.sip.command" "ack_wait=30s"
sleep 2

# Publish to a NON-matching subject (test.sip.invite is not test.sip.command)
publish_subject "test.sip.invite" "should-not-deliver-${$}"
sleep 2
if log_contains "got NATS command: should-not-deliver-${$}"; then
    check "filter rejects non-matching subject" fail
else
    check "filter rejects non-matching subject" ok
fi

# Publish to matching subject — delivers.
publish_subject "test.sip.command" "should-deliver-${$}"
if wait_for_log 8 "got NATS command: should-deliver-${$}"; then
    check "filter accepts matching subject" ok
else
    check "filter accepts matching subject" fail
fi
