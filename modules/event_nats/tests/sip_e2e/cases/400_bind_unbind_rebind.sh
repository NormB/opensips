# 400 — bind, publish, unbind, publish (no deliver), rebind, publish
# (delivers again).  Lifecycle for the consumer subscription.
case_begin "400_bind_unbind_rebind"

# Setup: cmd may be bound from earlier cases — unbind via MI first
# (server-side consumer_rm alone leaves the registry entry, and a
# fresh bind would 409-conflict).
unbind_consumer cmd 2>/dev/null || true
sleep 1
consumer_rm TEST cmd
bind_consumer cmd TEST cmd "test.sip.command" "ack_wait=30s"
sleep 2

# 1. bound: publish should deliver
publish_subject "test.sip.command" "stage1-${$}"
if wait_for_log 8 "got NATS command: stage1-${$}"; then
    check "stage 1 (bound): delivery works" ok
else
    check "stage 1 (bound): delivery works" fail
fi

# 2. unbind
unbind_consumer cmd
sleep 2

# 3. publish (must NOT deliver to the script -- handle is gone)
publish_subject "test.sip.command" "stage2-${$}"
sleep 3
if log_contains "got NATS command: stage2-${$}"; then
    check "stage 2 (unbound): no delivery" fail
else
    check "stage 2 (unbound): no delivery" ok
fi

# 4. rebind
bind_consumer cmd TEST cmd "test.sip.command" "ack_wait=30s"
sleep 2

# 5. publish: deliver again.  The durable consumer 'cmd' picks up
#    everything since its last ack, INCLUDING stage2 messages it
#    didn't deliver while unbound (durable consumers persist their
#    cursor server-side).  Verify at least the new stage3 lands.
publish_subject "test.sip.command" "stage3-${$}"
if wait_for_log 8 "got NATS command: stage3-${$}"; then
    check "stage 5 (rebound): delivery works again" ok
else
    check "stage 5 (rebound): delivery works again" fail
fi
