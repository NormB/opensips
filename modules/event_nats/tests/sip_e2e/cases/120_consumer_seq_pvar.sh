# 120 — $nats_seq pvar reflects stream sequence, increments per
# delivery.
case_begin "120_consumer_seq_pvar"

# Re-bind 'cmd' (was unbound by 110).
consumer_rm TEST cmd
bind_consumer cmd TEST cmd "test.sip.command" "ack_wait=30s"
sleep 2

base=$(log_count "got NATS command:")
publish_subject "test.sip.command" "seqcheck-${$}"

if wait_for_log 8 "got NATS command: seqcheck-${$}.*seq="; then
    check "got NATS command line includes seq= field" ok
else
    check "got NATS command line includes seq= field" fail \
        "expected 'seq=' in 'got NATS command' line"
fi
