# 103 — multiple publishes are all delivered (not just the first).
# Depends on 100_consumer_bind_list having bound 'cmd'.
case_begin "103_consumer_multiple"

for i in 1 2 3 4 5; do
    publish_subject "test.sip.command" "multi-${$}-${i}"
done

# Timer drain pops ONE message per tick at 1s interval; with 5
# messages we need at least 5s.  Wait for the last one with a
# generous timeout that still fails fast on real regressions.
wait_for_log 12 "got NATS command: multi-${$}-5" || true
got=$(( $(log_count "got NATS command: multi-${$}-") ))

if [ "$got" -ge 5 ]; then
    check "5 published messages all delivered to script" ok
else
    check "5 published messages all delivered to script" fail \
        "expected >= 5 'got NATS command: multi-${$}-' lines, got $got"
fi
