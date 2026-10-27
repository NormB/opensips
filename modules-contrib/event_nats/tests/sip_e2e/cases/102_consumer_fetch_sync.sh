# 102 — nats_consumer pull: publish -> ring -> timer drain -> xlog
# Depends on 100_consumer_bind_list having bound the 'cmd' handle.
case_begin "102_consumer_fetch_sync"

payload="hello-fetch-$(date +%s%N)"
publish_subject "test.sip.command" "$payload"

if wait_for_log 5 "got NATS command: ${payload}"; then
    check "timer_route delivers published message to script" ok
else
    check "timer_route delivers published message to script" fail \
        "expected: got NATS command: ${payload}"
fi
