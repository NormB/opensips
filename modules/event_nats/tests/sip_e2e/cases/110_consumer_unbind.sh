# 110 — unbind 'cmd' handle, verify subsequent publishes don't deliver.
# Runs LAST among consumer cases so 102/103 still see the handle bound.
case_begin "110_consumer_unbind"

unbind_consumer cmd
sleep 2

base=$(log_count "got NATS command: post-unbind")
publish_subject "test.sip.command" "post-unbind-$$"
sleep 3
got=$(log_count "got NATS command: post-unbind")

if [ "$got" = "$base" ]; then
    check "unbound handle stops delivering messages" ok
else
    check "unbound handle stops delivering messages" fail \
        "post-unbind delivered $((got - base)) extra; expected 0"
fi
