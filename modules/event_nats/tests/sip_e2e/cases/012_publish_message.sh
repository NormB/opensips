# 012 — SIPp MESSAGE -> opensips -> NATS test.sip.message (with body)
# Exercises: $rb (request body) pvar through nats_publish.
case_begin "012_publish_message"

sub_out="$WORKDIR/012_sub.out"
sub_pid=$(nats_sub_oneshot "test.sip.message" "$sub_out")
sleep 0.5

sipp_send "${HERE}/scenarios/message.xml"

for i in $(seq 1 5); do kill -0 "$sub_pid" 2>/dev/null || break; sleep 1; done

if grep -q 'from=alice' "$sub_out" && grep -q 'hello-from-sipp' "$sub_out"; then
    check "NATS receives MESSAGE with body forwarded" ok
else
    check "NATS receives MESSAGE with body forwarded" fail \
        "$(cat "$sub_out" 2>/dev/null | head -3)"
fi
