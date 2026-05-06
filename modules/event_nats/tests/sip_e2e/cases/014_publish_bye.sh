# 014 — SIPp BYE -> opensips -> NATS test.sip.bye
case_begin "014_publish_bye"

sub_out="$WORKDIR/014_sub.out"
sub_pid=$(nats_sub_oneshot "test.sip.bye" "$sub_out")
sleep 0.5

sipp_send "${HERE}/scenarios/bye.xml"

for i in $(seq 1 5); do kill -0 "$sub_pid" 2>/dev/null || break; sleep 1; done

if grep -q 'callid=' "$sub_out" && grep -q 'from=alice' "$sub_out"; then
    check "NATS receives BYE payload" ok
else
    check "NATS receives BYE payload" fail \
        "$(cat "$sub_out" 2>/dev/null | head -3)"
fi
