# 011 — SIPp INVITE -> opensips -> NATS test.sip.invite
# Exercises: nats_publish on a different subject, $ci (Call-ID) pvar.
case_begin "011_publish_invite"

sub_out="$WORKDIR/011_sub.out"
sub_pid=$(nats_sub_oneshot "test.sip.invite" "$sub_out")
sleep 0.5

sipp_send "${HERE}/scenarios/invite.xml"

for i in $(seq 1 5); do kill -0 "$sub_pid" 2>/dev/null || break; sleep 1; done

if grep -q 'callid=' "$sub_out" && grep -q 'from=alice' "$sub_out"; then
    check "NATS subscriber receives INVITE payload" ok
else
    check "NATS subscriber receives INVITE payload" fail \
        "$(cat "$sub_out" 2>/dev/null | head -3)"
fi
