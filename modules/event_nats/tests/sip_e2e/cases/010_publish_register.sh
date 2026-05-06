# 010 — SIPp REGISTER -> opensips route -> nats_publish -> NATS subscriber
# Exercises: event_nats nats_publish() from script, $rm/$ru/$fU pvars,
# the most common forward path.
case_begin "010_publish_register"

stream_purge TEST

sub_out="$WORKDIR/010_sub.out"
sub_pid=$(nats_sub_oneshot "test.sip.register" "$sub_out")
sleep 0.5

sipp_send "${HERE}/scenarios/register.xml"
rc=$?
check "sipp REGISTER exits 0" \
    $([ "$rc" = 0 ] && echo ok || echo fail) "rc=$rc"

# wait for the subscriber to receive
for i in $(seq 1 5); do kill -0 "$sub_pid" 2>/dev/null || break; sleep 1; done

if grep -q 'method=REGISTER' "$sub_out" && \
   grep -q 'from=alice' "$sub_out"; then
    check "NATS subscriber receives REGISTER payload" ok
else
    check "NATS subscriber receives REGISTER payload" fail \
        "$(cat "$sub_out" 2>/dev/null | head -3)"
fi
