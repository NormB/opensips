# 013 — SIPp OPTIONS -> opensips -> NATS test.sip.options
case_begin "013_publish_options"

sub_out="$WORKDIR/013_sub.out"
sub_pid=$(nats_sub_oneshot "test.sip.options" "$sub_out")

sipp_send "${HERE}/scenarios/options.xml"

for i in $(seq 1 5); do kill -0 "$sub_pid" 2>/dev/null || break; sleep 1; done

if grep -q 'from=ping' "$sub_out"; then
    check "NATS receives OPTIONS payload" ok
else
    check "NATS receives OPTIONS payload" fail \
        "$(cat "$sub_out" 2>/dev/null | head -3)"
fi
