# 300 — full call flow: REGISTER + INVITE + BYE in one scenario; each
# triggers its own NATS publish.  Validates that one opensips serves
# multiple SIP methods correctly without bleed.
case_begin "300_full_call_flow"

# subscribe to all three subjects in parallel
sub_reg="$WORKDIR/300_reg.out"
sub_inv="$WORKDIR/300_inv.out"
sub_bye="$WORKDIR/300_bye.out"

( timeout 8 nats --server "$NATS_URL" sub test.sip.register --count=1 > "$sub_reg" 2>&1 ) &
p1=$!
( timeout 8 nats --server "$NATS_URL" sub test.sip.invite --count=1   > "$sub_inv" 2>&1 ) &
p2=$!
( timeout 8 nats --server "$NATS_URL" sub test.sip.bye --count=1      > "$sub_bye" 2>&1 ) &
p3=$!
sleep 0.5

sipp_send "${HERE}/scenarios/register.xml"
sleep 0.3
sipp_send "${HERE}/scenarios/invite.xml"
sleep 0.3
sipp_send "${HERE}/scenarios/bye.xml"

for i in $(seq 1 8); do
    kill -0 "$p1" 2>/dev/null || \
    kill -0 "$p2" 2>/dev/null || \
    kill -0 "$p3" 2>/dev/null || break
    sleep 1
done

ok_reg=$(grep -q 'method=REGISTER' "$sub_reg" 2>/dev/null && echo ok || echo fail)
ok_inv=$(grep -q 'callid='         "$sub_inv" 2>/dev/null && echo ok || echo fail)
ok_bye=$(grep -q 'callid='         "$sub_bye" 2>/dev/null && echo ok || echo fail)

check "REGISTER reaches test.sip.register" "$ok_reg"
check "INVITE   reaches test.sip.invite"   "$ok_inv"
check "BYE      reaches test.sip.bye"      "$ok_bye"
