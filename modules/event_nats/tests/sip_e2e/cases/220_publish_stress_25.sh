# 220 — 25 SIPp REGISTERs at 25 cps; verify all reach NATS.
case_begin "220_publish_stress_25"

sub_out="$WORKDIR/220_sub.out"
( timeout 18 nats --server "$NATS_URL" sub test.sip.register --count=25 \
    > "$sub_out" 2>&1 ) &
sub_pid=$!
sleep 0.5

sipp -sf "${HERE}/scenarios/register.xml" -m 25 -r 25 -i 127.0.0.1 -p 5071 \
     -timeout 20s -nostdin "${SIP_HOST}:${SIP_PORT}" \
     > "$WORKDIR/220_sipp.out" 2>&1

for i in $(seq 1 18); do
    kill -0 "$sub_pid" 2>/dev/null || break
    sleep 1
done

n=$(grep -c 'method=REGISTER' "$sub_out" 2>/dev/null || echo 0)
if [ "$n" -ge 25 ]; then
    check "stress: 25 SIP REGISTERs all reach NATS" ok
else
    check "stress: 25 SIP REGISTERs all reach NATS" fail \
        "received n=$n (expected >= 25)"
fi
