# 210 — high-rate publish from script: 10 SIPp REGISTERS in quick
# succession; verify all 10 land on the NATS subject.
case_begin "210_publish_burst"

sub_out="$WORKDIR/210_sub.out"
( timeout 12 nats --server "$NATS_URL" sub test.sip.register --count=10 \
    > "$sub_out" 2>&1 ) &
sub_pid=$!
sleep 0.5

# Send 10 REGISTER calls back-to-back.
sipp -sf "${HERE}/scenarios/register.xml" -m 10 -r 10 -i 127.0.0.1 -p 5071 \
     -timeout 15s -nostdin "${SIP_HOST}:${SIP_PORT}" \
     > "$WORKDIR/210_sipp.out" 2>&1

for i in $(seq 1 12); do
    kill -0 "$sub_pid" 2>/dev/null || break
    sleep 1
done

n=$(grep -c 'method=REGISTER' "$sub_out" 2>/dev/null || echo 0)
if [ "$n" -ge 10 ]; then
    check "burst of 10 SIP REGISTERs all reach NATS" ok
else
    check "burst of 10 SIP REGISTERs all reach NATS" fail \
        "received n=$n (expected >= 10)"
fi
