# 410 — interleaved SIPp + KV traffic: 5 REGISTERs and 5 KV puts
# concurrently; both directions deliver.
case_begin "410_publish_after_kv_burst"

sub_out="$WORKDIR/410_sub.out"
( timeout 18 nats --server "$NATS_URL" sub test.sip.register --count=5 \
    > "$sub_out" 2>&1 ) &
sub_pid=$!
sleep 0.5

# 5 KV puts in background
pids=()
for i in $(seq 1 5); do
    kv_put TESTKV "burst-${$}-${i}" "v${i}" &
    pids+=( $! )
done

# 5 SIPp REGISTERs
sipp -sf "${HERE}/scenarios/register.xml" -m 5 -r 5 -i 127.0.0.1 -p 5071 \
     -timeout 15s -nostdin "${SIP_HOST}:${SIP_PORT}" \
     > "$WORKDIR/410_sipp.out" 2>&1

for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done

# wait for subscriber to drain 5 messages
for i in $(seq 1 12); do
    kill -0 "$sub_pid" 2>/dev/null || break
    sleep 1
done

regs=$(grep -c 'method=REGISTER' "$sub_out" 2>/dev/null || echo 0)
puts=$(grep -c "E_NATS_KV_CHANGE op=put key=burst-${$}-" "$WORKDIR/opensips.log")

if [ "$regs" -ge 5 ] && [ "$puts" -ge 5 ]; then
    check "5 SIPs + 5 KV puts interleave cleanly" ok \
        "regs=$regs puts=$puts"
else
    check "5 SIPs + 5 KV puts interleave cleanly" fail \
        "regs=$regs puts=$puts"
fi
