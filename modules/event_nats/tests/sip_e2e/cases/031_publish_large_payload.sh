# 031 — large payload (close to but under PHASE3_FETCH/RING limits).
case_begin "031_publish_large_payload"

# 4 KiB random ASCII
big=$(head -c 4096 /dev/urandom | base64 | head -c 4096)
big_signature=$(echo "$big" | head -c 32)

sub_out="$WORKDIR/031_sub.out"
sub_pid=$(nats_sub_oneshot "test.large" "$sub_out")
sleep 0.5

publish_subject "test.large" "$big"
for i in $(seq 1 5); do kill -0 "$sub_pid" 2>/dev/null || break; sleep 1; done

if grep -q "${big_signature}" "$sub_out"; then
    check "4 KiB payload preserved on subscriber" ok
else
    check "4 KiB payload preserved on subscriber" fail \
        "$(wc -c < "$sub_out") bytes received"
fi
