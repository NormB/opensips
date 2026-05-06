# 027 — JetStream MI: nats_stream_purge resets message count.
case_begin "027_mi_stream_purge"

# The TEST stream has accumulated messages from earlier cases;
# msg_count > 0 likely.
before=$(n stream info TEST --json 2>/dev/null | \
    python3 -c 'import sys,json; print(json.load(sys.stdin)["state"]["messages"])' \
    2>/dev/null)
[ -n "$before" ] || before=0

resp=$(mi event_nats:nats_stream_purge TEST)
sleep 1
after=$(n stream info TEST --json 2>/dev/null | \
    python3 -c 'import sys,json; print(json.load(sys.stdin)["state"]["messages"])' \
    2>/dev/null)
[ -n "$after" ] || after=0

if echo "$resp" | grep -q '"result"' && [ "$after" = 0 ]; then
    check "nats_stream_purge zeroes the message count" ok \
        "before=$before after=$after"
else
    check "nats_stream_purge zeroes the message count" fail \
        "before=$before after=$after resp=$resp"
fi
