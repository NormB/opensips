# 028 — JetStream MI: nats_msg_get fetches a stored message by seq.
case_begin "028_mi_msg_get"

payload="msg-get-${$}"
publish_subject "test.msgget" "$payload"
sleep 1

# Stream sequences don't reset on purge — use the just-published seq.
seq=$(n stream info TEST --json 2>/dev/null \
        | python3 -c 'import sys,json; print(json.load(sys.stdin)["state"]["last_seq"])' \
          2>/dev/null)
[ -n "$seq" ] || seq=1

resp=$(mi event_nats:nats_msg_get TEST "$seq")
if echo "$resp" | grep -q '"result"' && \
   echo "$resp" | grep -qE "$payload|test.msgget"; then
    check "nats_msg_get returns the published message" ok \
        "seq=$seq"
else
    check "nats_msg_get returns the published message" fail \
        "seq=$seq resp=$resp"
fi
