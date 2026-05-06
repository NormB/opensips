# 029 — JetStream MI: nats_msg_delete removes a stored message.
case_begin "029_mi_msg_delete"

stream_purge TEST
publish_subject "test.msgdel" "delete-me-${$}"
publish_subject "test.msgdel" "keep-me-${$}"
sleep 1

# Capture both seqs published into THIS stream incarnation.
state=$(n stream info TEST --json 2>/dev/null \
        | python3 -c 'import sys,json; d=json.load(sys.stdin); s=d["state"]; print(s.get("first_seq",0), s.get("last_seq",0), s.get("messages",0))' \
          2>/dev/null)
first=$(echo "$state" | awk '{print $1}')
last=$(echo  "$state" | awk '{print $2}')
before=$(echo "$state" | awk '{print $3}')

resp=$(mi event_nats:nats_msg_delete TEST "$first")
sleep 1
after=$(n stream info TEST --json 2>/dev/null \
        | python3 -c 'import sys,json; print(json.load(sys.stdin)["state"]["messages"])' \
        2>/dev/null)

if echo "$resp" | grep -q '"result"' && \
   [ "$before" = 2 ] && [ "$after" = 1 ]; then
    check "nats_msg_delete removes the targeted seq" ok \
        "first=$first last=$last before=$before after=$after"
else
    check "nats_msg_delete removes the targeted seq" fail \
        "first=$first last=$last before=$before after=$after resp=$resp"
fi
