# 200 — publish to a subject that's bound by JetStream stream TEST;
# verify the message landed in the stream (not just transient pub/sub).
case_begin "200_publish_jetstream_subject"

# stream TEST already includes 'test.>'; pre-purge to get a clean
# message count.
stream_purge TEST

publish_subject "test.sip.persisted" "js-payload-${$}"
sleep 1

# JSON output is parseable across nats CLI versions.
msgs=$(n stream info TEST --json 2>/dev/null \
       | python3 -c 'import sys,json; print(json.load(sys.stdin)["state"]["messages"])' \
         2>/dev/null)

if [ "${msgs:-0}" -ge 1 ]; then
    check "JetStream stream TEST captured published message" ok
else
    check "JetStream stream TEST captured published message" fail "msgs=$msgs"
fi
