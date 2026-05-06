# 023 — JetStream MI: nats_stream_list returns the TEST stream we
# created in run.sh setup.
case_begin "023_mi_stream_list"

resp=$(mi event_nats:nats_stream_list)
if echo "$resp" | grep -q '"result"' && echo "$resp" | grep -q 'TEST'; then
    check "nats_stream_list includes TEST stream" ok
else
    check "nats_stream_list includes TEST stream" fail "$resp"
fi
