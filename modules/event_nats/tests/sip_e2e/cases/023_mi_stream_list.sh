# 023 — JetStream MI: nats_stream_list returns the TEST stream we
# created in run.sh setup.  The read-only observability commands are
# owned by cachedb_nats (P0.3); event_nats keeps only mutating admin.
case_begin "023_mi_stream_list"

resp=$(mi cachedb_nats:nats_stream_list)
if echo "$resp" | grep -q '"result"' && echo "$resp" | grep -q 'TEST'; then
    check "nats_stream_list includes TEST stream" ok
else
    check "nats_stream_list includes TEST stream" fail "$resp"
fi
