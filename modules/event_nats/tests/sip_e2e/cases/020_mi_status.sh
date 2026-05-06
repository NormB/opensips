# 020 — event_nats MI nats_status returns connection state.
case_begin "020_mi_status"

resp=$(mi event_nats:nats_status)
if echo "$resp" | grep -q '"result"' && \
   echo "$resp" | grep -qi 'connect\|server'; then
    check "nats_status returns a connection-info result" ok
else
    check "nats_status returns a connection-info result" fail "$resp"
fi
