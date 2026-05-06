# 022 — JetStream MI: create a stream via MI, then nats_stream_info
# shows it.  Exercises nats_stream_create + nats_stream_info.
case_begin "022_mi_stream_create_info"

# Pre-clean (idempotent - stream may not exist)
n stream rm MITEST -f >/dev/null 2>&1 || true
sleep 0.5

create_resp=$(mi event_nats:nats_stream_create MITEST 'mi.test.>')
if echo "$create_resp" | grep -q '"result"'; then
    check "nats_stream_create succeeds" ok
else
    check "nats_stream_create succeeds" fail "$create_resp"
    return
fi

sleep 1
info_resp=$(mi event_nats:nats_stream_info MITEST)
if echo "$info_resp" | grep -q '"result"' && \
   echo "$info_resp" | grep -q 'MITEST\|mi.test'; then
    check "nats_stream_info shows the new stream" ok
else
    check "nats_stream_info shows the new stream" fail "$info_resp"
fi

# Cleanup
mi event_nats:nats_stream_delete MITEST >/dev/null
