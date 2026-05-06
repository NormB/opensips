# 064 — cachedb_nats nats_kv_status MI command.
case_begin "064_mi_kv_status"

resp=$(mi cachedb_nats:nats_kv_status)
if echo "$resp" | grep -q '"result"' && \
   echo "$resp" | grep -q 'TESTKV'; then
    check "nats_kv_status reports TESTKV bucket" ok
else
    check "nats_kv_status reports TESTKV bucket" fail "$resp"
fi
