# 065 — nats_kv_status MI exposes bucket+history+replicas+ttl fields.
case_begin "065_kv_status_fields"

resp=$(mi cachedb_nats:nats_kv_status)

if echo "$resp" | grep -qi 'bucket' && \
   echo "$resp" | grep -qi 'history\|replic\|ttl'; then
    check "nats_kv_status reports bucket configuration" ok
else
    check "nats_kv_status reports bucket configuration" fail "$resp"
fi
