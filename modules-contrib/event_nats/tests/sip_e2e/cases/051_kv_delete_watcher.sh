# 051 — nats kv delete -> cachedb_nats watcher -> event_route op=delete
case_begin "051_kv_delete_watcher"

key="kvdel-$$"
kv_put TESTKV "$key" "to-be-deleted"
sleep 1
kv_del TESTKV "$key"

if wait_for_log 5 "E_NATS_KV_CHANGE op=delete key=${key}"; then
    check "watcher fires event_route on delete" ok
else
    check "watcher fires event_route on delete" fail \
        "expected: E_NATS_KV_CHANGE op=delete key=${key}"
fi
