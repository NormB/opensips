# 050 — nats kv put -> cachedb_nats watcher -> event_route -> xlog
case_begin "050_kv_put_watcher"

key="kvput-$$"
val="alice-$(date +%s%N)"
kv_put TESTKV "$key" "$val"

if wait_for_log 5 "E_NATS_KV_CHANGE op=put key=${key} value=${val}"; then
    check "watcher fires event_route on put" ok
else
    check "watcher fires event_route on put" fail \
        "expected: E_NATS_KV_CHANGE op=put key=${key} value=${val}"
fi
