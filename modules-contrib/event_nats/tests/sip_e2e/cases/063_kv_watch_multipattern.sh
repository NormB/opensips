# 063 — kv_watch="json.>" multi-pattern: keys under json.* fire too.
case_begin "063_kv_watch_multipattern"

key="json.user.$$"
val="multipattern-${$}"
kv_put TESTKV "$key" "$val"

if wait_for_log 5 "E_NATS_KV_CHANGE op=put key=${key} value=${val}"; then
    check "second kv_watch pattern (json.>) catches dotted keys" ok
else
    check "second kv_watch pattern (json.>) catches dotted keys" fail
fi
