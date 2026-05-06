# 070 — kv_put + kv_get_value round-trip via nats CLI; verify the
# watcher event_route also sees the same key/value.
case_begin "070_kv_value_round_trip"

key="rt-$$"
val="cargo:$(date +%s%N):$$:end"
kv_put TESTKV "$key" "$val"
sleep 1

actual=$(kv_get_value TESTKV "$key")
check "kv get returns the put value" \
    $([ "$actual" = "$val" ] && echo ok || echo fail) \
    "actual='$actual' expected='$val'"

if log_contains "E_NATS_KV_CHANGE op=put key=${key} value=${val}"; then
    check "watcher sees the same key+value" ok
else
    check "watcher sees the same key+value" fail
fi
