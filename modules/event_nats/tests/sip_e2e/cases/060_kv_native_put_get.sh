# 060 — nats_kv_put + nats_kv_get script natives.
# Driven by an external nats kv put + observation of the watcher
# event_route, since we don't have a route that calls the natives
# directly without a SIP trigger.  Skipping pure-script test for now;
# instead verify that an externally-put key surfaces via the watcher
# AND can be retrieved via `nats kv get`.
case_begin "060_kv_native_put_get"

key="native-$$"
val="native-val-$(date +%s%N)"
kv_put TESTKV "$key" "$val"
sleep 1

# (a) value is queryable from outside via nats CLI
got=$(kv_get_value TESTKV "$key")
if [ "$got" = "$val" ]; then
    check "kv put round-trip via CLI" ok
else
    check "kv put round-trip via CLI" fail "got='$got' expected='$val'"
fi

# (b) opensips watcher saw it (cross-checks the watcher chain too)
if log_contains "E_NATS_KV_CHANGE op=put key=${key} value=${val}"; then
    check "kv put visible to opensips watcher" ok
else
    check "kv put visible to opensips watcher" fail
fi
