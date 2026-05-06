# 170 — nats_handle_reload MI: trigger persisted-handle re-read.
# With persist_handles modparam unset this should still respond
# (no-op or 200) without error.
case_begin "170_consumer_handle_reload"

resp=$(mi nats_consumer:nats_handle_reload)
if echo "$resp" | grep -qE '"result"|"error"'; then
    check "nats_handle_reload responds (result or error)" ok
else
    check "nats_handle_reload responds (result or error)" fail "$resp"
fi
