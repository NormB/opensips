# 062 — nats kv purge -> watcher fires op=purge.
case_begin "062_kv_purge"

key="purge-$$"
kv_put TESTKV "$key" "to-be-purged"
sleep 1

n kv purge TESTKV "$key" -f >/dev/null 2>&1 || true
sleep 2

# Either op=purge or op=delete (some NATS server versions emit
# delete for purge; both indicate the key is gone).
if log_contains "E_NATS_KV_CHANGE op=purge key=${key}" || \
   log_contains "E_NATS_KV_CHANGE op=delete key=${key}"; then
    check "watcher emits purge/delete event for kv purge" ok
else
    check "watcher emits purge/delete event for kv purge" fail
fi
