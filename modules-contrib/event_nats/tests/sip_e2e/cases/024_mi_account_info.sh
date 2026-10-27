# 024 — JetStream account info via MI.
case_begin "024_mi_account_info"

resp=$(mi event_nats:nats_account_info)
if echo "$resp" | grep -q '"result"'; then
    check "nats_account_info returns a result envelope" ok
else
    check "nats_account_info returns a result envelope" fail "$resp"
fi
