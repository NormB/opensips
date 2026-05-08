# 130 — Hard-killing instance A while instance B is serving traffic
# must not affect B. After A restarts, it rebuilds its in-memory
# index from KV and is consistent with B's view.
case_begin "130_instance_restart_isolation"

kv_clear
sleep 0.5

start_opensips_b
sleep 1

# Pre-populate via A; both instances' indexes will see these via
# their own child_init build (already done) — but for this test we
# care that B keeps working when A goes away.
register_n_parallel "pre" 3 "$SIP_PORT_A"
sleep 0.3

# Kill A while traffic continues
b_before=$(kv_aor_count)
stop_opensips_a

# Drive traffic at B
register_one bduring 3600 "$SIP_PORT_B"
b_rc=$?
check "instance B serves REGISTER while A is down" \
    $([ "$b_rc" = 0 ] && echo ok || echo fail) "b_rc=$b_rc"

b_during=$(kv_aor_count)
check "bucket grew while A was down" \
    $([ "$b_during" -gt "$b_before" ] && echo ok || echo fail) \
    "b_before=$b_before b_during=$b_during"

# Restart A — its index_build must rebuild from the KV that B has been
# updating in the meantime
start_opensips_a
sleep 1.5

a_index_built=$(grep "search index built:" "$WORKDIR/opensips.log" 2>/dev/null \
    | sed -n 's/.*search index built: \([0-9]*\) documents.*/\1/p' \
    | tail -1)
check "restarted A rebuilds index from up-to-date KV" \
    $([ "${a_index_built:-0}" -ge "$b_during" ] && echo ok || echo fail) \
    "a_index_built=${a_index_built:-0} b_during=$b_during"

# A new REGISTER on A should land alongside everything else
register_one apost 3600 "$SIP_PORT_A"
sleep 0.3
final=$(kv_aor_count)
check "A continues serving after restart" \
    $([ "$final" -gt "$b_during" ] && echo ok || echo fail) \
    "final=$final"

stop_opensips_b
