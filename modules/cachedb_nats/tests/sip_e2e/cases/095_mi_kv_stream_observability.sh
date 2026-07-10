# 095 — [KVOBS] generic stream/KV introspection MI: nats_stream_list /
# nats_stream_info / nats_kv_keys.  Where 090 answers usrloc questions, these
# answer the layer below — any stream, any bucket — and nats_stream_info is
# the operator's direct check of the HREV-1 TTL preconditions (allow_msg_ttl,
# max_msgs_per_subject=1, marker TTL) on the live bucket.
case_begin "095_mi_kv_stream_observability"

kv_clear

register_one kvobs1 3600
register_one kvobs2 3600
wait_kv_count 2

mifield() { printf '%s' "$1" | sed -n "s/.*\"$2\": *\([0-9-][0-9]*\).*/\1/p" | head -1; }

# ── nats_stream_info on the suite bucket's backing stream ──
out=$(mi nats_stream_info "KV_${KV_BUCKET}")
check "stream_info: resolves the KV backing stream + derives the bucket" \
    $(printf '%s' "$out" | grep -q "\"kv_bucket\": *\"${KV_BUCKET}\"" && echo ok || echo fail) \
    "out=$(printf '%s' "$out" | head -c 200)"
printf '%s' "$out" | grep -q '"allow_msg_ttl": *true'
check "stream_info: shows allow_msg_ttl=true (the HREV-1 precondition)" \
    $([ "$?" = 0 ] && echo ok || echo fail)
check "stream_info: max_msgs_per_subject=1 + 30s marker TTL visible" \
    $([ "$(mifield "$out" max_msgs_per_subject)" = 1 ] && \
      [ "$(mifield "$out" subject_delete_marker_ttl_s)" = 30 ] && echo ok || echo fail) \
    "mmps=$(mifield "$out" max_msgs_per_subject) marker=$(mifield "$out" subject_delete_marker_ttl_s)"
check "stream_info: state counts the 2 registered rows" \
    $([ "$(mifield "$out" messages)" -ge 2 ] && echo ok || echo fail) \
    "messages=$(mifield "$out" messages)"

out=$(mi nats_stream_info "NO_SUCH_STREAM_EVER")
printf '%s' "$out" | grep -q "no such stream"
check "stream_info: unknown stream 404s" \
    $([ "$?" = 0 ] && echo ok || echo fail)

# ── nats_stream_list ──
out=$(mi nats_stream_list "kv=1")
printf '%s' "$out" | grep -q "\"kv_bucket\": *\"${KV_BUCKET}\""
check "stream_list kv=1: lists the suite bucket by its BUCKET name" \
    $([ "$?" = 0 ] && echo ok || echo fail) \
    "out=$(printf '%s' "$out" | head -c 200)"

out=$(mi nats_stream_list "name=KV_${KV_BUCKET}")
check "stream_list name=<exact glob>: exactly one match" \
    $([ "$(mifield "$out" matched)" = 1 ] && echo ok || echo fail)

out=$(mi nats_stream_list "name=zz_no_match_*")
check "stream_list non-matching glob: empty, not an error" \
    $([ "$(mifield "$out" matched)" = 0 ] && echo ok || echo fail)

out=$(mi nats_stream_list "wat=1")
printf '%s' "$out" | grep -q "bad filter"
check "stream_list rejects unknown filter keys loudly" \
    $([ "$?" = 0 ] && echo ok || echo fail)

# ── nats_kv_keys ──
out=$(mi nats_kv_keys)
check "kv_keys (default bucket): both AoR keys live" \
    $([ "$(mifield "$out" matched)" = 2 ] && echo ok || echo fail) \
    "out=$(printf '%s' "$out" | head -c 200)"
printf '%s' "$out" | grep -q '"json_kvobs1=40127.0.0.1"'
check "kv_keys: encoded key names listed verbatim" \
    $([ "$?" = 0 ] && echo ok || echo fail)

out=$(mi nats_kv_keys "key=json_kvobs1*")
check "kv_keys glob: one match" \
    $([ "$(mifield "$out" matched)" = 1 ] && echo ok || echo fail)

out=$(mi nats_kv_keys "limit=1;offset=1")
check "kv_keys pagination: second page of one (deterministic name order)" \
    $([ "$(mifield "$out" returned)" = 1 ] && \
      [ "$(mifield "$out" offset)" = 1 ] && \
      printf '%s' "$out" | grep -q kvobs2 && echo ok || echo fail)

out=$(mi nats_kv_keys "detail=1;key=json_kvobs1*")
check "kv_keys detail=1: revision/created/size per returned key" \
    $([ "$(mifield "$out" revision)" -ge 1 ] && \
      [ "$(mifield "$out" size)" -gt 50 ] && echo ok || echo fail) \
    "out=$(printf '%s' "$out" | head -c 250)"

out=$(mi nats_kv_keys "bucket=no_such_bucket_ever")
printf '%s' "$out" | grep -q "no such bucket"
check "kv_keys: unknown bucket 404s (BOUND, never created)" \
    $([ "$?" = 0 ] && echo ok || echo fail)

# ── [FMT] formats on the generic commands ──
out=$(mi nats_stream_info "KV_${KV_BUCKET}" "txt;eol=lf")
data=$(mi_data "$out")
printf '%s' "$data" | grep -q $'^allow_msg_ttl\t1$'
check "fmt: stream_info txt = field/value lines (allow_msg_ttl 1)" \
    $([ "$?" = 0 ] && echo ok || echo fail) \
    "data=$(printf '%s' "$data" | head -c 150)"

out=$(mi nats_kv_keys "format=csv;detail=1;key=json_kvobs1*")
data=$(mi_data "$out")
first=$(printf '%s' "$data" | head -1 | tr -d '\r')
check "fmt: kv_keys csv detail header" \
    $([ "$first" = "key,revision,created,size" ] && echo ok || echo fail) \
    "first=$first"

out=$(mi nats_stream_list "kv=1;format=csv")
data=$(mi_data "$out")
printf '%s' "$data" | grep -q "^KV_${KV_BUCKET},${KV_BUCKET},"
check "fmt: stream_list csv row (stream name + derived bucket)" \
    $([ "$?" = 0 ] && echo ok || echo fail) \
    "data=$(printf '%s' "$data" | head -c 150)"

# the bind-never-create guarantee, verified against the broker itself
out=$(mi nats_stream_list "name=KV_no_such_bucket_ever")
check "kv_keys did NOT materialize the typo'd bucket" \
    $([ "$(mifield "$out" matched)" = 0 ] && echo ok || echo fail)
