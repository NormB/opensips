# 096 — [DOCX] the docbook's MI examples, validated 100%.
#
# Contract: EVERY `## opensips-cli -x mi ...` invocation in
# doc/cachedb_nats_admin.xml is extracted MECHANICALLY and executed against
# the live instance + broker; each must return a JSON-RPC result (never an
# error).  A future docbook example is therefore tested the moment it is
# written — or it fails this case.  On top of the run-success sweep,
# targeted asserts pin the STABLE parts of each documented output (counts,
# header rows, field values); timestamp/sequence/size fields naturally vary
# and are shape-checked only.
#
# The docbook examples use the DEFAULT bucket name ("opensips" /
# "KV_opensips") and this sample population, registered below verbatim:
#   alice@example.com  sip:alice@10.0.0.1:5060  3600s  "Yealink T54W"
#                      sip:alice@10.0.0.2:5060   120s  "Zoiper 5"
#   bob@example.com    sip:bob@10.0.0.3:5060    3600s  "Grandstream GXP2170"
# The suite runs on an ephemeral bucket, so the literal bucket tokens are
# mapped to $KV_BUCKET before execution (same command shape, parameterized
# bucket — the one documented divergence).
case_begin "096_docbook_examples"

DOCBOOK="${TREE_ROOT}/modules/cachedb_nats/doc/cachedb_nats_admin.xml"
[ -r "$DOCBOOK" ] || { check "docbook readable" fail "$DOCBOOK"; return 0; }

kv_clear

# ── the documented population ──
raw_register alice example.com "sip:alice@10.0.0.1:5060" 3600 "Yealink T54W"
r1=$?
raw_register alice example.com "sip:alice@10.0.0.2:5060" 120  "Zoiper 5"
r2=$?
raw_register bob   example.com "sip:bob@10.0.0.3:5060"   3600 "Grandstream GXP2170"
r3=$?
check "documented population registered (alice x2, bob x1)" \
    $([ "$r1$r2$r3" = "000" ] && echo ok || echo fail) "rc=$r1$r2$r3"
wait_kv_count 2

# ── mechanical sweep: run EVERY docbook MI example ──
# Extraction emits one TAB-separated line per example: method, then args.
# key=value tokens (no ';') become NAMED params, everything else positional
# (exactly opensips-cli's convention).
n_total=0
n_fail=0
while IFS=$'\t' read -r method kind a1 a2; do
    [ -n "$method" ] || continue
    n_total=$((n_total + 1))
    case "$kind" in
        named)  out=$(mi_named "$MI_PORT_A" "$method" $a1 $a2) ;;
        pos)    out=$(mi_at "$MI_PORT_A" "$method" ${a1:+"$a1"} ${a2:+"$a2"}) ;;
        none)   out=$(mi_at "$MI_PORT_A" "$method") ;;
    esac
    if ! printf '%s' "$out" | grep -q '"result"'; then
        n_fail=$((n_fail + 1))
        echo "  example FAILED: $method [$kind] '$a1' '$a2'"
        echo "    reply: $(printf '%s' "$out" | head -c 200)"
    fi
done << EXAMPLES_EOF
$(python3 - "$DOCBOOK" "$KV_BUCKET" << 'PYEOF'
import re, shlex, sys

doc, bucket = sys.argv[1], sys.argv[2]
for line in open(doc):
    m = re.match(r'^## opensips-cli -x mi (.+)$', line.strip())
    if not m:
        continue
    # the suite bucket stands in for the documented default bucket name
    text = m.group(1).replace('KV_opensips', 'KV_' + bucket)
    toks = shlex.split(text)
    method, args = toks[0], toks[1:]
    # a token is a NAMED param only when its key is a real MI param name;
    # anything else (incl. single-pair filter strings like 'kv=1') is a
    # positional value, exactly as opensips-cli would send it
    NAMED = {'domains', 'format', 'aor', 'stream', 'filter'}
    def is_named(a):
        m2 = re.match(r'^([a-z_]+)=[^;=]*$', a)
        return bool(m2) and m2.group(1) in NAMED
    if not args:
        print(f"{method}\tnone\t\t")
    elif all(is_named(a) for a in args):
        print(f"{method}\tnamed\t" + "\t".join(args[:2]))
    else:
        print(f"{method}\tpos\t" + "\t".join(args[:2]))
PYEOF
)
EXAMPLES_EOF

check "every docbook MI example executes successfully ($n_total found)" \
    $([ "$n_fail" = 0 ] && [ "$n_total" -ge 12 ] && echo ok || echo fail) \
    "total=$n_total failed=$n_fail"

# ── targeted asserts: the STABLE parts of each documented output ──
mifield() { printf '%s' "$1" | sed -n "s/.*\"$2\": *\([0-9-][0-9]*\).*/\1/p" | head -1; }

out=$(mi_named "$MI_PORT_A" nats_reg_summary domains=1)
check "doc summary: aors=2 contacts=3 active=3 (as documented)" \
    $([ "$(mifield "$out" aors)" = 2 ] && [ "$(mifield "$out" contacts)" = 3 ] && \
      [ "$(mifield "$out" active_contacts)" = 3 ] && echo ok || echo fail) \
    "out=$(printf '%s' "$out" | head -c 200)"
printf '%s' "$out" | grep -q '"domain": *"example.com"'
check "doc summary: example.com domain row present" \
    $([ "$?" = 0 ] && echo ok || echo fail)

out=$(mi_named "$MI_PORT_A" nats_reg_summary domains=1 format=csv)
data=$(mi_data "$out")
printf '%s' "$data" | grep -q '^total,,2,3,3,0,0' && \
    printf '%s' "$data" | grep -q '^domain,example.com,2,3,3,,'
check "doc summary csv: documented total + domain records" \
    $([ "$?" = 0 ] && echo ok || echo fail) \
    "data=$(printf '%s' "$data" | head -c 150)"

out=$(mi nats_reg_list 'domain=example.com;sort=expiry;limit=2')
first=$(printf '%s' "$out" | grep -o '"aor": *"[a-z]*@example.com"' | head -1)
check "doc list: matched=2, alice first (soonest expiry), bob second" \
    $([ "$(mifield "$out" matched)" = 2 ] && \
      printf '%s' "$first" | grep -q alice && \
      printf '%s' "$out" | grep -q '"aor": *"bob@example.com"' && echo ok || echo fail) \
    "first=$first"

out=$(mi nats_reg_list 'ua=Yealink;format=csv')
data=$(mi_data "$out")
first=$(printf '%s' "$data" | head -1 | tr -d '\r')
row=$(printf '%s' "$data" | sed -n 2p | tr -d '\r')
check "doc list csv: documented header + alice row prefix" \
    $([ "$first" = "aor,contacts,active,expired,permanent,expires_next,expires_in,last_mod" ] && \
      printf '%s' "$row" | grep -q '^alice@example.com,2,2,0,0,' && echo ok || echo fail) \
    "row=$row"

out=$(mi nats_reg_show "alice@example.com")
printf '%s' "$out" | grep -q '"ua": *"Yealink T54W"' && \
    printf '%s' "$out" | grep -q '"ua": *"Zoiper 5"' && \
    printf '%s' "$out" | grep -q '"key": *"json_alice=40example.com"'
check "doc show: both documented contacts + encoded key" \
    $([ "$?" = 0 ] && echo ok || echo fail) \
    "out=$(printf '%s' "$out" | head -c 200)"

out=$(mi nats_reg_show "alice@example.com" csv)
data=$(mi_data "$out")
n_rec=$(printf '%s' "$data" | grep -c $'\r$')
printf '%s' "$data" | head -1 | grep -q '^aor,id,contact,state,expires'
check "doc show csv: documented header + 2 contact records" \
    $([ "$?" = 0 ] && [ "$n_rec" = 3 ] && echo ok || echo fail) "n_rec=$n_rec"

out=$(mi nats_stream_list 'kv=1')
printf '%s' "$out" | grep -q "\"kv_bucket\": *\"${KV_BUCKET}\""
check "doc stream_list: bucket row with derived kv_bucket" \
    $([ "$?" = 0 ] && echo ok || echo fail)

out=$(mi nats_stream_info "KV_${KV_BUCKET}")
printf '%s' "$out" | grep -q '"allow_msg_ttl": *true'
check "doc stream_info: documented TTL preconditions visible" \
    $([ "$?" = 0 ] && [ "$(mifield "$out" max_msgs_per_subject)" = 1 ] && \
      [ "$(mifield "$out" subject_delete_marker_ttl_s)" = 30 ] && \
      [ "$(mifield "$out" messages)" = 2 ] && echo ok || echo fail) \
    "messages=$(mifield "$out" messages)"

out=$(mi nats_stream_info "KV_${KV_BUCKET}" txt)
data=$(mi_data "$out")
printf '%s' "$data" | head -1 | grep -q $'^# field\tvalue' && \
    printf '%s' "$data" | grep -q $'^allow_msg_ttl\t1' && \
    printf '%s' "$data" | grep -q $'^subject_delete_marker_ttl_s\t30'
check "doc stream_info txt: documented field/value lines" \
    $([ "$?" = 0 ] && echo ok || echo fail) \
    "data=$(printf '%s' "$data" | head -c 120)"

out=$(mi nats_kv_keys 'key=json_alice*;detail=1')
printf '%s' "$out" | grep -q '"key": *"json_alice=40example.com"'
check "doc kv_keys: documented encoded key with detail fields" \
    $([ "$?" = 0 ] && [ "$(mifield "$out" matched)" = 1 ] && \
      [ "$(mifield "$out" revision)" -ge 1 ] && \
      [ "$(mifield "$out" size)" -gt 100 ] && echo ok || echo fail) \
    "out=$(printf '%s' "$out" | head -c 220)"

out=$(mi nats_cdb_stats)
printf '%s' "$out" | grep -q '"reap_last_aors"' && \
    printf '%s' "$out" | grep -q '"contacts_pruned"'
check "doc cdb_stats: documented gauge fields present" \
    $([ "$?" = 0 ] && echo ok || echo fail)

out=$(mi nats_kv_status)
printf '%s' "$out" | grep -q '"bucket"'
check "doc kv_status: documented fields present" \
    $([ "$?" = 0 ] && echo ok || echo fail)

kv_clear
