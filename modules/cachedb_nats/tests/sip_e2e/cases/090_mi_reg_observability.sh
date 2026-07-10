# 090 — [OBS] registration observability MI: nats_reg_summary / _list /
# _show + the reaper-pass gauges in nats_cdb_stats.  usrloc's own ul_dump is
# empty by design in full-sharing-cachedb mode, so these commands are the
# operator's only SIP-level view of the bucket.
#
# Population (REAP_INTERVAL=120 so nothing gets pruned mid-assertions;
# each MI datagram call costs ~2 s of nc receive window, so the case is long):
#   alpha  1 contact,  expires 3600                    -> active
#   beta   2 contacts, both 3600                       -> active, multi
#   gamma  2 contacts, 3 + 3600 (mixed)                -> 1 expired + 1 active
#   delta  1 contact,  expires 300 (others 3600)       -> expiring soonest
case_begin "090_mi_reg_observability"

stop_opensips_a
REAP_INTERVAL=120 start_opensips_a
wait_for 10 mi_ready

kv_clear

register_one     alpha 3600
register_contact beta  6087 3600
register_contact beta  6088 3600
register_contact gamma 6089 3
register_contact gamma 6090 3600
register_one     delta 300
wait_for 5 kv_count_ge 4

# let gamma's short contact pass logical expiry (3+5=8 s)
sleep 9

# helper: pull one numeric field out of an MI JSON reply
mifield() { printf '%s' "$1" | sed -n "s/.*\"$2\": *\([0-9-][0-9]*\).*/\1/p" | head -1; }

out=$(mi nats_reg_summary)
check "summary: 4 AoRs" \
    $([ "$(mifield "$out" aors)" = 4 ] && echo ok || echo fail) "out=$(printf '%s' "$out" | head -c 200)"
check "summary: 6 stored contacts" \
    $([ "$(mifield "$out" contacts)" = 6 ] && echo ok || echo fail)
check "summary: 5 active / 1 expired (gamma's short contact lingers)" \
    $([ "$(mifield "$out" active_contacts)" = 5 ] && \
      [ "$(mifield "$out" expired_contacts)" = 1 ] && echo ok || echo fail) \
    "active=$(mifield "$out" active_contacts) expired=$(mifield "$out" expired_contacts)"

out=$(mi nats_reg_summary 1)
printf '%s' "$out" | grep -q '"domain": *"127.0.0.1"'
check "summary domains=1: per-domain table names 127.0.0.1" \
    $([ "$?" = 0 ] && echo ok || echo fail) "out=$(printf '%s' "$out" | head -c 200)"

out=$(mi nats_reg_list)
check "list (default state=active): all 4 AoRs match" \
    $([ "$(mifield "$out" matched)" = 4 ] && echo ok || echo fail)

out=$(mi nats_reg_list "state=expired")
check "list state=expired: exactly gamma" \
    $([ "$(mifield "$out" matched)" = 1 ] && \
      printf '%s' "$out" | grep -q '"aor": *"gamma@' && echo ok || echo fail) \
    "out=$(printf '%s' "$out" | head -c 200)"

out=$(mi nats_reg_list "expiring_within=600")
check "list expiring_within=600: exactly delta (expires 300; others 3600)" \
    $([ "$(mifield "$out" matched)" = 1 ] && \
      printf '%s' "$out" | grep -q '"aor": *"delta@' && echo ok || echo fail)

out=$(mi nats_reg_list "min_contacts=2")
check "list min_contacts=2: beta + gamma" \
    $([ "$(mifield "$out" matched)" = 2 ] && echo ok || echo fail)

out=$(mi nats_reg_list "sort=contacts;desc=1;limit=1")
first=$(printf '%s' "$out" | grep -o '"aor": *"[a-z]*@' | head -1)
check "list sort=contacts desc limit=1: multi-contact row first, AoR tie-break" \
    $([ "$(mifield "$out" returned)" = 1 ] && \
      printf '%s' "$first" | grep -q beta && echo ok || echo fail) "first=$first"

out=$(mi nats_reg_list "ua=sipsak")
check "list ua=sipsak substring: all 4" \
    $([ "$(mifield "$out" matched)" = 4 ] && echo ok || echo fail)
out=$(mi nats_reg_list "ua=NoSuchAgent")
check "list ua=NoSuchAgent: none" \
    $([ "$(mifield "$out" matched)" = 0 ] && echo ok || echo fail)

out=$(mi nats_reg_list "aor=alpha*")
check "list aor glob: alpha only" \
    $([ "$(mifield "$out" matched)" = 1 ] && echo ok || echo fail)

out=$(mi nats_reg_list "bogus=1")
printf '%s' "$out" | grep -q "bad filter"
check "list rejects an unknown filter key loudly (never mis-filters)" \
    $([ "$?" = 0 ] && echo ok || echo fail)

out=$(mi nats_reg_show "gamma@127.0.0.1")
# contact ids are STRING-valued; the JSON-RPC envelope's own "id":1 is
# numeric -- match the opening quote so the envelope never counts.
n_ct=$(printf '%s' "$out" | grep -o '"id": *"' | wc -l)
check "show gamma: both contacts with per-contact detail" \
    $([ "$n_ct" = 2 ] && echo ok || echo fail) "out=$(printf '%s' "$out" | head -c 220)"
printf '%s' "$out" | grep -q '"state": *"expired"' && \
    printf '%s' "$out" | grep -q '"state": *"active"'
check "show gamma: one expired + one active state" \
    $([ "$?" = 0 ] && echo ok || echo fail)
check "show gamma: KV revision + row_exp exposed" \
    $([ "$(mifield "$out" revision)" -ge 1 ] && \
      [ "$(mifield "$out" row_exp)" -gt 0 ] && echo ok || echo fail)

out=$(mi nats_reg_show "ghost@127.0.0.1")
printf '%s' "$out" | grep -q "no such registration"
check "show unknown AoR: 404, not an empty object" \
    $([ "$?" = 0 ] && echo ok || echo fail)

# ── [FMT] selectable output formats ──
out=$(mi nats_reg_list "state=all;sort=aor;format=csv")
data=$(mi_data "$out")
first=$(printf '%s' "$data" | head -1 | tr -d '\r')
check "fmt: csv data blob present, exact documented header first" \
    $([ "$first" = "aor,contacts,active,expired,permanent,expires_next,expires_in,last_mod" ] \
      && echo ok || echo fail) "first=$first"
n_rec=$(printf '%s' "$data" | grep -c $'\r$')
check "fmt: CRLF-terminated records, count = header + returned(4)" \
    $([ "$n_rec" = 5 ] && echo ok || echo fail) "n_rec=$n_rec"
printf '%s' "$data" | grep -q '^alpha@127.0.0.1,1,1,0,0,'
check "fmt: csv row carries the expected leading fields" \
    $([ "$?" = 0 ] && echo ok || echo fail)

out=$(mi nats_reg_list "state=all;format=csv;header=0;eol=lf")
data=$(mi_data "$out")
n_lf=$(printf '%s' "$data" | awk 'END{print NR}')
printf '%s' "$data" | grep -q $'\r'
had_cr=$?
check "fmt: header=0 + eol=lf -> 4 bare-LF records, no CR anywhere" \
    $([ "$n_lf" = 4 ] && [ "$had_cr" != 0 ] && echo ok || echo fail) \
    "lines=$n_lf had_cr=$had_cr"

out=$(mi nats_reg_list "format=txt;state=all")
data=$(mi_data "$out")
first=$(printf '%s' "$data" | head -1 | tr -d '\r')
check "fmt: txt header is '# '-prefixed and TAB-separated" \
    $(printf '%s' "$first" | grep -q $'^# aor\tcontacts' && echo ok || echo fail) \
    "first=$first"

out=$(mi nats_reg_list "format=cvs")
printf '%s' "$out" | grep -q "bad filter"
check "fmt: typo'd format refused (never silently json)" \
    $([ "$?" = 0 ] && echo ok || echo fail)

out=$(mi nats_reg_list "state=all")
printf '%s' "$out" | grep -q '"data":'
check "fmt: default json output has NO data field (byte-compatible)" \
    $([ "$?" != 0 ] && echo ok || echo fail)

out=$(mi nats_reg_show "gamma@127.0.0.1" "csv")
data=$(mi_data "$out")
n_rec=$(printf '%s' "$data" | grep -c $'\r$')
printf '%s' "$data" | head -1 | grep -q '^aor,id,contact,state,expires'
check "fmt: reg_show positional csv -> header + 2 contact records" \
    $([ "$?" = 0 ] && [ "$n_rec" = 3 ] && echo ok || echo fail) "n_rec=$n_rec"

out=$(mi nats_reg_summary 1 "csv;header=0")
data=$(mi_data "$out")
printf '%s' "$data" | grep -q '^total,,4,6,'
check "fmt: summary csv totals record (scope=total, empty domain)" \
    $([ "$?" = 0 ] && echo ok || echo fail) \
    "data=$(printf '%s' "$data" | head -c 120)"

# ── reaper-pass gauges: restart on a 5 s reaper and let one pass run ──
stop_opensips_a
REAP_INTERVAL=5 start_opensips_a
_reap_stamped() {
    [ "$(mifield "$(mi nats_cdb_stats)" reap_last_run)" -gt 0 ] 2>/dev/null
}
wait_for 20 _reap_stamped || true

out=$(mi nats_cdb_stats)
check "stats: reap_last_run stamped by a pass" \
    $([ "$(mifield "$out" reap_last_run)" -gt 0 ] && echo ok || echo fail) \
    "out=$(printf '%s' "$out" | head -c 300)"
check "stats: gauges see the population (>=3 AoRs, >=4 contacts)" \
    $([ "$(mifield "$out" reap_last_aors)" -ge 3 ] && \
      [ "$(mifield "$out" reap_last_contacts)" -ge 4 ] && echo ok || echo fail) \
    "aors=$(mifield "$out" reap_last_aors) contacts=$(mifield "$out" reap_last_contacts)"
check "stats: gamma's expired binding counted as pruned" \
    $([ "$(mifield "$out" contacts_pruned)" -ge 1 ] && echo ok || echo fail) \
    "pruned=$(mifield "$out" contacts_pruned)"

# restore the default instance
stop_opensips_a
start_opensips_a
wait_for 10 mi_ready
kv_clear
