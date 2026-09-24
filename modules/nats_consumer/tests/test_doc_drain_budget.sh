#!/bin/bash
#
# test_doc_drain_budget.sh -- the documented timer_route drain examples
# must fit inside their own timer interval.
#
# A fetch blocks until it has what it asked for or its wait budget runs
# out, so while messages keep trickling in every call can take its full
# budget and a drain pass never finds the ring empty.  A pass therefore
# lasts up to  iterations x per-call wait;  when that exceeds the
# timer_route interval, passes overlap and the core logs "timer task
# <timer_route> already scheduled ..." on every overrun (seen under
# stress_3way).  Every timer_route example that fetches must bound that
# product by its interval:
#   - nats_fetch_batch(..."expires_ms=E") inside  while ($var(x) < N)
#                                           -> worst = N * E ms
#   - while ($var(x) < N && nats_fetch("id", T) > 0)  -> worst = N * T ms
#   - a fetch loop with no iteration bound  -> unbounded, fails
# The generated README must carry the same drain examples as the docbook
# master.  bash + awk only (runs in the minimal CI containers).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
MOD="$(cd "$HERE/.." && pwd)"
XML="$MOD/doc/nats_consumer_admin.xml"
README="$MOD/README"
FAILS=0

# extract_blocks <file>: every "timer_route[...] {" ... "}" block that calls
# nats_fetch*, entities unescaped, one block per record (records separated
# by a line holding only "@@").
extract_blocks() {
    sed -e 's/&lt;/</g; s/&gt;/>/g; s/&amp;/\&/g' "$1" | awk '
        /^timer_route\[/ { inb = 1; blk = "" }
        inb { blk = blk $0 "\n" }
        inb && /^}[[:space:]]*$/ {
            inb = 0
            if (blk ~ /nats_fetch/) printf "%s@@\n", blk
        }'
}

# budget: read blocks, print "<name> <interval_ms> <worst_ms|unbounded|unknown>"
budget() {
    awk '
        function flush() {
            if (name == "") return
            if (worst == "") worst = (unb ? "unbounded" : "unknown")
            print name, ival * 1000, worst
            name = ""; worst = ""; unb = 0; bound = 0
        }
        /^@@$/ { flush(); next }
        /^timer_route\[/ {
            s = $0; sub(/^timer_route\[/, "", s)
            name = s; sub(/,.*/, "", name)
            ival = s; sub(/^[^,]*,[[:space:]]*/, "", ival); sub(/\].*/, "", ival)
            next
        }
        # while ($var(x) < N)  -- a loop bound for a batch fetch inside it
        /while[[:space:]]*\(\$var\([a-z_]+\)[[:space:]]*<[[:space:]]*[0-9]+[[:space:]]*\)/ {
            t = $0; sub(/.*<[[:space:]]*/, "", t); sub(/[^0-9].*/, "", t)
            if (!bound) bound = t + 0
        }
        /nats_fetch_batch\(/ {
            e = $0
            if (e ~ /expires_ms=[0-9]+/) { sub(/.*expires_ms=/, "", e); sub(/[^0-9].*/, "", e) }
            else if (e ~ /expires=[0-9]+ms/) { sub(/.*expires=/, "", e); sub(/[^0-9].*/, "", e) }
            else e = 0
            if (bound) worst = bound * e; else unb = 1
        }
        # while ([$var(x) < N &&] nats_fetch("id", T) > 0)
        /while[[:space:]]*\(.*nats_fetch\(/ {
            t = $0; sub(/.*nats_fetch\([^,]*,[[:space:]]*/, "", t); sub(/[^0-9].*/, "", t)
            if ($0 ~ /\$var\([a-z_]+\)[[:space:]]*<[[:space:]]*[0-9]+[[:space:]]*&&/) {
                n = $0; sub(/.*\$var\([a-z_]+\)[[:space:]]*<[[:space:]]*/, "", n); sub(/[^0-9].*/, "", n)
                worst = n * t
            } else unb = 1
        }
        END { flush() }'
}

[ -f "$XML" ] || { echo "FAIL: $XML missing"; exit 1; }
[ -f "$README" ] || { echo "FAIL: $README missing"; exit 1; }

echo "== drain examples fit their timer interval ($XML)"
n=0
while read -r name ival worst; do
    n=$((n + 1))
    case "$worst" in
    unbounded|unknown)
        echo "  FAIL: timer_route[$name] fetch loop is $worst (interval ${ival} ms)"
        FAILS=$((FAILS + 1)) ;;
    *)
        if [ "$worst" -le "$ival" ]; then
            echo "  ok: timer_route[$name] worst case ${worst} ms <= interval ${ival} ms"
        else
            echo "  FAIL: timer_route[$name] worst case ${worst} ms > interval ${ival} ms"
            FAILS=$((FAILS + 1))
        fi ;;
    esac
done < <(extract_blocks "$XML" | budget)
if [ "$n" -eq 0 ]; then
    echo "  FAIL: no timer_route fetch examples found (parser out of date?)"
    FAILS=$((FAILS + 1))
fi

echo "== README carries the docbook's drain examples"
if diff <(extract_blocks "$XML") <(extract_blocks "$README") >/dev/null; then
    echo "  ok: README drain examples == docbook master"
else
    echo "  FAIL: README drain examples differ from $XML (regenerate/sync README):"
    diff <(extract_blocks "$XML") <(extract_blocks "$README") | sed 's/^/    /' | head -20
    FAILS=$((FAILS + 1))
fi

echo
if [ "$FAILS" -eq 0 ]; then echo "test_doc_drain_budget: OK"; exit 0; fi
echo "test_doc_drain_budget: $FAILS check(s) FAILED"; exit 1
