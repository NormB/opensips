#!/bin/bash
#
# test_docbook_parse.sh -- every NATS module's docbook book must parse,
# with the tree's own entity set (docs/entities.xml + the book's local
# entities).  A book that does not parse cannot regenerate its README, and
# the first sign is usually a stray HTML entity (&nbsp;, &le;, ...) that
# XML does not predefine -- use a numeric reference (&#160;, &#8804;).
#
# Skips (77) when xmllint is not installed.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TREE="$(cd "$HERE/../../.." && pwd)"
command -v xmllint >/dev/null 2>&1 || { echo "SKIP: xmllint not installed"; exit 77; }

FAILS=0
for book in cachedb_nats/doc/cachedb_nats.xml \
            event_nats/doc/event_nats.xml \
            nats_consumer/doc/nats_consumer.xml; do
    f="$TREE/modules/$book"
    if [ ! -f "$f" ]; then
        echo "  FAIL: $book missing"; FAILS=$((FAILS + 1)); continue
    fi
    # --noent substitutes entities; --nonet keeps the DTD fetch offline
    # (the DocBook DTD itself is not needed for well-formedness).
    if out=$(cd "$(dirname "$f")" && xmllint --noout --noent --nonet "$(basename "$f")" 2>&1); then
        echo "  ok: $book parses"
    else
        echo "  FAIL: $book does not parse:"
        printf '%s\n' "$out" | grep -E 'error' | head -3 | sed 's/^/    /'
        FAILS=$((FAILS + 1))
    fi
done

echo
if [ "$FAILS" -eq 0 ]; then echo "test_docbook_parse: OK"; exit 0; fi
echo "test_docbook_parse: $FAILS book(s) FAILED"; exit 1
