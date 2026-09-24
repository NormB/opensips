#!/bin/bash
#
# test_readme_format.sh -- the NATS module docs follow the upstream
# OpenSIPS module-documentation format: one README.md per module (no
# docbook sources, no generated plain-text README), with
#   - YAML front matter carrying title and description,
#   - "## Admin Guide" with "### Overview" and "### Dependencies",
#   - a "### Limitations" section,
#   - fenced examples that are balanced and name a language,
#   - in-page links (#slug) that resolve to a heading in the same file
#     (GitHub slug rules),
#   - the fixed upstream footer (contributors marker + License section);
# and lib/nats/README.md, the entry point for the whole NATS family,
# links every module README.
#
# bash + awk only.  Exit 0 = all checks pass.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TREE="$(cd "$HERE/../../.." && pwd)"
FAILS=0
check() {  # check <description> <expected> <actual>
    if [ "$2" = "$3" ]; then echo "  ok: $1"
    else echo "  FAIL: $1 (expected '$2', got '$3')"; FAILS=$((FAILS + 1)); fi
}

FOOTER='<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0'

# GitHub heading slug: lowercase, drop everything but [a-z0-9 _-], spaces -> "-"
slugs() {
    awk '/^```/ { f = !f; next } !f && /^#{1,6} / {
            h = $0; sub(/^#+ +/, "", h); h = tolower(h)
            gsub(/[^a-z0-9 _-]/, "", h); gsub(/ /, "-", h)
            n[h]++; if (n[h] > 1) h = h "-" (n[h] - 1)
            print h }' "$1"
}

for m in cachedb_nats cachedb_nats_fts event_nats nats_consumer; do
    d="$TREE/modules/$m"; f="$d/README.md"
    echo "== modules/$m"
    [ -f "$f" ] || { check "README.md exists" yes no; continue; }
    check "no docbook sources left (doc/*.xml)" 0 "$(ls "$d"/doc/*.xml 2>/dev/null | wc -l)"
    check "no generated plain-text README" no "$([ -e "$d/README" ] && echo yes || echo no)"
    check "front matter first" yes "$(head -1 "$f" | grep -qx -- '---' && echo yes || echo no)"
    check "front matter has title" yes "$(awk 'NR>1 && /^---$/{exit} /^title: ".+"$/{print "yes"; exit}' "$f")"
    check "front matter has description" yes "$(awk 'NR>1 && /^---$/{exit} /^description: ".+"$/{print "yes"; exit}' "$f")"
    for h in '## Admin Guide' '### Overview' '### Dependencies' '### Limitations'; do
        check "has '$h'" yes "$(grep -qxF -- "$h" "$f" && echo yes || echo no)"
    done
    check "code fences balanced" 0 "$(( $(grep -c '^```' "$f") % 2 ))"
    check "every opening fence names a language" 0 "$(awk '/^```/ { if (!f && $0 == "```") bad++; f = !f } END { print bad + 0 }' "$f")"
    missing=$(grep -oE '\]\(#[^)]+\)' "$f" | sed -E 's/^\]\(#//; s/\)$//' | sort -u | while read -r a; do
                  slugs "$f" | grep -qxF -- "$a" || echo "$a"; done)
    check "in-page links resolve${missing:+ (unresolved: $(echo $missing))}" "" "$missing"
    check "ends with the upstream contributors + License footer" yes \
        "$([ "$(tail -n 5 "$f")" = "$FOOTER" ] && echo yes || echo no)"
done

echo "== lib/nats/README.md (NATS family entry point)"
L="$TREE/lib/nats/README.md"
for m in cachedb_nats cachedb_nats_fts event_nats nats_consumer; do
    check "links modules/$m/README.md" yes \
        "$(grep -qE "\]\(\.\./\.\./modules/$m/README\.md(#[^)]*)?\)" "$L" && echo yes || echo no)"
done
check "has '## Limitations'" yes "$(grep -qxF '## Limitations' "$L" && echo yes || echo no)"
check "code fences balanced" 0 "$(( $(grep -c '^```' "$L") % 2 ))"

echo
if [ "$FAILS" -eq 0 ]; then echo "test_readme_format: OK"; exit 0; fi
echo "test_readme_format: $FAILS check(s) FAILED"; exit 1
