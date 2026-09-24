#!/bin/bash
#
# test_readme_examples.sh -- every ```opensips example in the NATS
# module READMEs (and lib/nats/README.md) must pass `opensips -C`.
#
# Each fenced block is checked on its own.  "..." elision lines are
# dropped; loadmodule/modparam lines and top-level route blocks are kept
# as written; bare statements are wrapped in a route.  Any module the
# block configures via modparam() is loaded for it, on top of a small
# base set (the four NATS modules and the SIP modules the examples call
# into).  Config checking runs the parser and the function fixups, so
# unknown functions, wrong argument counts and syntax errors all fail.
#
# Needs a built tree (./opensips + modules/*/*.so); exits 77 (skip)
# otherwise.  README_EXAMPLES_FILES (space-separated paths) overrides the
# list of READMEs; selftest_readme_examples.sh uses it.
# bash + awk only.  Exit 0 = every example passes.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TREE="$(cd "$HERE/../../.." && pwd)"
BIN="${OPENSIPS_BIN:-$TREE/opensips}"
[ -x "$BIN" ] || { echo "SKIP: no built opensips at $BIN"; exit 77; }
for m in event_nats cachedb_nats cachedb_nats_fts nats_consumer; do
    [ -f "$TREE/modules/$m/$m.so" ] || { echo "SKIP: modules/$m not built"; exit 77; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

BASE_MODS="proto_udp sl tm signaling event_nats cachedb_nats cachedb_nats_fts nats_consumer"

# split <readme> <prefix>: one file per ```opensips block, first line = title
split_blocks() {
    awk -v out="$2" '
        /^```opensips/ { n++; f = sprintf("%s.%03d", out, n)
                         t = $0; sub(/^```opensips */, "", t)
                         print "#TITLE " NR " " t > f; inb = 1; next }
        inb && /^```/  { inb = 0; close(f); next }
        inb            { print > f }' "$1"
}

# build <block> <cfg>: wrap one example into a checkable config
build_cfg() {
    local blk="$1" cfg="$2" mods m
    mods="$BASE_MODS $(grep -oE 'modparam\("[a-z0-9_]+"' "$blk" | sed -E 's/modparam\("//; s/"$//')"
    mods="$mods $(grep -oE 'loadmodule +"[a-z0-9_]+\.so"' "$blk" | sed -E 's/.*"([a-z0-9_]+)\.so"/\1/')"
    {
        echo 'log_level=2'
        echo 'socket=udp:127.0.0.1:5060'
        echo "mpath=\"$TREE/modules/\""
        for m in $(echo $mods | tr ' ' '\n' | awk '!s[$0]++'); do
            echo "loadmodule \"$m.so\""
        done
        awk '
            /^#TITLE /                          { next }
            /^[ \t]*\.\.\.[ \t]*$/              { next }
            /^[ \t]*loadmodule[ \t]/            { next }
            /^(startup_|timer_|failure_|onreply_|branch_|local_|error_|event_)?route[ \t]*[\[{]/ \
                                                { depth_top = 1 }
            {
                if (depth_top) { print; o = gsub(/{/, "{"); c = gsub(/}/, "}")
                                 d += o - c; if (d <= 0) { depth_top = 0; d = 0 }; next }
                if ($0 ~ /^[ \t]*modparam[ \t]*\(/ || cont) {
                    print; cont = ($0 !~ /\)[ \t]*;?[ \t]*(#.*)?$/); next }
                if ($0 ~ /^[ \t]*(#.*)?$/) { print; next }
                if ($0 ~ /^[a-z_]+[ \t]*=/) { print; next }   # core setting
                body = body $0 "\n"
            }
            END { if (body != "") printf "route[doc_example] {\n%s}\n", body }' "$blk"
        grep -q '^route[ \t]*{' "$blk" || echo 'route { exit; }'
    } > "$cfg"
}

FAILS=0; N=0
FILES="${README_EXAMPLES_FILES:-$(echo "$TREE"/modules/{cachedb_nats,cachedb_nats_fts,event_nats,nats_consumer}/README.md "$TREE/lib/nats/README.md")}"
for f in $FILES; do
    rel="${f#$TREE/}"
    pfx="$WORK/$(echo "$rel" | tr / _)"
    split_blocks "$f" "$pfx"
    for blk in "$pfx".[0-9]*; do
        [ -f "$blk" ] || continue
        N=$((N + 1))
        read -r _ line title < "$blk"
        build_cfg "$blk" "$blk.cfg"
        if out=$("$BIN" -C -f "$blk.cfg" 2>&1); then
            echo "  ok: $rel:$line $title"
        else
            echo "  FAIL: $rel:$line $title"
            echo "$out" | grep -E 'CRITICAL:core:yyerror|ERROR' | grep -v 'bad config file\|failed to parse\|Traceback' \
                | head -3 | sed 's/^/        /'
            FAILS=$((FAILS + 1))
        fi
    done
done

echo
if [ "$N" -eq 0 ]; then echo "test_readme_examples: no examples found"; exit 1; fi
if [ "$FAILS" -eq 0 ]; then echo "test_readme_examples: OK ($N examples)"; exit 0; fi
echo "test_readme_examples: $FAILS of $N example(s) FAILED"; exit 1
