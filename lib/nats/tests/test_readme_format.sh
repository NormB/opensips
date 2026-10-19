#!/bin/bash
#
# test_readme_format.sh -- the NATS docs follow the current upstream
# OpenSIPS README.md conventions.
#
# Every module README (modules/<m>/README.md):
#   - one README.md per module (no docbook sources, no generated
#     plain-text README), YAML front matter with title and description;
#   - "## Admin Guide", then "### Overview", topical "###" sections,
#     "### Limitations", "### Dependencies" ("#### OpenSIPS Modules" and
#     "#### External Libraries or Applications", each with the upstream
#     intro sentence), "### Exported Parameters", "### Exported
#     Functions", "### Exported Asynchronous Functions", then the MI /
#     Statistics / Events / Pseudo-Variables sections ("### Raw Query..."
#     may follow them);
#   - every exported parameter, function, async function, MI command and
#     pseudo-variable (read from the module's *_export_t tables) has its
#     own "####" entry, and every "####" entry in those sections names an
#     export: "#### name (string|integer)" matching STR_PARAM/INT_PARAM,
#     "#### name(args)", "#### module:cmd", "#### $pv";
#   - parameter entries carry a modparam example and the
#     "*Default value is ...*" form; function entries say "This function
#     can be used from ..." and "Meaning of the parameters is as
#     follows:" and carry an opensips example; MI entries carry a
#     "Parameters:" list naming every recipe parameter and a
#     module-qualified opensips-cli example; event entries a
#     "Parameters:" list;
#   - mentions of an exported name are links, not `code` text; function
#     link labels end in "()", MI link labels are module-qualified;
#   - a blank line before every heading, no raw <tag> text in headings,
#     GitHub admonitions ("> [!NOTE]"...) instead of "Note:" prose, no
#     '(see "x" - [x](#x))' double links, in-page links resolve, and the
#     fixed upstream footer.
# Every README in scope (modules + lib/nats/README.md +
# lib/nats/patches/README.md):
#   - LF line endings and no NUL bytes, balanced fences that name a
#     language, title= only after a language, no markup inside titles;
#   - opensips-cli MI calls are module-qualified, shown in ```bash
#     without a "$ " prompt or commented out, and their output (or any
#     log output) is in a separate block;
#   - relative links to other README.md files resolve to an existing
#     file and heading.
# lib/nats/README.md also links every module README.
#
# README_FORMAT_FILES (space-separated paths) overrides the list of
# READMEs; selftest_readme_format.sh uses it.  A README under
# .../modules/<m>/ gets the module checks, reading the export tables
# from .../modules/<m>/*.c and the other modules' tables from its
# sibling directories.
#
# bash + awk (POSIX awk: runs with mawk).  Exit 0 = all checks pass.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TREE="$(cd "$HERE/../../.." && pwd)"
NATS_MODS="cachedb_nats cachedb_nats_fts event_nats nats_consumer"
FAILS=0
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

check() {  # check <description> <expected> <actual>
    if [ "$2" = "$3" ]; then echo "  ok: $1"
    else echo "  FAIL: $1 (expected '$2', got '$3')"; FAILS=$((FAILS + 1)); fi
}
none() {   # none <description> <problems>: pass when there are none
    if [ -z "$2" ]; then echo "  ok: $1"
    else echo "  FAIL: $1"; printf '%s\n' "$2" | sed 's/^/      /'
         FAILS=$((FAILS + 1)); fi
}

FOOTER='<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0'

# GitHub heading slug: lowercase, drop everything but [a-z0-9 _-], spaces -> "-"
slugs() {
    awk '/^```/ { f = !f; next } !f && /^#+ / {
            h = $0; sub(/^#+ +/, "", h); h = tolower(h)
            gsub(/[^a-z0-9 _-]/, "", h); gsub(/ /, "-", h)
            n[h]++; if (n[h] > 1) h = h "-" (n[h] - 1)
            print h }' "$1"
}

# exports <module-dir>: the module's export tables, one per line:
#   param <name> string|integer|other     cmd <name>   (script-callable)
#   acmd <name>    mi <name> <p1,p2,...|->    pv <name>
exports() {
    cat "$1"/*.c 2>/dev/null | awk '
        function flush(   ps, s, p, t) {
            if (name == "") return
            if (blk == "param") {
                t = "other"
                if (text ~ /STR_PARAM/) t = "string"; else if (text ~ /INT_PARAM/) t = "integer"
                print "param", name, t
            } else if (blk == "cmd") { if (text ~ /ROUTE/) print "cmd", name }
            else if (blk == "acmd") print "acmd", name
            else if (blk == "mi") {
                ps = ""; s = text; split("", seen)
                while (match(s, /"[a-z_]+"/)) {
                    p = substr(s, RSTART + 1, RLENGTH - 2); s = substr(s, RSTART + RLENGTH)
                    if (!(p in seen)) { seen[p] = 1; ps = ps (ps == "" ? "" : ",") p }
                }
                print "mi", name, (ps == "" ? "-" : ps)
            }
            name = ""
        }
        { line = $0; gsub(/\/\*[^*]*\*+([^\/*][^*]*\*+)*\//, "", line) }
        line ~ /^[ \t]*(\/\*|\*)/ { next }
        blk == "" && line ~ /acmd_export_t[^;]*=/  { blk = "acmd";  next }
        blk == "" && line ~ /cmd_export_t[^;]*=/   { blk = "cmd";   next }
        blk == "" && line ~ /param_export_t[^;]*=/ { blk = "param"; next }
        blk == "" && line ~ /mi_export_t[^;]*=/    { blk = "mi";    next }
        blk == "" && line ~ /pv_export_t[^;]*=/    { blk = "pv";    next }
        blk == "" { next }
        line ~ /^};/ { flush(); blk = ""; next }
        blk == "pv" {
            if (match(line, /str_const_init\("[^"]+"\)/))
                print "pv", substr(line, RSTART + 16, RLENGTH - 18)
            next
        }
        line ~ /^[ \t]*\{[ \t]*"/ {
            flush(); match(line, /"[^"]+"/)
            name = substr(line, RSTART + 1, RLENGTH - 2)
            text = substr(line, RSTART + RLENGTH); next
        }
        name != "" { text = text " " line }'
}

# generic_checks <label> <normalized file> <original file>: checks that
# apply to every README in scope
generic_checks() {
    local f="$2" orig="$3" bad
    check "LF line endings (no CR)" 0 "$(tr -cd '\r' < "$orig" | wc -c | tr -d ' ')"
    check "no NUL bytes" 0 "$(tr -cd '\000' < "$orig" | wc -c | tr -d ' ')"
    check "code fences balanced" 0 "$(( $(grep -c '^```' "$f") % 2 ))"
    check "every opening fence names a language" 0 \
        "$(awk '/^```/ { if (!f && $0 ~ /^```[ \t]*($|title=)/) bad++; f = !f } END { print bad + 0 }' "$f")"
    bad=$(awk '/^```/ { if (!f && $0 ~ /^```[ \t]*title=/) print NR ": " $0; f = !f }' "$f")
    none "title= only on fences that name a language" "$bad"
    bad=$(awk '/^```/ { if (!f && $0 ~ /title="[^"]*[*`<>][^"]*"/) print NR ": " $0; f = !f }' "$f")
    none "no markup in fence titles" "$bad"
    bad=$(awk '/^```/ { if (!f) { lang = $0; sub(/^```/, "", lang); sub(/[ \t].*/, "", lang) }; f = !f; next }
               { l = $0; while (match(l, /opensips-cli[ \t]+-x[ \t]+mi[ \t]+[^ \t]+/)) {
                     c = substr(l, RSTART, RLENGTH); sub(/.*[ \t]/, "", c)
                     if (c !~ /^[a-z0-9_]+:[a-z0-9_]+$/) print NR ": " c
                     l = substr(l, RSTART + RLENGTH) } }' "$f")
    none "opensips-cli MI commands are module-qualified (module:cmd)" "$bad"
    bad=$(awk '/^```/ { if (!f) { lang = $0; sub(/^```/, "", lang); sub(/[ \t].*/, "", lang); start = NR; cli = 0; out = "" }
                       else if (cli && out != "") print start ": " out
                       f = !f; next }
               !f { next }
               /opensips-cli/ { cli = 1
                   if ($0 ~ /^[ \t]*#/) print NR ": commented-out command"
                   if (lang != "bash") print NR ": opensips-cli in a ```" lang " block" }
               lang == "bash" && /^[ \t]*\$ / { print NR ": shell prompt" }
               lang == "bash" && /^(INFO|NOTICE|WARNING|ERROR|CRITICAL|ALERT|DBG):/ { print NR ": log output in a ```bash block" }
               lang == "bash" && /^[ \t]*([]{}[]|"[^"]*":)/ && out == "" { out = "command output inside the ```bash block (line " NR ")" }' "$f")
    none "MI examples: bash block, no prompt, output in a separate block" "$bad"
    bad=$(awk '/^```/ { f = !f; next } !f {
                 l = $0
                 while (match(l, /\]\([^)#: ]+\.md(#[^) ]*)?\)/)) {
                     print NR " " substr(l, RSTART + 2, RLENGTH - 3); l = substr(l, RSTART + RLENGTH) } }' "$f" |
          while read -r ln target; do
              p="${target%%#*}"; s=""; case "$target" in *"#"*) s="${target#*#}";; esac
              t="$(dirname "$orig")/$p"
              if [ ! -f "$t" ]; then echo "$ln: $target (no such file)"; continue; fi
              if [ -n "$s" ]; then
                  tr -d '\r' < "$t" > "$W/target.md"
                  slugs "$W/target.md" | grep -qxF -- "$s" || echo "$ln: $target (no such heading)"
              fi
          done)
    none "links to other READMEs resolve (file and heading)" "$bad"
}

# module_awk: the structural checks of one module README.  Input: the
# export list of all NATS modules ("<module> <kind> <name> ..."), then
# the normalized README.  Output: "<check-key>\t<line>: <detail>".
module_awk() {
    awk -v m="$1" -v emdash="—" '
    function bad(k, d) { print k "\t" FNR ": " d }
    function bad_at(k, ln, d) { print k "\t" ln ": " d }
    function rank(s) {
        if (s == "Overview") return 1
        if (s == "Limitations") return 3
        if (s == "Dependencies") return 4
        if (s == "Exported Parameters") return 5
        if (s == "Exported Functions") return 6
        if (s == "Exported Asynchronous Functions") return 7
        if (s == "Exported MI Functions") return 8
        if (s == "Exported Statistics") return 9
        if (s == "Exported Events") return 10
        if (s == "Exported Pseudo-Variables") return 11
        if (s ~ /^Raw Query/) return 12
        if (s == "License") return 13
        return 2
    }
    function kind(s) {
        if (s == "Exported Parameters") return "param"
        if (s == "Exported Functions") return "func"
        if (s == "Exported Asynchronous Functions") return "async"
        if (s == "Exported MI Functions") return "mi"
        if (s == "Exported Events") return "event"
        if (s == "Exported Pseudo-Variables") return "pv"
        if (s == "Dependencies") return "dep"
        return ""
    }
    function finish(   n, i, ps) {
        if (ek == "param" && !e_modparam) bad_at("param-example", e_line, "#### " en " has no modparam(\"" m "\", \"" en "\", ...) example")
        if (ek == "func" || ek == "async") {
            if (!e_route && !(ek == "async" && e_flavor))
                bad_at("func-route", e_line, "#### " en "() lacks \"This function can be used from ...\"")
            if (e_args && !e_meaning && !(ek == "async" && e_flavor))
                bad_at("func-meaning", e_line, "#### " en "() lacks \"Meaning of the parameters is as follows:\"")
            if (!e_example) bad_at("func-example", e_line, "#### " en "() has no ```opensips example")
        }
        if (ek == "mi") {
            if (!e_params) bad_at("mi-parameters", e_line, "#### " en " lacks a \"Parameters:\" line")
            if ((en in mi_p) && mi_p[en] != "-") {
                n = split(mi_p[en], ps, ",")
                for (i = 1; i <= n; i++)
                    if (index(e_items, "," ps[i] ",") == 0)
                        bad_at("mi-parameters", e_line, "#### " en " does not list parameter *" ps[i] "*")
            }
            if (!e_cli) bad_at("mi-example", e_line, "#### " en " has no ```bash example running opensips-cli -x mi " en)
        }
        if (ek == "event" && !e_params) bad_at("event-parameters", e_line, "#### " en " lacks a \"Parameters:\" line")
        ek = ""; en = ""
    }
    NR == FNR {
        mod = $1; k = $2; nm = $3
        if (mod == m) {
            if (k == "param") { ptype[nm] = $4; own_ref[nm] = 1 }
            else if (k == "cmd") { cmd[nm] = 1; own_ref[nm] = 1 }
            else if (k == "acmd") { acmd[nm] = 1; own_ref[nm] = 1 }
            else if (k == "mi") { mi_p[m ":" nm] = $4; own_ref[nm] = 1; own_ref[m ":" nm] = 1 }
            else if (k == "pv") pv[nm] = 1
        } else if (k != "pv") { other_ref[nm] = mod; if (k == "mi") other_ref[mod ":" nm] = mod }
        if (k == "mi") mi_short[nm] = 1
        if (k == "cmd" || k == "acmd") fn_name[nm] = 1
        next
    }
    FNR == 1 { prev = "" }
    /^```/ {
        if (!fence) {
            fence = 1; lang = $0; sub(/^```/, "", lang); sub(/[ \t].*/, "", lang)
            if (ek != "" && lang == "opensips") e_example = 1
        } else fence = 0
        prev = $0; next
    }
    fence {
        if (ek == "param" && lang == "opensips" && index($0, "modparam(\"" m "\", \"" en "\""))
            e_modparam = 1
        if (ek == "mi" && lang == "bash" && $0 ~ ("opensips-cli[ \t]+-x[ \t]+mi[ \t]+" en "([ \t]|$)"))
            e_cli = 1
        prev = $0; next
    }
    /^#+ / {
        lvl = index($0, " ") - 1; h = $0; sub(/^#+ +/, "", h)
        if (FNR > 1 && prev != "") bad("blank-before-heading", "no blank line before \"" $0 "\"")
        t = h; gsub(/`[^`]*`/, "", t); gsub(/\\</, "", t)
        if (t ~ /<[A-Za-z\/!]/) bad("heading-html", "raw <...> text in \"" $0 "\" (escape it or use backticks)")
        if (tolower(h) ~ /table of contents|^contents$/) bad("no-toc", "table of contents heading \"" $0 "\"")
        if (lvl <= 4) finish()
        if (lvl <= 3) { sec = h; sk = (lvl == 3) ? kind(h) : ""; sub4 = "" }
        if (lvl == 3) {
            r = rank(h)
            if (h == "Limitations") { seen_lim = 1; if (seen_dep) bad("limitations-before-dependencies", "### Limitations comes after ### Dependencies") }
            if (h == "Dependencies") seen_dep = 1
            if (r < last_rank) bad("section-order", "### " h " is out of order (Overview, topical sections, Limitations, Dependencies, Exported Parameters/Functions/Asynchronous Functions/MI/Statistics/Events/Pseudo-Variables, Raw Query)")
            else last_rank = r
        }
        if (lvl == 4 && sk == "dep") {
            sub4 = h
            if (h != "OpenSIPS Modules" && h != "External Libraries or Applications")
                bad("deps-headings", "#### " h " (expected \"OpenSIPS Modules\" / \"External Libraries or Applications\")")
            else { want_intro = h; if (h == "OpenSIPS Modules") has_om = 1; else has_el = 1 }
        }
        if (lvl == 4 && sk != "" && sk != "dep") {
            ek = sk; en = ""; e_line = FNR; e_modparam = e_example = e_route = e_meaning = e_flavor = e_params = e_cli = e_args = 0; e_items = ","
            if (sk == "param") {
                if (h !~ /^[a-z0-9_]+ \((string|integer)\)$/) { bad("param-heading", "\"#### " h "\" (expected \"#### name (string)\" or \"#### name (integer)\")"); en = h; sub(/ .*/, "", en) }
                else { en = h; sub(/ .*/, "", en); ty = h; sub(/^[^(]*\(/, "", ty); sub(/\)$/, "", ty)
                       if (en in ptype && ptype[en] != ty) bad("param-type", "#### " h ": the code exports " en " as " ptype[en]) }
                if (!(en in ptype)) bad("unknown-export", "#### " h ": no such parameter in param_export_t")
                else documented["param " en] = 1
            } else if (sk == "func" || sk == "async") {
                hs = h; gsub(/\\/, "", hs)
                if (hs !~ /^[a-z0-9_]+\(.*\)$/) bad("func-heading", "\"#### " h "\" (expected \"#### name(args)\")")
                en = hs; sub(/\(.*/, "", en)
                a = hs; sub(/^[^(]*\(/, "", a); sub(/\)$/, "", a); e_args = (a ~ /[a-z]/)
                if (sk == "func" && !(en in cmd)) bad("unknown-export", "#### " h ": no such function in cmd_export_t")
                else if (sk == "async" && !(en in acmd)) bad("unknown-export", "#### " h ": no such function in acmd_export_t")
                else documented[sk " " en] = 1
            } else if (sk == "mi") {
                en = h
                if (h !~ ("^" m ":[a-z0-9_]+$")) bad("mi-qualified", "\"#### " h "\" (expected \"#### " m ":<command>\")")
                if (!(h in mi_p)) bad("unknown-export", "#### " h ": no such command in mi_export_t")
                else documented["mi " h] = 1
            } else if (sk == "pv") {
                en = h; sub(/^\$/, "", en); sub(/\(.*/, "", en)
                if (h !~ /^\$[a-z0-9_]+(\(.*\))?$/) bad("pv-heading", "\"#### " h "\" (expected \"#### $name\")")
                else if (!(en in pv)) bad("unknown-export", "#### " h ": no such pseudo-variable in pv_export_t")
                else documented["pv " en] = 1
            } else if (sk == "event") {
                en = h
                if (h !~ /^E_[A-Z0-9_]+$/) bad("event-heading", "\"#### " h "\" (expected \"#### E_NAME\")")
            }
        }
        prev = $0; next
    }
    {
        l = $0
        if (want_intro != "" && l != "") {
            if (want_intro == "OpenSIPS Modules" && l != "The following modules must be loaded before this module:")
                bad("deps-intro", "#### OpenSIPS Modules must open with \"The following modules must be loaded before this module:\"")
            if (want_intro != "OpenSIPS Modules" && l !~ /^The following libraries or applications must be installed before running/)
                bad("deps-intro", "#### External Libraries or Applications must open with \"The following libraries or applications must be installed before running OpenSIPS with this module loaded:\"")
            want_intro = ""
        }
        if (ek != "") {
            if (index(l, "This function can be used from")) e_route = 1
            if (index(l, "Meaning of the parameters is as follows:")) e_meaning = 1
            if (index(l, "The asynchronous flavor of the")) e_flavor = 1
            if (l ~ /^Parameters:/) e_params = 1
            if (match(l, /^- \*[a-z0-9_]+[*(]/)) { it = substr(l, 4, RLENGTH - 4); e_items = e_items it "," }
        }
        if (sk != "" && sk != "dep" && (l ~ /^- \*\*[A-Za-z_$]/ || l ~ ("^- (\\*\\*?[^*]+\\*\\*?|`[^`]+`)( \\([^)]*\\))? " emdash)))
            bad("list-item-form", "list item \"" substr(l, 1, 40) "...\" (use \"- *name* (type) - text\")")
        if (l ~ /[Dd]efault value:/ || (l ~ /^\*Default value/ && l !~ /^\*Default value is /))
            bad("default-form", "\"" l "\" (use *Default value is \"X\".*)")
        t = l; gsub(/`[^`]*`/, "", t)
        if (t ~ /(^|[ (])\*?\*?(Note|NOTE|Warning|WARNING|Important|IMPORTANT|Caution|Tip)\*?\*?:/)
            bad("admonition", "\"" substr(l, 1, 50) "\" (use > [!NOTE] / > [!IMPORTANT] / > [!WARNING])")
        if (l ~ /^>[ \t]*\[!/ && l !~ /^> \[!(NOTE|IMPORTANT|WARNING)\]$/)
            bad("admonition", "\"" l "\" (only > [!NOTE], > [!IMPORTANT], > [!WARNING])")
        if (l ~ /"[^"]+" - \[[^]]*\]\(#/) bad("dup-link", "\"" substr(l, 1, 60) "\" (one link, no quoted repeat)")
        t = l
        while (match(t, /\[[^]]*\]\([^)]*\)/)) {
            lab = substr(t, RSTART + 1, RLENGTH); sub(/\]\(.*/, "", lab); gsub(/`/, "", lab)
            if (lab in mi_short) bad("mi-qualified", "link label [" lab "] (use the module-qualified MI name)")
            if (lab in fn_name) bad("func-link-label", "link label [" lab "] (function labels end in \"()\")")
            t = substr(t, 1, RSTART - 1) " " substr(t, RSTART + RLENGTH)
        }
        while (match(t, /`[^`]+`/)) {
            c = substr(t, RSTART + 1, RLENGTH - 2); t = substr(t, RSTART + RLENGTH); sub(/\(\)$/, "", c)
            if (c in own_ref) bad("xref-link", "`" c "` (link the exported name)")
            else if (c in other_ref) bad("xref-link", "`" c "` (link ../" other_ref[c] "/README.md#...)")
        }
        prev = $0
    }
    END {
        finish()
        for (n in ptype) if (!(("param " n) in documented)) aliasable[n] = 1
        for (n in cmd) if (!(("func " n) in documented)) bad_at("undocumented-export", 0, "function " n "() has no #### entry under ### Exported Functions")
        for (n in acmd) if (!(("async " n) in documented)) bad_at("undocumented-export", 0, "async function " n "() has no #### entry under ### Exported Asynchronous Functions")
        for (n in mi_p) if (!(("mi " n) in documented)) bad_at("undocumented-export", 0, "MI command " n " has no #### entry under ### Exported MI Functions")
        for (n in pv) if (!(("pv " n) in documented)) bad_at("undocumented-export", 0, "pseudo-variable $" n " has no #### entry under ### Exported Pseudo-Variables")
        for (n in aliasable) print "alias?\t" n
        if (!has_om) bad_at("deps-headings", 0, "### Dependencies lacks #### OpenSIPS Modules")
        if (!has_el) bad_at("deps-headings", 0, "### Dependencies lacks #### External Libraries or Applications")
    }' "$2" "$3"
}

MOD_KEYS="blank-before-heading heading-html no-toc section-order limitations-before-dependencies
deps-headings deps-intro param-heading param-type param-example unknown-export undocumented-export
func-heading func-route func-meaning func-example mi-qualified mi-parameters mi-example
pv-heading event-heading event-parameters list-item-form default-form admonition dup-link
func-link-label xref-link"
declare -A KEY_DESC=(
  [blank-before-heading]="blank line before every heading"
  [heading-html]="no raw <tag> text in headings"
  [no-toc]="no table of contents"
  [section-order]="section order (topical sections before Limitations/Dependencies)"
  [limitations-before-dependencies]="### Limitations precedes ### Dependencies"
  [deps-headings]="Dependencies: OpenSIPS Modules + External Libraries or Applications"
  [deps-intro]="Dependencies: upstream intro sentences"
  [param-heading]="parameter headings are '#### name (string|integer)'"
  [param-type]="parameter type labels match param_export_t (STR_PARAM/INT_PARAM)"
  [param-example]="every parameter entry has a modparam example"
  [unknown-export]="every #### entry in an Exported section names an export"
  [undocumented-export]="every exported function / MI command / pseudo-variable has a #### entry"
  [func-heading]="function headings are '#### name(args)'"
  [func-route]="function entries say 'This function can be used from ...'"
  [func-meaning]="function entries say 'Meaning of the parameters is as follows:'"
  [func-example]="function entries have an opensips example"
  [mi-qualified]="MI headings and MI link labels are module-qualified (module:cmd)"
  [mi-parameters]="MI entries have a Parameters: list naming every recipe parameter"
  [mi-example]="MI entries have an opensips-cli example"
  [pv-heading]="pseudo-variable headings are '#### \$name'"
  [event-heading]="event headings are '#### E_NAME'"
  [event-parameters]="event entries have a Parameters: list"
  [list-item-form]="parameter/field lists use '- *name* (type) - text'"
  [default-form]="'*Default value is ...*' form"
  [admonition]="admonitions use > [!NOTE] / > [!IMPORTANT] / > [!WARNING]"
  [dup-link]="no '(see \"x\" - [x](#x))' double links"
  [func-link-label]="function link labels end in ()"
  [xref-link]="mentions of exported names are links, not code text"
)

FILES="${README_FORMAT_FILES:-$(for m in $NATS_MODS; do printf '%s ' "$TREE/modules/$m/README.md"; done)$TREE/lib/nats/README.md $TREE/lib/nats/patches/README.md}"

n=0
for f in $FILES; do
    n=$((n + 1)); N="$W/readme.$n.md"
    case "$f" in "$TREE"/*) rel="${f#$TREE/}";; *) rel="$f";; esac
    echo "== $rel"
    [ -f "$f" ] || { check "README.md exists" yes no; continue; }
    tr -d '\r\000' < "$f" > "$N"
    generic_checks "$rel" "$N" "$f"

    case "$f" in
    */modules/*/README.md)
        d="$(dirname "$f")"; m="$(basename "$d")"; mods="$(dirname "$d")"
        check "no docbook sources left (doc/*.xml)" 0 "$(ls "$d"/doc/*.xml 2>/dev/null | wc -l)"
        check "no generated plain-text README" no "$([ -e "$d/README" ] && echo yes || echo no)"
        check "front matter first" yes "$(head -1 "$N" | grep -qx -- '---' && echo yes || echo no)"
        check "front matter has title" yes "$(awk 'NR>1 && /^---$/{exit} /^title: ".+"$/{print "yes"; exit}' "$N")"
        check "front matter has description" yes "$(awk 'NR>1 && /^---$/{exit} /^description: ".+"$/{print "yes"; exit}' "$N")"
        for h in '## Admin Guide' '### Overview' '### Dependencies' '### Limitations'; do
            check "has '$h'" yes "$(grep -qxF -- "$h" "$N" && echo yes || echo no)"
        done
        missing=$(grep -oE '\]\(#[^)]+\)' "$N" | sed -E 's/^\]\(#//; s/\)$//' | sort -u | while read -r a; do
                      slugs "$N" | grep -qxF -- "$a" || echo "$a"; done)
        check "in-page links resolve${missing:+ (unresolved: $(echo $missing))}" "" "$missing"
        check "ends with the upstream contributors + License footer" yes \
            "$([ "$(tail -n 5 "$N")" = "$FOOTER" ] && echo yes || echo no)"
        check "contributors marker directly follows the last content line" yes \
            "$(awk '/^<!-- CONTRIBUTORS -->$/ { print (p != "" ? "yes" : "no"); exit } { p = $0 }' "$N")"
        # export tables: this module first, then its NATS siblings
        : > "$W/exports"
        for x in "$m" $NATS_MODS; do
            [ -d "$mods/$x" ] || continue
            exports "$mods/$x" | sed "s/^/$x /" >> "$W/exports"
        done
        module_awk "$m" "$W/exports" "$N" | sort -t "$(printf '\t')" -k1,1 -k2,2n > "$W/out"
        # a parameter without its own entry must be documented as an alias
        undoc=$(sed -n 's/^alias?\t//p' "$W/out" | sort | while read -r p; do
                    grep -wF -- "$p" "$N" | grep -qi 'alias' || echo "$p"; done)
        none "every exported parameter has a #### entry (or is documented as an alias)" \
            "$(printf '%s\n' $undoc | sed '/^$/d; s/^/parameter /')"
        for k in $MOD_KEYS; do
            none "${KEY_DESC[$k]}" "$(awk -F'\t' -v k="$k" '$1 == k { print $2 }' "$W/out")"
        done
        ;;
    */lib/nats/README.md)
        for m in $NATS_MODS; do
            check "links modules/$m/README.md" yes \
                "$(grep -qE "\]\(\.\./\.\./modules/$m/README\.md(#[^)]*)?\)" "$N" && echo yes || echo no)"
        done
        check "has '## Limitations'" yes "$(grep -qxF '## Limitations' "$N" && echo yes || echo no)"
        ;;
    esac
done

echo
if [ "$FAILS" -eq 0 ]; then echo "test_readme_format: OK"; exit 0; fi
echo "test_readme_format: $FAILS check(s) FAILED"; exit 1
