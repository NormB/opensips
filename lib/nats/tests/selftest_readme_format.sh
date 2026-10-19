#!/bin/bash
#
# selftest_readme_format.sh -- contract of test_readme_format.sh: a
# known-good module README passes; each convention violation is caught
# on its own; tricky but valid inputs (escaped parens and \< in
# headings, backticks in headings, "####" lines inside a fence, an
# alias-only parameter) do not trip it; CRLF line endings, an embedded
# NUL byte and an empty file fail cleanly.
#
# Fixtures are synthetic: a fake module "fakemod" with its own export
# tables, fed through README_FORMAT_FILES.  bash + awk only.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
T="$HERE/test_readme_format.sh"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
FAILS=0

run() {  # run <readme> -> output of the test, rc in $RC
    OUT=$(README_FORMAT_FILES="$1" bash "$T" 2>&1); RC=$?
}
expect() {  # expect <description> <want-rc> <grep-pattern> [<failed-check-count>]
    local ok=1
    [ "$RC" -eq "$2" ] || ok=0
    printf '%s\n' "$OUT" | grep -qE -- "$3" || ok=0
    if [ $# -ge 4 ]; then
        printf '%s\n' "$OUT" | grep -qE "^test_readme_format: $4 check\(s\) FAILED$" || ok=0
    fi
    printf '%s\n' "$OUT" | grep -qiE '^(g|m)?awk: |syntax error|unbound variable' && ok=0
    if [ "$ok" -eq 1 ]; then echo "  ok: $1"
    else
        echo "  FAIL: $1 (rc=$RC)"; printf '%s\n' "$OUT" | grep -v '^  ok:' | sed 's/^/      /'
        FAILS=$((FAILS + 1))
    fi
}

# fixture <case>: a fresh fake tree; prints the README path
fixture() {
    local d="$W/$1/modules/fakemod"
    mkdir -p "$d" "$W/$1/modules/othermod"
    cp "$W/fakemod.c" "$d/"
    cp "$W/good.md" "$d/README.md"
    printf '## Other\n\n### Some Heading\n\ntext\n' > "$W/$1/modules/othermod/README.md"
    echo "$d/README.md"
}

cat > "$W/fakemod.c" <<'EOF'
static const param_export_t params[] = {
	{"url",         STR_PARAM, &url},
	/* canonical name first; the old spelling stays as an alias */
	{"timeout",     INT_PARAM, &tmo},
	{"old_timeout", INT_PARAM, &tmo},
	{"hook",
	      INT_PARAM | USE_FUNC_PARAM, (void *)hook_setter},
	{0, 0, 0}
};
static const cmd_export_t cmds[] = {
	{"fake_get", (cmd_function)w_get, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{0, 0, 0}},
	ALL_ROUTES},
	{"fake_bind_api", (cmd_function)bind_api, {{0, 0, 0}}, 0},
	{"fake_ping", (cmd_function)w_ping, {
		{0, 0, 0}},
	REQUEST_ROUTE | STARTUP_ROUTE},
	{0, 0, {{0, 0, 0}}, 0}
};
static const acmd_export_t acmds[] = {
	{ "fake_get", (acmd_function)w_get_async, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, 0, 0},
		{0, 0, 0}} },
	{ 0, 0, {{0, 0, 0}} }
};
static const mi_export_t mi_cmds[] = {
	{ "fake_status", 0, 0, 0, {
		{mi_status, {0}},
		{mi_status, {"filter", 0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{ "fake_reset", "reset the counters", 0, 0, {
		{mi_reset, {0}},
		{EMPTY_MI_RECIPE}},
		{0}
	},
	{EMPTY_MI_EXPORT}
};
static const pv_export_t mod_pvars[] = {
	{ str_const_init("fake_val"), 1000, pv_get_val,
		0, 0, 0, 0, 0 },
	{ str_const_init("fake_hdr"), 1000, pv_get_hdr,
		0, pv_parse_hdr, 0, 0, 0 },
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};
EOF

cat > "$W/good.md" <<'EOF'
---
title: "fakemod Module"
description: "A fake module used to exercise the README format checks."
---

## Admin Guide


### Overview


The module reads [url](#url-string) and calls
[fake_get()](#fake_getkey-result) or its
[asynchronous flavor](#fake_getkey-result-1).  See
[the other module](../othermod/README.md#some-heading) and
[fakemod:fake_status](#fakemodfake_status).  A `fake_get("k", $var(v))`
call is code, not a cross-reference.


### Keys like \<prefix\>.\<id\>


Topical section with an escaped \<tag\> in its heading.


#### The `KV PURGE <key>` command


Backticks may hold angle brackets.


> [!NOTE]
> An admonition.


### Limitations


- Nothing works.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *tls_mgm* if [url](#url-string) uses TLS.


#### External Libraries or Applications


The following libraries or applications must be installed before running
OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### url (string)


The server URL.


*Default value is "nats://127.0.0.1:4222".*


```opensips title="Set url parameter"
...
modparam("fakemod", "url", "nats://10.0.0.1:4222")
...
```


#### timeout (integer)


The old name "old_timeout" is accepted as an alias.


*Default value is "10" (seconds).*


```opensips title="Set timeout parameter"
...
modparam("fakemod", "timeout", 5)
...
```


#### hook (integer)


*Default value is "0" (off).*


```opensips title="Set hook parameter"
modparam("fakemod", "hook", 1)
```


### Exported Functions


#### fake_get(key, [result])


Fetches a key.


Meaning of the parameters is as follows:


- *key* (string) - the key.
- *result* (var, optional) - where to store it.


This function can be used from any route.


```text
#### not a heading: fences are skipped
### Exported Bogus
```


```opensips title="fake_get usage"
fake_get("k", $var(v));
```


#### fake_ping()


Pings.  This function can be used from REQUEST_ROUTE and
STARTUP_ROUTE.


```opensips title="fake_ping usage"
fake_ping();
```


### Exported Asynchronous Functions


#### fake_get\(key, [result]\)


The asynchronous flavor of the [fake_get()](#fake_getkey-result)
function. It receives the same parameters, with the same meanings.


```opensips title="async fake_get usage"
async(fake_get("k", $var(v)), resume);
```


### Exported MI Functions


#### fakemod:fake_status


Reports the status.


Parameters:


- *filter* (optional) - a filter.


```bash
opensips-cli -x mi fakemod:fake_status
opensips-cli -x mi fakemod:fake_status filter=x
```


```json
{ "ok": 1 }
```


#### fakemod:fake_reset


Parameters: *none*


```bash
opensips-cli -x mi fakemod:fake_reset
```


### Exported Events


#### E_FAKE_EVENT


Parameters:


- *key* - the key.


### Exported Pseudo-Variables


#### $fake_val


The value.


#### $fake_hdr(name)


A header.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
EOF

echo "== good fixture"
run "$(fixture good)"
expect "a README following every convention passes" 0 '^test_readme_format: OK$'
expect "the mask-0 API export (fake_bind_api) needs no entry" 0 'every exported function / MI command / pseudo-variable has a #### entry'

# bad [-n <count>] <case> <description> <check-pattern> <sed-or-awk ...>:
# one violation on top of the good fixture, caught by the named check
# (and by nothing else unless -n says how many checks it trips)
bad() {
    local n=1; [ "$1" = "-n" ] && { n="$2"; shift 2; }
    local c="$1" desc="$2" pat="$3"; shift 3
    local f; f=$(fixture "$c")
    "$@" "$f" > "$f.new" && mv "$f.new" "$f"
    run "$f"
    expect "$desc" 1 "FAIL: $pat" "$n"
}

echo "== each violation is caught on its own"
bad -n 4 unqual_mi_heading "MI heading not module-qualified" "MI headings and MI link labels are module-qualified" \
    sed 's/^#### fakemod:fake_reset$/#### fake_reset/; s/mi fakemod:fake_reset$/mi fake_reset/'
bad unqual_cli "opensips-cli line not module-qualified" "opensips-cli MI commands are module-qualified" \
    sed 's/^opensips-cli -x mi fakemod:fake_status filter=x$/opensips-cli -x mi fake_status filter=x/'
bad mi_link_label "bare MI name as link label" "MI headings and MI link labels" \
    sed 's/^\[fakemod:fake_status\](#fakemodfake_status)/[fake_status](#fakemodfake_status)/'
bad param_type "parameter type label disagrees with the code" "parameter type labels match param_export_t" \
    sed 's/^#### url (string)$/#### url (integer)/; s/(#url-string)/(#url-integer)/g'
bad param_label "parameter type label not string|integer" "parameter headings are" \
    sed 's/^#### url (string)$/#### url (string, multiple)/; s/(#url-string)/(#url-string-multiple)/g'
bad -n 2 unknown_param "entry for a parameter the code does not export" "every #### entry in an Exported section names an export" \
    sed 's/^#### hook (integer)$/#### hooks (integer)/; s/"fakemod", "hook"/"fakemod", "hooks"/'
bad undoc_func "exported function without an entry" "every exported function / MI command / pseudo-variable" \
    awk '/^#### fake_ping\(\)$/ { skip = 1 } /^### Exported Asynchronous/ { skip = 0 } !skip'
bad undoc_param "exported parameter without an entry or alias note" "every exported parameter has a #### entry" \
    sed 's/^The old name "old_timeout" is accepted as an alias\.$/Timeout in seconds./'
bad undoc_pv "pseudo-variable without an entry" "every exported function / MI command / pseudo-variable" \
    sed 's/^#### \$fake_hdr(name)$/A header heading went missing./'
bad default_colon "'*Default value:*' form" "'\*Default value is \.\.\.\*' form" \
    sed 's/^\*Default value is "10" (seconds)\.\*$/*Default value:* `10`/'
bad route_sentence "function entry without the route sentence" "function entries say 'This function can be used from" \
    sed 's/^This function can be used from any route\.$/Use it anywhere./'
bad meaning "function entry without 'Meaning of the parameters is as follows:'" "function entries say 'Meaning of the parameters" \
    sed 's/^Meaning of the parameters is as follows:$/Parameters:/'
bad func_example "function entry without an opensips example" "function entries have an opensips example" \
    sed 's/^```opensips title="fake_ping usage"$/```text/'
bad param_example "parameter entry without a modparam example" "every parameter entry has a modparam example" \
    sed 's/^modparam("fakemod", "hook", 1)$/# nothing/'
bad mi_params "MI entry without a Parameters: list" "MI entries have a Parameters: list" \
    sed 's/^Parameters: \*none\*$/No parameters./'
bad mi_param_item "MI entry not listing a recipe parameter" "MI entries have a Parameters: list naming every recipe parameter" \
    sed 's/^- \*filter\* (optional) - a filter\.$/- a filter can be given./'
bad -n 3 title_nolang "title= on a fence with no language" "title= only on fences that name a language" \
    sed 's/^```opensips title="fake_get usage"$/``` title="fake_get usage"/'
bad title_markup "markup inside a fence title" "no markup in fence titles" \
    sed 's/^```opensips title="Set url parameter"$/```opensips title="Set *url* parameter"/'
bad xfile_slug "cross-file link to a missing heading" "links to other READMEs resolve" \
    sed 's|(\.\./othermod/README\.md#some-heading)|(../othermod/README.md#no-such-heading)|'
bad xfile_file "cross-file link to a missing file" "links to other READMEs resolve" \
    sed 's|(\.\./othermod/README\.md#some-heading)|(../nomod/README.md#some-heading)|'
bad dup_link "duplicate-link construction" "no '\(see" \
    sed 's/^The server URL\.$/The server URL (see "url" - [url](#url-string))./'
bad heading_html "raw <tag> in a heading" "no raw <tag> text in headings" \
    sed 's/^### Keys like \\<prefix\\>\.\\<id\\>$/### Keys like <prefix>.<id>/'
bad note_italic "'*Note:*' instead of an admonition" "admonitions use" \
    sed 's/^Backticks may hold angle brackets\.$/*Note:* backticks may hold angle brackets./'
bad note_caps "'NOTE:' instead of an admonition" "admonitions use" \
    sed 's/^Backticks may hold angle brackets\.$/NOTE: backticks may hold angle brackets./'
bad admon_kind "unsupported admonition kind" "admonitions use" \
    sed 's/^> \[!NOTE\]$/> [!DANGER]/'
bad -n 2 lim_after_dep "Limitations after Dependencies" "### Limitations precedes ### Dependencies" \
    awk '/^### Limitations$/ { hold = 1 } /^### Dependencies$/ { hold = 0 } hold { buf = buf $0 "\n"; next }
         /^### Exported Parameters$/ { printf "%s", buf } { print }'
bad topical_late "topical section after the exported sections" "section order" \
    awk '{ print } /^A header\.$/ { print ""; print ""; print "### Usage"; print ""; print ""; print "text" }'
bad backtick_xref "exported name as code text instead of a link" "mentions of exported names are links" \
    sed 's/^Topical section with an escaped/Topical section (see `timeout`) with an escaped/'
bad func_label "function link label without ()" "function link labels end in" \
    sed 's/^\[fake_get()\](#fake_getkey-result) or its$/[fake_get](#fake_getkey-result) or its/'
bad deps_intro "Dependencies intro sentence missing" "Dependencies: upstream intro sentences" \
    sed 's/^The following modules must be loaded before this module:$/Modules:/'
bad deps_heading "Dependencies sub-heading renamed" "Dependencies: OpenSIPS Modules \+ External" \
    sed 's/^#### External Libraries or Applications$/#### External Libraries/'
bad cli_prompt "shell prompt in an MI example" "MI examples: bash block" \
    sed 's/^opensips-cli -x mi fakemod:fake_reset$/$ opensips-cli -x mi fakemod:fake_reset/'
bad cli_output "MI output mixed into the bash block" "MI examples: bash block" \
    sed 's/^opensips-cli -x mi fakemod:fake_reset$/opensips-cli -x mi fakemod:fake_reset\n{\n    "ok": 1\n}/'
bad cli_commented "commented-out MI command" "MI examples: bash block" \
    sed 's/^opensips-cli -x mi fakemod:fake_reset$/## opensips-cli -x mi fakemod:fake_reset/'
bad list_item "bold name and em dash in a parameter list" "parameter/field lists use" \
    sed 's/^- \*key\* (string) - the key\.$/- **key** (string) — the key./'
bad footer_gap "blank line before the contributors marker" "contributors marker directly follows" \
    sed 's/^A header\.$/A header.\n/'

f=$(fixture no_blank)
awk '/^$/ { blanks = blanks "\n"; next }
     { if ($0 != "### Limitations") printf "%s", blanks; blanks = ""; print }' "$f" > "$f.new" && mv "$f.new" "$f"
run "$f"; expect "heading glued to the previous paragraph" 1 'FAIL: blank line before every heading' 1

echo "== tricky inputs"
f=$(fixture crlf); sed 's/$/\r/' "$f" > "$f.new" && mv "$f.new" "$f"
run "$f"; expect "CRLF endings: only the line-ending check fails" 1 'FAIL: LF line endings' 1
f=$(fixture nul); sed 's/^The server URL\.$/The server\x00 URL./' "$f" > "$f.new" && mv "$f.new" "$f"
run "$f"; expect "embedded NUL byte: only the NUL check fails" 1 'FAIL: no NUL bytes' 1
f=$(fixture empty); : > "$f"
run "$f"; expect "empty file fails cleanly" 1 'FAIL: front matter first'
f=$(fixture fence_heading)
sed 's/^#### not a heading: fences are skipped$/#### fakemod:not_exported/' "$f" > "$f.new" && mv "$f.new" "$f"
run "$f"; expect "#### lines inside a fence are not entries" 0 '^test_readme_format: OK$'
f=$(fixture backslash)
sed 's/^#### fake_ping()$/#### fake_ping\\(\\)/' "$f" > "$f.new" && mv "$f.new" "$f"
run "$f"; expect "backslash-escaped parens in a function heading" 0 '^test_readme_format: OK$'
f=$(fixture missing); rm -f "$f"
run "$f"; expect "a missing README fails" 1 'FAIL: README.md exists'

echo
if [ "$FAILS" -eq 0 ]; then echo "selftest_readme_format: OK"; exit 0; fi
echo "selftest_readme_format: $FAILS case(s) FAILED"; exit 1
