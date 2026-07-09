#!/bin/sh
# lint_key_redaction.sh -- forbid logging raw KV row keys in cachedb_nats.
#
# usrloc row keys encode the AoR ("usrloc.alice@example.com"), so a raw
# key in a log line is user-identifying data (PII) even when URL
# credentials are redacted.  Any non-DBG log site whose arguments
# reference a key-named variable must pass it through nats_redact_key()
# (lib/nats/nats_redact.c) first.  LM_DBG sites are exempt: their
# arguments only evaluate when debugging is enabled, and an unconditional
# redact call would tax the hot path.
#
# A statement may opt out with a trailing /* not PII */ comment when the
# key is provably synthetic (e.g. the TTL canary key).
#
# Run from anywhere; scans modules/cachedb_nats only (the usrloc-bearing
# module).  Exit 0 = clean, 1 = violations listed on stdout.
#
# Wired into: the NATS CI workflow next to lint_url_redaction.sh.

set -eu

root=$(cd "$(dirname "$0")/../../.." && pwd)

found=0
for f in "$root"/modules/cachedb_nats/*.c; do
	[ -f "$f" ] || continue
	out=$(awk -v FILE="${f#"$root"/}" '
		/LM_(ERR|WARN|NOTICE|INFO|CRIT|ALERT)\(/ { collecting=1; stmt=""; startline=FNR }
		collecting {
			stmt = stmt $0 "\n"
			if (index($0, ";")) {
				collecting = 0
				s = stmt
				gsub(/"[^"]*"/, "", s)   # ignore words inside format strings
				if (s ~ /(^|[^A-Za-z0-9_])(key|key_buf|kv_key|row_key)([^A-Za-z0-9_]|$)/ &&
				    s !~ /redact/ && s !~ /not PII/)
					printf "%s:%d: raw KV key in log call:\n%s\n", \
						FILE, startline, stmt
			}
		}' "$f")
	if [ -n "$out" ]; then
		printf '%s\n' "$out"
		found=1
	fi
done

if [ "$found" -ne 0 ]; then
	echo "lint_key_redaction: FAIL -- pass row keys through nats_redact_key() before logging (or mark synthetic keys /* not PII */)" >&2
	exit 1
fi
echo "lint_key_redaction: OK"
