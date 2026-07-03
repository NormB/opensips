#!/bin/sh
# lint_url_redaction.sh -- forbid logging unredacted NATS URLs.
#
# A nats:// URL may embed credentials (nats://user:pass@host).  Any log
# site whose arguments include a url-named variable must pass it through
# nats_redact_url() first (lib/nats/nats_redact.c).  This lint joins each
# LM_*(...) statement, strips string literals, and flags statements that
# reference a *url* identifier without 'redact' anywhere in the statement.
#
# Run from anywhere; scans the NATS lib + the three NATS modules.
# Exit 0 = clean, 1 = violations listed on stdout.
#
# Wired into: the repo pre-commit hook and the NATS CI workflow.

set -eu

root=$(cd "$(dirname "$0")/../../.." && pwd)

found=0
for f in "$root"/lib/nats/*.c \
         "$root"/modules/cachedb_nats/*.c \
         "$root"/modules/event_nats/*.c \
         "$root"/modules/nats_consumer/*.c; do
	[ -f "$f" ] || continue
	out=$(awk -v FILE="${f#"$root"/}" '
		/LM_[A-Z]+\(/ { collecting=1; stmt=""; startline=NR }
		collecting {
			stmt = stmt $0 "\n"
			if (index($0, ";")) {
				collecting = 0
				s = stmt
				gsub(/"[^"]*"/, "", s)   # ignore words inside format strings
				if (s ~ /(^|[^A-Za-z0-9_])[A-Za-z_]*url[A-Za-z0-9_]*/ &&
				    s !~ /redact/)
					printf "%s:%d: unredacted URL variable in log call:\n%s\n", \
						FILE, startline, stmt
			}
		}' "$f")
	if [ -n "$out" ]; then
		printf '%s\n' "$out"
		found=1
	fi
done

if [ "$found" -ne 0 ]; then
	echo "lint_url_redaction: FAIL -- pass URL variables through nats_redact_url() before logging" >&2
	exit 1
fi
echo "lint_url_redaction: OK"
