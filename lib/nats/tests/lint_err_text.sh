#!/bin/sh
# lint_err_text.sh -- KV error logs carry libnats' detail, not just the
# status name.
#
# natsStatus_GetText(s) alone logs "Error" / "Invalid Argument"; the
# reason (a broker message such as "replicas > 1 not supported in
# non-clustered mode", or "Invalid key") is in nats_GetLastError().
# The cachedb_nats KV paths and the pool's bucket create/bind must log
# through NATS_ERR_TEXT(s) (lib/nats/nats_err.h), which joins the two.
#
# Exit 0 = clean, 1 = offending lines listed on stdout.
set -eu
root=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$root"

files="modules/cachedb_nats/cachedb_nats_dbase.c
modules/cachedb_nats/cachedb_nats_native.c
modules/cachedb_nats/cachedb_nats_json.c"

out=$(grep -nH 'natsStatus_GetText(s)' $files || true)
# the pool's KV bucket bind/create function
pool=$(awk '/^kvStore \*nats_pool_get_kv\(/,/^}/ { if (/natsStatus_GetText\(s\)/) print FILENAME ":" FNR ":" $0 }' lib/nats/nats_pool.c)
out=$(printf '%s\n%s' "$out" "$pool" | sed '/^$/d')

if [ -n "$out" ]; then
	printf '%s\n' "$out"
	echo "lint_err_text: $(printf '%s\n' "$out" | wc -l) KV error log(s) without the libnats detail -- use NATS_ERR_TEXT(s)"
	exit 1
fi
echo "lint_err_text: OK"
