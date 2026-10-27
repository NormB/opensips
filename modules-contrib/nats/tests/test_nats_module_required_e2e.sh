#!/bin/bash
# test_nats_module_required_e2e.sh -- each NATS module needs the nats
# module (nats.so): a configuration that loads one without nats.so does
# not start, and the error names the missing module; with nats.so loaded,
# before or after it, the same configuration passes the configuration
# check.
#
# Uses `opensips -C` (module loading and the dependency check, then
# exit): no broker is needed.
#
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/nats_local_lib.sh"

require_opensips_built
for m in event_nats cachedb_nats cachedb_nats_fts nats_consumer; do
    [ -f "${REPO_ROOT}/modules-contrib/${m}/${m}.so" ] || \
        skip "${m}.so not built -- make modules=modules-contrib/${m} modules-contrib"
done

mkworkdir nats_required >/dev/null

# the blocks that load each module (cachedb_nats_fts needs cachedb_nats)
mod_block() {
    case "$1" in
    event_nats)
        echo 'loadmodule "event_nats.so"' ;;
    cachedb_nats)
        echo 'loadmodule "cachedb_nats.so"'
        echo 'modparam("cachedb_nats", "cachedb_url", "nats://127.0.0.1:4222/")' ;;
    cachedb_nats_fts)
        echo 'loadmodule "cachedb_nats.so"'
        echo 'modparam("cachedb_nats", "cachedb_url", "nats://127.0.0.1:4222/")'
        echo 'loadmodule "cachedb_nats_fts.so"' ;;
    nats_consumer)
        echo 'loadmodule "nats_consumer.so"' ;;
    esac
}

# $1 module, $2 where nats.so is loaded: none, before or after
write_cfg() {
    {
        echo 'log_level=3'
        echo 'stderror_enabled=yes'
        echo 'udp_workers=1'
        echo 'socket=udp:127.0.0.1:5196'
        echo "mpath=\"${OPENSIPS_MPATH}\""
        echo 'loadmodule "proto_udp.so"'
        [ "$2" = before ] && echo 'loadmodule "nats.so"'
        mod_block "$1"
        [ "$2" = after ] && echo 'loadmodule "nats.so"'
        echo 'route { exit; }'
    } > "${WORK}/test.cfg"
}

ok=0; total=0
expect() {
    total=$((total+1))
    if eval "$1"; then echo "  ok: $2"; ok=$((ok+1)); else echo "  MISSING: $2"; fi
}

check_cfg() {
    : > "${OPS_LOG}"
    rc=0
    timeout 20 "${OPENSIPS_BIN}" -C -f "${WORK}/test.cfg" > "${OPS_LOG}" 2>&1 || rc=$?
}

for m in event_nats cachedb_nats cachedb_nats_fts nats_consumer; do
    echo "${m}:"
    write_cfg "${m}" none
    check_cfg
    expect '[ "${rc}" -ne 0 ] && [ "${rc}" -ne 124 ]' \
        "without nats.so the configuration is refused (rc=${rc})"
    expect "grep -q 'module ${m} depends on module nats, but it was not loaded' '${OPS_LOG}'" \
        "the error names the nats module"

    for where in before after; do
        write_cfg "${m}" "${where}"
        check_cfg
        expect '[ "${rc}" -eq 0 ]' "nats.so loaded ${where} it: the configuration passes (rc=${rc})"
        [ "${rc}" -eq 0 ] || tail -5 "${OPS_LOG}"
    done
done

echo "${ok}/${total}"
[ "${ok}" -eq "${total}" ] || fail "${ok}/${total} checks passed"
pass "every NATS module requires nats.so"
