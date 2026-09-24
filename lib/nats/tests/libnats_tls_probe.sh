# libnats_tls_probe.sh -- is the libnats that opensips will load
# TLS-capable?  Sourced by the lib/nats and nats_consumer tls_mgm smokes.
#
# A libnats built without TLS makes the pool refuse tls:// URLs (no silent
# plaintext downgrade), so a TLS smoke against it can only fail for an
# environmental reason; the smokes skip with this probe's reason instead.
#
# The library checked is the one lib/nats/nats_dl.c will dlopen():
# $NATS_DL_LIBNATS_PATH when set, otherwise the system libnats that
# `ldconfig -p` resolves.  TLS-capable == dynamically links libssl.

# libnats_path -> path of the libnats opensips will load ("" if none found)
libnats_path() {
    if [ -n "${NATS_DL_LIBNATS_PATH:-}" ]; then
        printf '%s\n' "${NATS_DL_LIBNATS_PATH}"
        return
    fi
    ldconfig -p 2>/dev/null | awk '/libnats\.so /{print $NF; exit}'
}

# libnats_tls_check -> 0 if TLS-capable; else prints the reason, returns 1
libnats_tls_check() {
    local lib
    lib="$(libnats_path)"
    if [ -z "${lib}" ]; then
        echo "no libnats found (ldconfig -p has none; set NATS_DL_LIBNATS_PATH)"
        return 1
    fi
    if [ ! -f "${lib}" ]; then
        echo "libnats ${lib} does not exist"
        return 1
    fi
    if ! ldd "${lib}" 2>/dev/null | grep -q libssl; then
        echo "libnats at ${lib} was built without TLS (no libssl linkage); rebuild with -DNATS_BUILD_WITH_TLS=ON or point NATS_DL_LIBNATS_PATH at a TLS build"
        return 1
    fi
    return 0
}
