#!/bin/bash
#
# selftest_tls_probe.sh -- hermetic self-test for libnats_tls_probe.sh,
# the "is the libnats opensips will load TLS-capable?" check shared by the
# lib/nats and nats_consumer tls_mgm smokes.  ldd and ldconfig are stubbed
# on PATH, so this runs anywhere.
#
# Pins:
#   1. $NATS_DL_LIBNATS_PATH wins over the system libnats (it is what
#      lib/nats/nats_dl.c dlopen()s when set).
#   2. Without it, the system libnats from `ldconfig -p` is checked.
#   3. TLS-capable == dynamically links libssl or libwolfssl (a libnats
#      built with the wolfSSL patch in lib/nats/patches/).
#   4. A missing or unfindable library is "not TLS-capable", with a reason.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d -t tls_probe_selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
FAILS=0
check() {
    if [ "$2" = "$3" ]; then echo "  ok: $1"
    else echo "  FAIL: $1 (expected '$2', got '$3')"; FAILS=$((FAILS + 1)); fi
}

mkdir -p "$WORK/bin" "$WORK/lib"
: > "$WORK/lib/libnats-tls.so"
: > "$WORK/lib/libnats-plain.so"
: > "$WORK/lib/libnats-wolf.so"
# ldd stub: libraries whose FILE name contains "tls" link libssl (the
# work dir's own name may contain "tls", so match the basename only)
cat > "$WORK/bin/ldd" <<'STUB'
#!/bin/sh
echo "	libc.so.6 => /lib/libc.so.6"
case "$(basename "$1")" in
    *tls*)  echo "	libssl.so.3 => /lib/libssl.so.3" ;;
    *wolf*) echo "	libwolfssl.so.44 => /opt/wolfssl/lib/libwolfssl.so.44" ;;
esac
STUB
# ldconfig stub: reports $FAKE_SYSTEM_LIBNATS as the system libnats (if set)
cat > "$WORK/bin/ldconfig" <<'STUB'
#!/bin/sh
[ "$1" = "-p" ] || exit 0
[ -n "${FAKE_SYSTEM_LIBNATS:-}" ] && \
    echo "	libnats.so (libc6,x86-64) => ${FAKE_SYSTEM_LIBNATS}"
exit 0
STUB
chmod +x "$WORK/bin/ldd" "$WORK/bin/ldconfig"

probe() {  # probe <NATS_DL_LIBNATS_PATH or -> <system libnats or -> -> rc
    (
        export PATH="$WORK/bin:$PATH"
        if [ "$1" = - ]; then unset NATS_DL_LIBNATS_PATH; else export NATS_DL_LIBNATS_PATH="$1"; fi
        if [ "$2" = - ]; then unset FAKE_SYSTEM_LIBNATS; else export FAKE_SYSTEM_LIBNATS="$2"; fi
        [ -f "$HERE/libnats_tls_probe.sh" ] || { echo "missing"; exit 0; }
        . "$HERE/libnats_tls_probe.sh"
        libnats_tls_check >/dev/null 2>&1
        echo $?
    )
}

T="$WORK/lib/libnats-tls.so"; P="$WORK/lib/libnats-plain.so"; WF="$WORK/lib/libnats-wolf.so"
echo "== libnats_tls_check"
check "override -> TLS lib (system plain) = capable"         0 "$(probe "$T" "$P")"
check "override -> plain lib (system TLS) = not capable"     1 "$(probe "$P" "$T")"
check "no override, system TLS = capable"                    0 "$(probe - "$T")"
check "no override, system plain = not capable"              1 "$(probe - "$P")"
check "override -> missing file = not capable"               1 "$(probe "$WORK/lib/nope.so" "$T")"
check "no override, no system libnats = not capable"         1 "$(probe - -)"
check "override -> wolfSSL-backed lib = capable"              0 "$(probe "$WF" "$P")"

reason=$( export PATH="$WORK/bin:$PATH" NATS_DL_LIBNATS_PATH="$P"
          [ -f "$HERE/libnats_tls_probe.sh" ] && . "$HERE/libnats_tls_probe.sh" && libnats_tls_check )
case "$reason" in *"$P"*libssl*) r=names-lib ;; *) r="${reason:-<none>}" ;; esac
check "reason names the library and the missing libssl" names-lib "$r"

# ---- optional live section: the two smokes honour the probe -------------
# Needs a built tree and real libraries: PLAIN_LIBNATS=<non-TLS libnats>
# and TLS_LIBNATS=<TLS-built libnats>.  Skipped when either is unset.
TREE="$(cd "$HERE/../../.." && pwd)"
if [ -n "${PLAIN_LIBNATS:-}" ] && [ -n "${TLS_LIBNATS:-}" ]; then
    echo "== live: smokes honour the probe"
    NATS_DL_LIBNATS_PATH="$PLAIN_LIBNATS" timeout 120 \
        "$TREE/lib/nats/tests/test_tls_mgm_smoke.sh" >"$WORK/lib_smoke.log" 2>&1
    check "lib/nats smoke, non-TLS libnats -> skip (77)" 77 "$?"
    NATS_DL_LIBNATS_PATH="$TLS_LIBNATS" timeout 300 \
        "$TREE/modules/nats_consumer/tests/test_tls_mgm_consumer_smoke.sh" \
        >"$WORK/consumer_smoke.log" 2>&1
    check "consumer smoke, TLS libnats via override -> runs and passes (0)" 0 "$?"
else
    echo "== live section skipped (set PLAIN_LIBNATS and TLS_LIBNATS)"
fi

echo
if [ "$FAILS" -eq 0 ]; then echo "selftest_tls_probe: OK"; exit 0; fi
echo "selftest_tls_probe: $FAILS check(s) FAILED"; exit 1
