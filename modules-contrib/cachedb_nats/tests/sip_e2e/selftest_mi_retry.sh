#!/bin/bash
# selftest_mi_retry.sh -- mi_at() in lib/helpers.sh rides out a transient
# "503" (JetStream briefly unavailable, e.g. a cluster leader election),
# but returns any other answer -- or no answer -- at once.
#
# Hermetic: nc is stubbed on PATH; the stub records each request and
# answers 503 (or nothing) for the first $STUB_BAD calls.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d -t mi_retry_selftest.XXXXXX)
trap 'rm -rf "$T"' EXIT

mkdir -p "$T/bin"
cat > "$T/bin/nc" <<'STUB'
#!/bin/sh
cat > "$STUB_DIR/req.$(ls "$STUB_DIR" | grep -c '^req\.')"
n=$(ls "$STUB_DIR" | grep -c '^req\.')
if [ "$n" -le "${STUB_BAD:-0}" ]; then
    case "$STUB_KIND" in
    503)   printf '{"jsonrpc":"2.0","error":{"code":503,"message":"key listing failed"},"id":1}' ;;
    404)   printf '{"jsonrpc":"2.0","error":{"code":404,"message":"no such stream"},"id":1}' ;;
    empty) : ;;
    esac
else
    printf '{"jsonrpc":"2.0","result":{"ok":1},"id":1}'
fi
STUB
chmod +x "$T/bin/nc"

# helpers.sh needs these from run.sh
export WORKDIR="$T" NATS_URL=nats://127.0.0.1:1 KV_BUCKET=b
export PATH="$T/bin:$PATH" MI_RETRY_DELAY=0
. "$HERE/lib/helpers.sh"

# after helpers.sh: the shared harness defines its own check()
st_fails=0
st_check() { # label, want, got
    if [ "$2" = "$3" ]; then echo "  ok: $1"
    else echo "  FAIL: $1 (want '$2', got '$3')"; st_fails=$((st_fails + 1)); fi
}

run() { # run <kind> <bad> [MI_RETRIES]; prints "<calls> <answer>"
    rm -rf "$T/s"; mkdir -p "$T/s"
    local out
    out=$(STUB_DIR="$T/s" STUB_KIND="$1" STUB_BAD="$2" MI_RETRIES="${3:-}" \
        mi_at 1 nats_kv_keys)
    printf '%s %s' "$(ls "$T/s" | grep -c '^req\.')" "$out"
}

echo "== transient 503 is retried"
r=$(run 503 2)
st_check "503, 503, ok -> 3 calls" 3 "${r%% *}"
st_check "503, 503, ok -> the ok answer" '{"jsonrpc":"2.0","result":{"ok":1},"id":1}' "${r#* }"

echo "== a persistent 503 is returned after the retries"
r=$(run 503 99)
st_check "503 forever -> 3 calls (MI_RETRIES default)" 3 "${r%% *}"
case "${r#* }" in *'"code":503'*) got=503 ;; *) got="${r#* }" ;; esac
st_check "503 forever -> the 503 answer" 503 "$got"

echo "== no answer is returned at once (readiness pollers rely on it)"
r=$(run empty 1)
st_check "no answer -> 1 call" 1 "${r%% *}"

echo "== other errors are not retried"
r=$(run 404 99)
st_check "404 -> 1 call" 1 "${r%% *}"

echo "== MI_RETRIES=1 disables the retry"
r=$(run 503 99 1)
st_check "MI_RETRIES=1 -> 1 call" 1 "${r%% *}"

echo "== parameters keep their escaping"
rm -rf "$T/s"; mkdir -p "$T/s"
STUB_DIR="$T/s" STUB_KIND=503 STUB_BAD=1 mi_at 1 m 'a\b' 'q"x' '' >/dev/null
st_check "retried request carries the same escaped params" \
    '{"jsonrpc":"2.0","id":1,"method":"m","params":["a\\b","q\"x",""]}' \
    "$(cat "$T/s/req.1")"
st_check "both attempts identical" "$(cat "$T/s/req.0")" "$(cat "$T/s/req.1")"

echo
[ "$st_fails" -eq 0 ] && echo "selftest_mi_retry: all checks passed" \
    || echo "selftest_mi_retry: $st_fails check(s) FAILED"
[ "$st_fails" -eq 0 ]
