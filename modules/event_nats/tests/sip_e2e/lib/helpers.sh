# Shared helpers for the bidirectional SIP <-> NATS e2e suite.
# Sourced by run.sh BEFORE the test cases execute.  All test cases
# can rely on these symbols being defined.
#
# Test cases call check() to register pass/fail; the runner aggregates
# and exits non-zero unless every case passes.

# ── globals expected from run.sh ────────────────────────────────
: "${WORKDIR:?WORKDIR must be set by run.sh}"
: "${NATS_URL:?NATS_URL must be set by run.sh}"
: "${MI_DGRAM_HOST:=127.0.0.1}"
: "${MI_DGRAM_PORT:=8889}"
: "${SIP_HOST:=127.0.0.1}"
: "${SIP_PORT:=5072}"

# ── result aggregation ──────────────────────────────────────────
SUITE_PASS=0
SUITE_FAIL=0
declare -a FAILED_CASES

case_name=""
case_begin() {
    case_name="$1"
    echo "[$(date +%H:%M:%S)] CASE: $case_name"
}

check() {
    local label=$1
    local ok=$2
    local detail=${3:-}
    if [ "$ok" = ok ]; then
        echo "  PASS: $label"
        SUITE_PASS=$((SUITE_PASS + 1))
    else
        echo "  FAIL: $label"
        [ -n "$detail" ] && echo "        $detail"
        SUITE_FAIL=$((SUITE_FAIL + 1))
        FAILED_CASES+=("${case_name}::${label}")
    fi
}

# ── nats CLI wrappers ───────────────────────────────────────────
n() { nats --server "$NATS_URL" "$@"; }

publish_subject() {
    # publish_subject <subject> <payload>
    n publish "$1" "$2" >/dev/null 2>&1
}

kv_add_bucket() {
    # kv_add_bucket <name> [history] [replicas]
    local name=$1; local hist=${2:-5}; local rep=${3:-1}
    n kv add "$name" --history="$hist" --replicas="$rep" \
        >/dev/null 2>&1 || true
}

kv_put() {
    # kv_put <bucket> <key> <value>
    n kv put "$1" "$2" "$3" >/dev/null 2>&1
}

kv_del() {
    # kv_del <bucket> <key>
    n kv del "$1" "$2" -f >/dev/null 2>&1
}

kv_get_value() {
    # kv_get_value <bucket> <key>  ->  prints raw value
    n kv get "$1" "$2" --raw 2>/dev/null
}

stream_add() {
    # stream_add <name> <subjects-spec>
    n stream add "$1" --subjects "$2" --storage memory \
        --defaults >/dev/null 2>&1 || true
}

stream_purge() {
    n stream purge "$1" -f >/dev/null 2>&1 || true
}

consumer_rm() {
    # consumer_rm <stream> <consumer>
    n consumer rm "$1" "$2" -f >/dev/null 2>&1 || true
}

# ── MI over UDP datagram ────────────────────────────────────────
# JSON-RPC 2.0 with positional params.
mi() {
    # mi <method> [param ...]  ->  prints response on stdout
    local method=$1; shift
    local params=""
    if [ $# -gt 0 ]; then
        params=',"params":['
        local first=1
        for p in "$@"; do
            [ $first -eq 1 ] || params="${params},"
            first=0
            # naive JSON string escape (good enough for ASCII)
            local esc
            esc=$(printf '%s' "$p" | sed 's/\\/\\\\/g; s/"/\\"/g')
            params="${params}\"${esc}\""
        done
        params="${params}]"
    fi
    local payload="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"${method}\"${params}}"
    printf '%s' "$payload" | timeout 3 nc -u -w 2 \
        "$MI_DGRAM_HOST" "$MI_DGRAM_PORT"
}

# ── log assertions ──────────────────────────────────────────────
log_contains() {
    # log_contains <pattern>  -> 0 if found, 1 otherwise
    grep -q -- "$1" "$WORKDIR/opensips.log"
}

log_count() {
    # log_count <pattern>
    grep -c -- "$1" "$WORKDIR/opensips.log" 2>/dev/null || echo 0
}

wait_for_log() {
    # wait_for_log <timeout-sec> <pattern>  -> 0 on hit, 1 on timeout
    local timeout=$1
    local pattern=$2
    local end=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$end" ]; do
        log_contains "$pattern" && return 0
        sleep 0.2
    done
    return 1
}

# ── sipp wrappers ───────────────────────────────────────────────
sipp_send() {
    # sipp_send <scenario.xml> [-key vXXX]...  ->  exit code
    local scenario=$1; shift
    sipp -sf "$scenario" -m 1 -r 1 -i 127.0.0.1 -p 5071 \
        -timeout 10s -nostdin "$@" \
        "${SIP_HOST}:${SIP_PORT}" \
        > "$WORKDIR/sipp_$(basename "$scenario" .xml).out" 2>&1
}

# ── nats subscriber (one-shot, count=1) ─────────────────────────
nats_sub_oneshot() {
    # nats_sub_oneshot <subject> <out-file>  -> background pid
    n sub "$1" --count=1 > "$2" 2>&1 &
    echo $!
}

# ── consumer bind helper ────────────────────────────────────────
bind_consumer() {
    # bind_consumer <id> <stream> <durable> <filter> [extras...]
    local id=$1 stream=$2 dur=$3 filter=$4
    shift 4
    local cfg="id=${id};stream=${stream};durable=${dur};filter=${filter}"
    for kv in "$@"; do
        cfg="${cfg};${kv}"
    done
    mi nats_consumer_bind "$cfg" > /dev/null
}

unbind_consumer() {
    # unbind_consumer <id>
    mi nats_consumer_unbind "$1" > /dev/null
}
