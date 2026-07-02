# Shared helpers for the cachedb_nats <-> usrloc e2e suite.
# Sourced by run.sh before any test cases.

: "${WORKDIR:?WORKDIR must be set by run.sh}"
: "${NATS_URL:?NATS_URL must be set by run.sh}"
: "${KV_BUCKET:?KV_BUCKET must be set by run.sh}"
: "${SIP_HOST:=127.0.0.1}"
: "${SIP_PORT_A:=5072}"
: "${SIP_PORT_B:=5074}"
: "${MI_PORT_A:=8889}"
: "${MI_PORT_B:=8890}"

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

# ── nats CLI wrapper ────────────────────────────────────────────
n() { nats --server "$NATS_URL" "$@"; }

kv_clear() {
    # Delete + recreate the bucket for a tombstone-free clean slate.
    # opensips workers cache a kvStore handle in lib/nats; the handle is
    # bucket-name-keyed and survives a delete+recreate because libnats
    # transparently re-resolves on the next op (we exercise this in the
    # broker_bounce case so we know it works).
    # kvctl (not the nats CLI) so the recreated bucket keeps the module's
    # shape: history=1 [HREV-1] + AllowMsgTTL via LimitMarkerTTL.
    : "${KVCTL:?run.sh must export KVCTL}"
    "$KVCTL" rm "$NATS_URL" "$KV_BUCKET" >/dev/null 2>&1 || true
    "$KVCTL" mk "$NATS_URL" "$KV_BUCKET" "${KV_HISTORY:-1}" 30 >/dev/null 2>&1 || true
}

kv_get_raw() {
    n kv get "$KV_BUCKET" "$1" --raw 2>/dev/null
}

kv_keys() {
    # LIVE keys only, via a marker-aware libnats (kvctl ls) -- the 0.1.6
    # nats CLI predates delete markers and lists an expired, marker'd key
    # as if it were live.
    "$KVCTL" ls "$NATS_URL" "$KV_BUCKET" 2>/dev/null || true
}

# ── MI over UDP datagram ────────────────────────────────────────
mi_at() {
    # mi_at <port> <method> [param ...]
    local port=$1; shift
    local method=$1; shift
    local params=""
    if [ $# -gt 0 ]; then
        params=',"params":['
        local first=1
        for p in "$@"; do
            [ $first -eq 1 ] || params="${params},"
            first=0
            local esc
            esc=$(printf '%s' "$p" | sed 's/\\/\\\\/g; s/"/\\"/g')
            params="${params}\"${esc}\""
        done
        params="${params}]"
    fi
    local payload="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"${method}\"${params}}"
    printf '%s' "$payload" | timeout 3 nc -u -w 2 127.0.0.1 "$port"
}

mi() { mi_at "$MI_PORT_A" "$@"; }
mi_b() { mi_at "$MI_PORT_B" "$@"; }

# Returns the per-process snapshot of the cdb counters as a flat string
# "cas_retry=N cas_exhausted=N create_doc=N index_miss_kv=N".
mi_cdb_stats() {
    local port=${1:-$MI_PORT_A}
    local raw
    raw=$(mi_at "$port" nats_cdb_stats)
    local cr ce cd im
    cr=$(printf '%s' "$raw" | sed -n 's/.*"cas_retry"[ \t]*:[ \t]*\([0-9]*\).*/\1/p')
    ce=$(printf '%s' "$raw" | sed -n 's/.*"cas_exhausted"[ \t]*:[ \t]*\([0-9]*\).*/\1/p')
    cd=$(printf '%s' "$raw" | sed -n 's/.*"create_doc"[ \t]*:[ \t]*\([0-9]*\).*/\1/p')
    im=$(printf '%s' "$raw" | sed -n 's/.*"index_miss_kv"[ \t]*:[ \t]*\([0-9]*\).*/\1/p')
    printf 'cas_retry=%s cas_exhausted=%s create_doc=%s index_miss_kv=%s' \
        "${cr:-0}" "${ce:-0}" "${cd:-0}" "${im:-0}"
}

# ── usrloc inspection ────────────────────────────────────────────
# In cluster_mode=full-sharing-cachedb, usrloc frees in-memory state
# after flushing to cachedb on every release_urecord; ul_dump therefore
# always returns empty AORs.  The truth lives in the KV bucket, so we
# count the JSON-prefixed keys that cachedb_nats writes per AoR.
kv_aor_count() {
    # grep -c always prints a count (0 included); swallow only the exit
    # status -- an `|| echo 0` here double-printed ("0\n0") on empty.
    kv_keys | grep -c '^json_' || true
}

# Encoded KV key for an AoR: fts_json_prefix ("json_") +
# _kv_encode_key(aor), which encodes '@' as =40 etc.
kv_aor_key() {
    local aor=$1
    local enc
    enc=$(printf '%s' "$aor" | python3 -c '
import sys
s = sys.stdin.read()
out = []
for b in s.encode("utf-8"):
    c = chr(b)
    if c.isalnum() or c in "-_./\\\\":
        out.append(c)
    else:
        out.append("=%02X" % b)
print("".join(out), end="")
' 2>/dev/null)
    if [ -z "$enc" ]; then
        # Fallback to bash-only encoding when python3 is missing.
        enc=$(printf '%s' "$aor" | awk '
        BEGIN { for (i=0;i<256;i++) ord[sprintf("%c",i)]=i }
        {
            for (i=1; i<=length($0); i++) {
                c = substr($0,i,1)
                if (c ~ /[A-Za-z0-9_./\\-]/) printf "%s", c
                else printf "=%02X", ord[c]
            }
        }')
    fi
    printf 'json_%s' "$enc"
}

# Look for a specific AoR's KV doc.  Returns the raw JSON (or empty).
kv_aor_get() {
    n kv get "$KV_BUCKET" "$(kv_aor_key "$1")" --raw 2>/dev/null
}

# Revision count of an AoR's KV key (nats kv history data lines).  The CLI
# renders a box-drawing table, so match the Op column values, not line
# starts.
kv_aor_revisions() {
    n kv history "$KV_BUCKET" "$(kv_aor_key "$1")" 2>/dev/null \
        | grep -cE ' (PUT|DEL|PURGE) ' || true
}

# Poll until the AoR's doc is physically ABSENT from the bucket (Get fails
# AND the key is not listed).  wait_kv_gone <aor> <timeout_s>; rc 0 = gone.
wait_kv_gone() {
    local aor=$1 timeout=$2
    local end=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$end" ]; do
        if [ -z "$(kv_aor_get "$aor")" ] && \
           ! kv_keys | grep -qxF "$(kv_aor_key "$aor")"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# SIP-level visibility probe [HREV-3]: MESSAGE runs lookup("location") in
# the cfg -- 202 = live binding, 404 = none.  Prints "202", "404" or "none".
# Hand-rolled over nc: this host's sipsak segfaults in MESSAGE mode, and the
# raw datagram keeps the probe deterministic (reply arrives on the same
# socket, exactly like the mi_at helper).
probe_binding() {
    local user=$1; local port=${2:-$SIP_PORT_A}
    local tag="$$${RANDOM}"
    local out="$WORKDIR/probe_${user}_${tag}.out"
    printf 'MESSAGE sip:%s@%s:%s SIP/2.0\r\nVia: SIP/2.0/UDP %s:5098;rport;branch=z9hG4bK%s\r\nMax-Forwards: 10\r\nFrom: <sip:probe@%s>;tag=%s\r\nTo: <sip:%s@%s:%s>\r\nCall-ID: probe-%s@%s\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n' \
        "$user" "$SIP_HOST" "$port" \
        "$SIP_HOST" "$tag" \
        "$SIP_HOST" "$tag" \
        "$user" "$SIP_HOST" "$port" \
        "$tag" "$SIP_HOST" \
        | timeout 3 nc -u -w 2 "$SIP_HOST" "$port" > "$out" 2>&1
    if grep -q "SIP/2.0 202" "$out"; then echo 202
    elif grep -q "SIP/2.0 404" "$out"; then echo 404
    else echo none
    fi
}

# [FMT] extract the raw .result.data blob from an MI JSON reply (csv/txt
# formats ride as ONE string field; JSON escaping preserves CR/LF exactly).
mi_data() {
    printf '%s' "$1" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    sys.stdout.write(d.get("result", {}).get("data", ""))
except Exception:
    pass
'
}

# ── log assertions ──────────────────────────────────────────────
log_contains() {
    grep -q -- "$1" "$WORKDIR/opensips.log"
}

wait_for_log() {
    local timeout=$1; local pattern=$2
    local end=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$end" ]; do
        log_contains "$pattern" && return 0
        sleep 0.2
    done
    return 1
}

# ── SIP REGISTER via sipsak ─────────────────────────────────────
register_one() {
    # register_one <user> <expires> [port]  -> sipsak exit code
    # NB: sipsak's Expires flag is -x (default 15).  -e is "ending number of
    # the appendix to the user name" -- the original helper passed the
    # expiry through -e, so every REGISTER silently went out with
    # Expires: 15; invisible until the TTL cases timed actual expiry.
    local user=$1; local expires=${2:-3600}; local port=${3:-$SIP_PORT_A}
    sipsak -U -C "sip:${user}@${SIP_HOST}:${port}" \
        -s "sip:${user}@${SIP_HOST}:${port}" \
        -x "$expires" \
        > "$WORKDIR/sipsak_${user}_${port}.out" 2>&1
}

# Register an ADDITIONAL contact for an AoR: same To/From user, different
# Contact URI (distinct port) -- usrloc keys contacts by their URI, so this
# lands as a second binding on the same row.  Multi-contact rows with
# DIFFERING expiries are the TTL-ineligible path (a min-derived row TTL
# would tombstone the still-live contacts), served by the reaper [REV-6/F6].
register_contact() {
    # register_contact <user> <contact_port> <expires> [sip_port]
    local user=$1; local cport=$2; local expires=$3; local port=${4:-$SIP_PORT_A}
    sipsak -U -C "sip:${user}@${SIP_HOST}:${cport}" \
        -s "sip:${user}@${SIP_HOST}:${port}" \
        -x "$expires" \
        > "$WORKDIR/sipsak_${user}_c${cport}.out" 2>&1
}

# Decoded headers of the CURRENT (last-per-subject) stream message backing
# an AoR's KV row.  Lets a case assert the Nats-TTL header is present
# (TTL-eligible write) or absent (ineligible mixed-expiry write) -- the
# actual on-broker outcome of the _ttl_eligible decision.
kv_last_headers() {
    local subj="\$KV.${KV_BUCKET}.$(kv_aor_key "$1")"
    n req "\$JS.API.STREAM.MSG.GET.KV_${KV_BUCKET}" \
        "{\"last_by_subj\":\"$subj\"}" 2>/dev/null \
        | python3 -c '
import sys, json, base64
try:
    d = json.load(sys.stdin)
    h = d.get("message", {}).get("hdrs", "")
    print(base64.b64decode(h).decode(errors="replace") if h else "")
except Exception:
    print("")
'
}

# Register N users in parallel, blocking until all return.
register_n_parallel() {
    # register_n_parallel <prefix> <count> [port] [start]
    local prefix=$1; local count=$2; local port=${3:-$SIP_PORT_A}; local start=${4:-1}
    local i pids=""
    for i in $(seq "$start" $((start + count - 1))); do
        register_one "${prefix}${i}" 3600 "$port" &
        pids="$pids $!"
    done
    for p in $pids; do wait "$p"; done
}

# Register the same AoR many times concurrently to exercise CAS retry.
register_same_aor_concurrent() {
    # register_same_aor_concurrent <user> <count> [port]
    local user=$1; local count=$2; local port=${3:-$SIP_PORT_A}
    local i pids=""
    for i in $(seq 1 "$count"); do
        register_one "$user" 3600 "$port" &
        pids="$pids $!"
    done
    for p in $pids; do wait "$p"; done
}

# ── opensips lifecycle (run.sh sets OPENSIPS_PID for instance A) ─
opensips_running() {
    local pid=${1:-$OPENSIPS_PID}
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

# ── nats broker lifecycle for broker_bounce test ────────────────
# We never kill the user's broker.  Tests that need a bounce use a
# disposable broker on a different port (BOUNCE_NATS_PORT) controlled
# by run.sh; helpers.sh exposes hooks if BOUNCE_NATS_PID is set.
bounce_broker() {
    : "${BOUNCE_NATS_PID:?bounce broker not configured for this run}"
    : "${BOUNCE_NATS_BIN:=nats-server}"
    : "${BOUNCE_NATS_PORT:=4322}"
    : "${BOUNCE_NATS_JS:=$WORKDIR/jsdir}"
    kill "$BOUNCE_NATS_PID" 2>/dev/null
    wait "$BOUNCE_NATS_PID" 2>/dev/null
    sleep 1
    "$BOUNCE_NATS_BIN" -p "$BOUNCE_NATS_PORT" -js -sd "$BOUNCE_NATS_JS" \
        > "$WORKDIR/bounce_nats.log" 2>&1 &
    BOUNCE_NATS_PID=$!
    for i in $(seq 1 10); do
        nats --server "nats://127.0.0.1:${BOUNCE_NATS_PORT}" \
            server check connection >/dev/null 2>&1 && return 0
        sleep 0.5
    done
    return 1
}
