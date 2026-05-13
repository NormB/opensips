# Shared helpers for the integration test scripts.  Sourced, not run.
#
# The harness talks to two compose services:
#   - nats      : the JetStream broker, exposed locally on 4222.
#   - opensips  : the nats_consumer container, MI FIFO on the `mi`
#                 volume (accessed via the `opensips` service).
#
# Tests assume the compose stack is already up (`docker compose up -d`
# before running, `docker compose down -v` after).  If the stack is
# absent we skip with exit 77 (standard "skip" code for autotools-style
# harnesses; CI can detect it without failing).

COMPOSE_FILE="$(cd "$(dirname "$0")" && pwd)/docker-compose.yaml"
COMPOSE="docker compose -f ${COMPOSE_FILE}"

ensure_stack() {
    if ! docker info >/dev/null 2>&1; then
        echo "docker not available; skipping integration test"
        exit 77
    fi
    if ! ${COMPOSE} ps --format json >/dev/null 2>&1; then
        echo "compose stack not up; skipping integration test"
        echo "  run: (cd $(dirname ${COMPOSE_FILE}) && docker compose up -d)"
        exit 77
    fi
}

# Restart the opensips container and wait for the MI FIFO to come back.
# Use before stress tests that need a clean handle registry: the worker
# tick retries failed js_PullSubscribe / js_AddConsumer indefinitely
# for handles whose broker-side consumers have been deleted by earlier
# tests, and that retry storm crowds out fresh binds for tens of
# seconds even on an otherwise idle broker.
restart_opensips_clean() {
    ${COMPOSE} restart opensips >/dev/null 2>&1
    local deadline=$(( $(date +%s) + 15 ))
    while [ "$(date +%s)" -lt "${deadline}" ]; do
        if ${COMPOSE} exec -T opensips test -p /var/run/opensips/mi.fifo \
                >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    echo "WARN: opensips MI FIFO not ready 15s after restart" >&2
    return 1
}

# Run a nats CLI command in the natscli helper container.
ncli() {
    ${COMPOSE} exec -T natscli nats --server nats://nats:4222 "$@"
}

# Run an MI command against the opensips container's FIFO.
mi() {
    ${COMPOSE} exec -T opensips opensips-mi "$@" 2>/dev/null || \
        ${COMPOSE} exec -T opensips \
            sh -c "echo ':$*:\n\n' > /var/run/opensips/mi.fifo"
}

# Send a JSON-RPC MI request over /var/run/opensips/mi.fifo and capture the
# reply on stdout. Args: <method> [<params_json>]
#
# Opensips' mi_fifo expects:   ":<reply_pipe>:<jsonrpc>" on a single line
# where <reply_pipe> is a named pipe under /tmp (the reply_dir default).
mi_send() {
    local method="$1"
    local params="${2:-}"
    local body
    if [ -n "${params}" ]; then
        body=$(printf '{"jsonrpc":"2.0","id":1,"method":"%s","params":%s}' \
            "${method}" "${params}")
    else
        body=$(printf '{"jsonrpc":"2.0","id":1,"method":"%s"}' "${method}")
    fi
    local rid="r$$_$RANDOM"
    # Pass rid + body via env so JSON quotes don't fight shell quoting.
    ${COMPOSE} exec -T -e RID="${rid}" -e BODY="${body}" opensips sh -c '
        rm -f /tmp/$RID /tmp/$RID.out
        mkfifo /tmp/$RID
        ( timeout 5 cat /tmp/$RID > /tmp/$RID.out ) &
        rdr=$!
        printf ":%s:%s\n" "$RID" "$BODY" > /var/run/opensips/mi.fifo
        wait $rdr 2>/dev/null
        cat /tmp/$RID.out 2>/dev/null
        rm -f /tmp/$RID /tmp/$RID.out
    '
}

# Bind a nats_consumer handle. Args: <id> <stream> <kv-pairs...>
# kv-pair examples:  durable=foo  ephemeral=1  filter=sub.>
#                    ack_wait=30s  max_deliver=3  max_ack_pending=512
#                    inactive_threshold=3s  filters=a,b
#
# The MI command nats_consumer_bind takes a single "config" string in the
# legacy semicolon-separated form: id=...;stream=...;durable=...;...
nats_bind() {
    local id="$1"; local stream="$2"; shift 2
    local cfg="id=${id};stream=${stream}"
    local kv
    for kv in "$@"; do
        cfg="${cfg};${kv}"
    done
    mi_send nats_consumer:nats_consumer_bind "{\"config\":\"${cfg}\"}"
}

# Unbind a handle by id.
nats_unbind() {
    mi_send nats_consumer:nats_consumer_unbind "{\"id\":\"$1\"}"
}

# List all consumer handles. Returns raw JSON-RPC envelope on stdout.
# Fully qualified name to disambiguate from event_nats:nats_consumer_list.
nats_list() {
    mi_send nats_consumer:nats_consumer_list
}

# Extract a field from a single handle entry in a nats_consumer_list reply.
# Args: <list_json_envelope> <handle_id> <field>
nats_list_field() {
    local env_json="$1"; local hid="$2"; local field="$3"
    python3 - "$env_json" "$hid" "$field" <<'PY'
import json,sys
env_json, hid, field = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    env=json.loads(env_json)
except Exception:
    sys.exit(0)
res=env.get('result', env_json)
handles = res.get('handles', []) if isinstance(res, dict) else []
if not handles and isinstance(res, list):
    handles = res
for h in handles:
    if h.get('id')==hid:
        v = h.get(field, '')
        print(v if v is not None else '')
        break
PY
}

# Ensure a stream exists (idempotent -- ignore "already exists" errors).
ensure_stream() {
    local name="$1"
    local subjects="$2"
    ncli stream add "${name}" --subjects "${subjects}" \
        --storage memory --defaults >/dev/null 2>&1 || true
}

# Publish a single message on a subject.
publish() {
    local subject="$1"
    local payload="$2"
    ncli publish "${subject}" "${payload}"
}

# Tail the opensips container's stdout for up to $1 seconds and grep
# for $2.  Returns 0 when the pattern matches, non-zero on timeout.
#
# Uses grep -c (not grep -q): grep -q exits early and SIGPIPEs the upstream
# `docker compose logs`, which under `set -o pipefail` leaks the signal exit
# and makes a successful match look like a miss.
wait_for_log() {
    local timeout="$1"
    local pattern="$2"
    local deadline=$(( $(date +%s) + timeout ))
    local n
    while [ "$(date +%s)" -lt "$deadline" ]; do
        n=$(${COMPOSE} logs --since "${timeout}s" opensips 2>&1 \
                | grep -c "${pattern}" || true)
        [ "${n:-0}" -gt 0 ] && return 0
        sleep 0.3
    done
    return 1
}

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; exit 1; }
