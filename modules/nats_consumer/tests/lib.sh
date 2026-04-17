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
wait_for_log() {
    local timeout="$1"
    local pattern="$2"
    ${COMPOSE} logs --since "${timeout}s" opensips 2>&1 | grep -q "${pattern}"
}

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; exit 1; }
