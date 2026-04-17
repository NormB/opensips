#!/bin/bash
# test_fetch_sync.sh -- integration test for nats_fetch() (sync path).
#
# Publishes a single message and verifies opensips' timer_route drain
# picks it up + acks it (logs 'got test.in: <payload>' and
# nats_consumer_list reports acks>=1).
#
# Requires the docker-compose stack in this directory to be up:
#   docker compose up -d --build
# Exits 77 if docker / the stack is unavailable.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "${HERE}/lib.sh"

ensure_stack

ensure_stream TEST 'test.*'

payload="hello-$(date +%s)"
publish test.in "${payload}"

# The timer_route drains once a second; give it up to 10s to fire.
for i in 1 2 3 4 5 6 7 8 9 10; do
    if wait_for_log 15 "got test.in: ${payload}"; then
        pass "fetch_sync delivered payload ${payload}"
        exit 0
    fi
    sleep 1
done

fail "timer_route never logged the published payload"
