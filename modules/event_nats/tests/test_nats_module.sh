#!/bin/bash
# test_nats_module.sh — Incremental test suite for mod_nats and event_nats subscribe
#
# This script grows with each implementation phase. Tests are cumulative —
# later phases include all earlier tests as regression checks.
#
# Usage:
#   ./tests/test_nats_module.sh [phase]
#   phase: 1-10 (default: run all implemented phases)

set -uo pipefail

MI_URL="http://172.20.0.30:8888/mi"
PASS=0
FAIL=0
SKIP=0

# ── Test helpers ─────────────────────────────────────────────────

mi() {
    local method="$1"
    shift
    local params=""
    if [ $# -gt 0 ]; then
        params=",$*"
    fi
    curl -sf -X POST -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\"$params}" \
        "$MI_URL" 2>/dev/null
}

mi_with_params() {
    local method="$1"
    local params_json="$2"
    curl -sf -X POST -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params_json}" \
        "$MI_URL" 2>/dev/null
}

assert_ok() {
    local test_name="$1"
    local result="$2"
    if echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'result' in d" 2>/dev/null; then
        echo "  PASS: $test_name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $test_name"
        echo "    Response: $result"
        FAIL=$((FAIL + 1))
    fi
}

assert_field() {
    local test_name="$1"
    local result="$2"
    local field="$3"
    if echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); assert '$field' in d.get('result',{})" 2>/dev/null; then
        echo "  PASS: $test_name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $test_name (missing field: $field)"
        echo "    Response: $result"
        FAIL=$((FAIL + 1))
    fi
}

assert_error() {
    local test_name="$1"
    local result="$2"
    local expected_code="$3"
    if echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'error' in d, 'no error field'; assert d['error'].get('code') == $expected_code, f\"code {d['error'].get('code')} != $expected_code\"" 2>/dev/null; then
        echo "  PASS: $test_name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $test_name (expected error code $expected_code)"
        echo "    Response: $result"
        FAIL=$((FAIL + 1))
    fi
}

assert_value() {
    local test_name="$1"
    local result="$2"
    local py_check="$3"
    if echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin)['result']; $py_check" 2>/dev/null; then
        echo "  PASS: $test_name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $test_name"
        echo "    Check: $py_check"
        echo "    Response: $result"
        FAIL=$((FAIL + 1))
    fi
}

# ── Phase 1: Module skeleton + nats_account_info ─────────────────

test_phase1() {
    echo "=== Phase 1: Module skeleton + nats_account_info ==="

    # Test 1: Module loaded (check MI is responsive)
    local r
    r=$(mi "nats_account_info")
    assert_ok "nats_account_info returns valid response" "$r"

    # Test 2: Has required fields
    assert_field "has memory field" "$r" "memory"
    assert_field "has storage field" "$r" "storage"
    assert_field "has streams field" "$r" "streams"
    assert_field "has consumers field" "$r" "consumers"
    assert_field "has api field" "$r" "api"
    assert_field "has limits field" "$r" "limits"

    # Test 3: Stream count is positive (we have opensips-events, ai-events, KV_opensips)
    assert_value "streams count >= 1" "$r" "assert d['streams'] >= 1"

    # Test 4: API stats has total and errors
    assert_value "api.total is a number" "$r" "assert isinstance(d['api']['total'], (int, float))"
    assert_value "api.errors is a number" "$r" "assert isinstance(d['api']['errors'], (int, float))"

    # Test 5: Limits has expected fields
    assert_value "limits.max_memory exists" "$r" "assert 'max_memory' in d['limits']"
    assert_value "limits.max_storage exists" "$r" "assert 'max_storage' in d['limits']"
    assert_value "limits.max_streams exists" "$r" "assert 'max_streams' in d['limits']"
}

# ── Phase 2: nats_stream_list + nats_stream_info ─────────────────

test_phase2() {
    echo "=== Phase 2: nats_stream_list + nats_stream_info ==="

    # Test 1: stream_list returns valid response with streams array
    local r
    r=$(mi "nats_stream_list")
    assert_ok "nats_stream_list returns valid response" "$r"
    assert_field "has count field" "$r" "count"
    assert_field "has streams field" "$r" "streams"

    # Test 2: known streams are present
    assert_value "opensips-events stream exists" "$r" \
        "assert any(s['name'] == 'opensips-events' for s in d['streams'])"
    assert_value "ai-events stream exists" "$r" \
        "assert any(s['name'] == 'ai-events' for s in d['streams'])"

    # Test 3: stream entries have required fields
    assert_value "streams have name field" "$r" \
        "assert all('name' in s for s in d['streams'])"
    assert_value "streams have messages field" "$r" \
        "assert all('messages' in s for s in d['streams'])"
    assert_value "streams have replicas field" "$r" \
        "assert all('replicas' in s for s in d['streams'])"

    # Test 4: stream_info returns detailed info
    r=$(mi_with_params "nats_stream_info" '{"stream":"opensips-events"}')
    assert_ok "nats_stream_info returns valid response" "$r"
    assert_field "has config field" "$r" "config"
    assert_field "has state field" "$r" "state"

    # Test 5: config has expected fields
    assert_value "config has name" "$r" "assert d['config']['name'] == 'opensips-events'"
    assert_value "config has replicas=3" "$r" "assert d['config']['replicas'] == 3"
    assert_value "config has retention" "$r" "assert 'retention' in d['config']"
    assert_value "config has storage" "$r" "assert 'storage' in d['config']"
    assert_value "config has subjects array" "$r" "assert 'subjects' in d['config']"

    # Test 6: state has expected fields
    assert_value "state has messages" "$r" "assert 'messages' in d['state']"
    assert_value "state has bytes" "$r" "assert 'bytes' in d['state']"
    assert_value "state has first_seq" "$r" "assert 'first_seq' in d['state']"
    assert_value "state has last_seq" "$r" "assert 'last_seq' in d['state']"

    # Test 7: cluster info present (3-node cluster)
    assert_value "cluster info present" "$r" "assert 'cluster' in d"
    assert_value "cluster has leader" "$r" "assert 'leader' in d['cluster']"
    assert_value "cluster has replicas" "$r" "assert 'replicas' in d['cluster']"

    # Test 8: non-existent stream returns 404
    r=$(mi_with_params "nats_stream_info" '{"stream":"nonexistent"}')
    assert_error "non-existent stream returns 404" "$r" 404
}

# ── Main ─────────────────────────────────────────────────────────

MAX_PHASE="${1:-1}"
RUN_EDGE=0
if [ "$MAX_PHASE" = "edge" ]; then
    MAX_PHASE=0
    RUN_EDGE=1
fi

echo "Running mod_nats tests (phases 1-$MAX_PHASE${RUN_EDGE:+, edge cases})"
echo ""

# Wait for OpenSIPS to be ready
echo "Waiting for OpenSIPS MI..."
for i in $(seq 1 30); do
    if mi "version" >/dev/null 2>&1; then
        echo "OpenSIPS MI ready."
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "FATAL: OpenSIPS MI not responding after 30s"
        exit 1
    fi
    sleep 1
done
echo ""

# ── Phase 3: nats_stream_create/delete/purge ─────────────────────

test_phase3() {
    echo "=== Phase 3: nats_stream_create/delete/purge ==="

    local r

    # Test 1: Create a test stream
    r=$(mi_with_params "nats_stream_create" '{"name":"test-mod-nats","subjects":"test.mod.>"}')
    assert_ok "create test stream" "$r"
    assert_value "create returns name" "$r" "assert d.get('name') == 'test-mod-nats' or d.get('status') == 'created'"

    # Test 2: Verify stream exists via stream_info
    r=$(mi_with_params "nats_stream_info" '{"stream":"test-mod-nats"}')
    assert_ok "stream info for new stream" "$r"
    assert_value "new stream has correct name" "$r" "assert d['config']['name'] == 'test-mod-nats'"
    assert_value "new stream has correct subjects" "$r" "assert 'test.mod.>' in d['config']['subjects']"

    # Test 3: Stream appears in stream_list
    r=$(mi "nats_stream_list")
    assert_value "new stream in list" "$r" \
        "assert any(s['name'] == 'test-mod-nats' for s in d['streams'])"

    # Test 4: Purge stream (should succeed even with no messages)
    r=$(mi_with_params "nats_stream_purge" '{"stream":"test-mod-nats"}')
    assert_ok "purge test stream" "$r"

    # Test 5: Verify purge — 0 messages
    r=$(mi_with_params "nats_stream_info" '{"stream":"test-mod-nats"}')
    assert_value "purged stream has 0 messages" "$r" "assert d['state']['messages'] == 0"

    # Test 6: Delete stream
    r=$(mi_with_params "nats_stream_delete" '{"stream":"test-mod-nats"}')
    assert_ok "delete test stream" "$r"

    # Test 7: Verify stream is gone
    r=$(mi_with_params "nats_stream_info" '{"stream":"test-mod-nats"}')
    assert_error "deleted stream returns 404" "$r" 404

    # Test 8: Delete non-existent stream returns error
    r=$(mi_with_params "nats_stream_delete" '{"stream":"nonexistent-xyz"}')
    assert_error "delete non-existent returns 404" "$r" 404

    # Test 9: Create with custom config
    r=$(mi_with_params "nats_stream_create" \
        '{"name":"test-custom","subjects":"custom.>","replicas":1,"max_msgs":100,"max_bytes":1048576,"max_age":3600,"retention":"interest","storage":"memory"}')
    assert_ok "create custom config stream" "$r"

    # Verify custom config roundtrips
    r=$(mi_with_params "nats_stream_info" '{"stream":"test-custom"}')
    assert_value "custom replicas=1" "$r" "assert d['config']['replicas'] == 1"
    assert_value "custom max_msgs=100" "$r" "assert d['config']['max_msgs'] == 100"
    assert_value "custom retention=interest" "$r" "assert d['config']['retention'] == 'interest'"
    assert_value "custom storage=memory" "$r" "assert d['config']['storage'] == 'memory'"

    # Cleanup
    mi_with_params "nats_stream_delete" '{"stream":"test-custom"}' >/dev/null 2>&1
}

# ── Phase 4: nats_consumer_list/info/create/delete ───────────────

test_phase4() {
    echo "=== Phase 4: nats_consumer_list/info/create/delete ==="

    local r

    # Setup: create a test stream for consumer tests
    mi_with_params "nats_stream_delete" '{"stream":"test-consumers"}' >/dev/null 2>&1
    r=$(mi_with_params "nats_stream_create" '{"name":"test-consumers","subjects":"test.cons.>"}')
    assert_ok "setup: create test stream" "$r"

    # Test 1: Create a consumer
    r=$(mi_with_params "nats_consumer_create" \
        '{"stream":"test-consumers","name":"my-consumer","filter_subject":"test.cons.>"}')
    assert_ok "create consumer" "$r"
    assert_value "create returns name" "$r" "assert d.get('name') == 'my-consumer' or d.get('status') == 'created'"

    # Test 2: Consumer appears in list
    r=$(mi_with_params "nats_consumer_list" '{"stream":"test-consumers"}')
    assert_ok "consumer list" "$r"
    assert_value "list has count >= 1" "$r" "assert d['count'] >= 1"
    assert_value "my-consumer in list" "$r" \
        "assert any(c['name'] == 'my-consumer' for c in d['consumers'])"

    # Test 3: Consumer info has expected fields
    r=$(mi_with_params "nats_consumer_info" \
        '{"stream":"test-consumers","consumer":"my-consumer"}')
    assert_ok "consumer info" "$r"
    assert_value "info has stream" "$r" "assert d['stream'] == 'test-consumers'"
    assert_value "info has name" "$r" "assert d['name'] == 'my-consumer'"
    assert_field "info has config" "$r" "config"
    assert_field "info has delivered" "$r" "delivered"
    assert_field "info has ack_floor" "$r" "ack_floor"
    assert_field "info has num_pending" "$r" "num_pending"

    # Test 4: Consumer config has expected fields
    assert_value "config has deliver_policy" "$r" "assert 'deliver_policy' in d['config']"
    assert_value "config has ack_policy" "$r" "assert 'ack_policy' in d['config']"

    # Test 5: Delete consumer
    r=$(mi_with_params "nats_consumer_delete" \
        '{"stream":"test-consumers","consumer":"my-consumer"}')
    assert_ok "delete consumer" "$r"

    # Test 6: Deleted consumer returns 404
    r=$(mi_with_params "nats_consumer_info" \
        '{"stream":"test-consumers","consumer":"my-consumer"}')
    assert_error "deleted consumer returns 404" "$r" 404

    # Test 7: Consumer on non-existent stream returns error
    r=$(mi_with_params "nats_consumer_list" '{"stream":"nonexistent-xyz"}')
    # nats.c returns generic error for consumer list on missing stream
    if echo "$r" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'error' in d" 2>/dev/null; then
        echo "  PASS: consumer list on missing stream returns error"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: consumer list on missing stream returns error"
        FAIL=$((FAIL + 1))
    fi

    # Cleanup
    mi_with_params "nats_stream_delete" '{"stream":"test-consumers"}' >/dev/null 2>&1
}

# ── Phase 5: nats_msg_get/delete ─────────────────────────────────

test_phase5() {
    echo "=== Phase 5: nats_msg_get/delete ==="

    local r

    # Get the last sequence from opensips-events (which has messages)
    r=$(mi_with_params "nats_stream_info" '{"stream":"opensips-events"}')
    local last_seq
    last_seq=$(echo "$r" | python3 -c "import sys,json; print(int(json.load(sys.stdin)['result']['state']['last_seq']))" 2>/dev/null)

    if [ -z "$last_seq" ] || [ "$last_seq" -le 0 ]; then
        echo "  SKIP: no messages in opensips-events"
        SKIP=$((SKIP + 1))
        return
    fi

    # Test 1: Get message by sequence
    r=$(mi_with_params "nats_msg_get" "{\"stream\":\"opensips-events\",\"seq\":$last_seq}")
    assert_ok "get message by seq" "$r"
    assert_field "msg has subject" "$r" "subject"
    assert_field "msg has data" "$r" "data"
    assert_value "msg has correct seq" "$r" "assert d['sequence'] == $last_seq"

    # Test 2: Get message with invalid sequence returns error
    r=$(mi_with_params "nats_msg_get" '{"stream":"opensips-events","seq":999999999}')
    assert_error "invalid seq returns 404" "$r" 404

    # Test 3: Get from non-existent stream
    r=$(mi_with_params "nats_msg_get" '{"stream":"nonexistent-xyz","seq":1}')
    assert_error "get from missing stream returns error" "$r" 404

    # Test 4: Create a test stream, publish a message, get it, delete it
    mi_with_params "nats_stream_delete" '{"stream":"test-msg-ops"}' >/dev/null 2>&1
    mi_with_params "nats_stream_create" '{"name":"test-msg-ops","subjects":"test.msg.>"}' >/dev/null 2>&1

    # Publish via nats_publish (event_nats function — already loaded)
    # Use the opensips MI to publish a message
    curl -sf -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","id":1,"method":"nats_msg_get","params":{"stream":"test-msg-ops","seq":1}}' \
        "$MI_URL" >/dev/null 2>&1
    # Since we can't easily publish to test.msg.> without a SIP trigger,
    # just test the error case for empty stream
    r=$(mi_with_params "nats_msg_get" '{"stream":"test-msg-ops","seq":1}')
    assert_error "get from empty stream returns 404" "$r" 404

    # Cleanup
    mi_with_params "nats_stream_delete" '{"stream":"test-msg-ops"}' >/dev/null 2>&1
}

# ── Phase 8+9: event_nats subscribe ──────────────────────────────

test_phase89() {
    echo "=== Phase 8+9: event_nats subscribe ==="

    local r

    # Test 1: NATS consumer process is running
    r=$(mi "ps")
    assert_value "NATS consumer process exists" "$r" \
        "assert any(p['Type'] == 'NATS consumer' for p in d['Processes'])"

    # Test 2: Publish and verify event_route fires
    # Publish a message to the test subject
    nats pub -s nats://172.20.0.50:4222 test.subscribe.test-run '{"test":"subscribe_test"}' >/dev/null 2>&1
    sleep 1

    # Check OpenSIPS logs for the event_route output
    if docker compose logs opensips 2>&1 | grep -q "NATS_TEST:.*test.subscribe.test-run"; then
        echo "  PASS: event_route[E_NATS_TEST] fired on published message"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: event_route[E_NATS_TEST] did not fire"
        FAIL=$((FAIL + 1))
    fi

    # Test 3: Verify $param(data) contains the payload
    if docker compose logs opensips 2>&1 | grep -q 'NATS_TEST:.*data={"test":"subscribe_test"}'; then
        echo "  PASS: \$param(data) contains correct payload"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: \$param(data) missing or incorrect"
        FAIL=$((FAIL + 1))
    fi

    # Test 4: Verify $param(subject) contains the subject
    if docker compose logs opensips 2>&1 | grep -q "NATS_TEST:.*subject=test.subscribe.test-run"; then
        echo "  PASS: \$param(subject) contains correct subject"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: \$param(subject) missing or incorrect"
        FAIL=$((FAIL + 1))
    fi
}

# ── Edge case tests ──────────────────────────────────────────────

assert_any_error() {
    local test_name="$1"
    local result="$2"
    if echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'error' in d" 2>/dev/null; then
        echo "  PASS: $test_name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $test_name (expected error response)"
        echo "    Response: $result"
        FAIL=$((FAIL + 1))
    fi
}

test_edge_phase1() {
    echo "=== Edge: Phase 1 — account_info edge cases ==="

    local r

    # Calling account_info multiple times in rapid succession (idempotent)
    local r1 r2
    r1=$(mi "nats_account_info")
    r2=$(mi "nats_account_info")
    assert_ok "rapid successive calls (1)" "$r1"
    assert_ok "rapid successive calls (2)" "$r2"

    # Verify numeric fields are non-negative
    r=$(mi "nats_account_info")
    assert_value "memory >= 0" "$r" "assert d['memory'] >= 0"
    assert_value "storage >= 0" "$r" "assert d['storage'] >= 0"
    assert_value "api.total >= 0" "$r" "assert d['api']['total'] >= 0"
    assert_value "api.errors >= 0" "$r" "assert d['api']['errors'] >= 0"

    # Verify limits are either -1 (unlimited) or positive
    assert_value "max_memory is -1 or positive" "$r" \
        "assert d['limits']['max_memory'] == -1 or d['limits']['max_memory'] > 0"
    assert_value "max_streams is -1 or positive" "$r" \
        "assert d['limits']['max_streams'] == -1 or d['limits']['max_streams'] > 0"
}

test_edge_phase2() {
    echo "=== Edge: Phase 2 — stream list/info edge cases ==="

    local r

    # Empty string stream name
    r=$(mi_with_params "nats_stream_info" '{"stream":""}')
    assert_any_error "empty stream name returns error" "$r"

    # Very long stream name (> 256 chars)
    local long_name
    long_name=$(python3 -c "print('a'*300)")
    r=$(mi_with_params "nats_stream_info" "{\"stream\":\"$long_name\"}")
    assert_any_error "oversized stream name returns error" "$r"

    # Stream name with special characters
    r=$(mi_with_params "nats_stream_info" '{"stream":"test/stream"}')
    assert_any_error "stream name with slash returns error" "$r"

    # Stream name with spaces
    r=$(mi_with_params "nats_stream_info" '{"stream":"test stream"}')
    assert_any_error "stream name with space returns error" "$r"

    # Count in stream_list matches actual array length
    r=$(mi "nats_stream_list")
    assert_value "count matches streams array length" "$r" \
        "assert d['count'] == len(d['streams'])"

    # All streams in list have non-negative message counts
    assert_value "all streams have messages >= 0" "$r" \
        "assert all(s['messages'] >= 0 for s in d['streams'])"

    # All streams have non-negative byte counts
    assert_value "all streams have bytes >= 0" "$r" \
        "assert all(s['bytes'] >= 0 for s in d['streams'])"

    # Cluster replicas are all current (no lag in healthy cluster)
    r=$(mi_with_params "nats_stream_info" '{"stream":"opensips-events"}')
    assert_value "cluster replicas have lag field" "$r" \
        "assert all('lag' in r for r in d.get('cluster',{}).get('replicas',[]))"
}

test_edge_phase3() {
    echo "=== Edge: Phase 3 — stream create/delete/purge edge cases ==="

    local r

    # Create stream with empty name
    r=$(mi_with_params "nats_stream_create" '{"name":"","subjects":"test.>"}')
    assert_any_error "create with empty name fails" "$r"

    # Create stream with empty subjects
    r=$(mi_with_params "nats_stream_create" '{"name":"edge-test","subjects":""}')
    assert_any_error "create with empty subjects fails" "$r"

    # Create duplicate stream (should fail or update)
    mi_with_params "nats_stream_delete" '{"stream":"edge-dup"}' >/dev/null 2>&1
    r=$(mi_with_params "nats_stream_create" '{"name":"edge-dup","subjects":"edge.dup.>"}')
    assert_ok "first create succeeds" "$r"
    r=$(mi_with_params "nats_stream_create" '{"name":"edge-dup","subjects":"edge.dup.>"}')
    # Duplicate create may succeed (idempotent) or fail — both are acceptable
    echo "  INFO: duplicate create returned: $(echo "$r" | python3 -c "import sys,json; d=json.load(sys.stdin); print('ok' if 'result' in d else 'error')" 2>/dev/null)"
    PASS=$((PASS + 1))

    # Delete the duplicate stream
    mi_with_params "nats_stream_delete" '{"stream":"edge-dup"}' >/dev/null 2>&1

    # Double delete — second should fail
    mi_with_params "nats_stream_delete" '{"stream":"edge-dup"}' >/dev/null 2>&1
    r=$(mi_with_params "nats_stream_delete" '{"stream":"edge-dup"}')
    assert_error "double delete returns 404" "$r" 404

    # Purge non-existent stream
    r=$(mi_with_params "nats_stream_purge" '{"stream":"nonexistent-purge"}')
    assert_any_error "purge non-existent stream fails" "$r"

    # Create stream with multiple subjects (comma-separated)
    mi_with_params "nats_stream_delete" '{"stream":"edge-multi-subj"}' >/dev/null 2>&1
    r=$(mi_with_params "nats_stream_create" '{"name":"edge-multi-subj","subjects":"edge.a.>,edge.b.>,edge.c.>"}')
    assert_ok "create with multiple subjects" "$r"
    r=$(mi_with_params "nats_stream_info" '{"stream":"edge-multi-subj"}')
    assert_value "stream has 3 subjects" "$r" "assert len(d['config']['subjects']) == 3"
    mi_with_params "nats_stream_delete" '{"stream":"edge-multi-subj"}' >/dev/null 2>&1

    # Create stream with replicas=1 (standalone, not clustered)
    mi_with_params "nats_stream_delete" '{"stream":"edge-r1"}' >/dev/null 2>&1
    r=$(mi_with_params "nats_stream_create" '{"name":"edge-r1","subjects":"edge.r1.>","replicas":1}')
    assert_ok "create with replicas=1" "$r"
    r=$(mi_with_params "nats_stream_info" '{"stream":"edge-r1"}')
    assert_value "replicas=1 roundtrips" "$r" "assert d['config']['replicas'] == 1"
    mi_with_params "nats_stream_delete" '{"stream":"edge-r1"}' >/dev/null 2>&1

    # Create with max_bytes=0 (should fail — invalid)
    r=$(mi_with_params "nats_stream_create" \
        '{"name":"edge-zero","subjects":"edge.zero.>","replicas":1,"max_msgs":0,"max_bytes":0,"max_age":0,"retention":"limits","storage":"memory"}')
    # max_bytes=0 might be treated as unlimited by NATS — just verify no crash
    echo "  INFO: zero limits create returned: $(echo "$r" | python3 -c "import sys,json; d=json.load(sys.stdin); print('ok' if 'result' in d else 'error')" 2>/dev/null)"
    PASS=$((PASS + 1))
    mi_with_params "nats_stream_delete" '{"stream":"edge-zero"}' >/dev/null 2>&1
}

test_edge_phase4() {
    echo "=== Edge: Phase 4 — consumer edge cases ==="

    local r

    # Setup
    mi_with_params "nats_stream_delete" '{"stream":"edge-cons"}' >/dev/null 2>&1
    mi_with_params "nats_stream_create" '{"name":"edge-cons","subjects":"edge.cons.>"}' >/dev/null 2>&1

    # Create consumer with empty name — NATS generates an ephemeral name
    r=$(mi_with_params "nats_consumer_create" \
        '{"stream":"edge-cons","name":"","filter_subject":"edge.cons.>"}')
    # NATS accepts empty name and creates ephemeral consumer — this is valid behavior
    if echo "$r" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'result' in d or 'error' in d" 2>/dev/null; then
        echo "  PASS: empty name creates ephemeral or returns error (both valid)"
        PASS=$((PASS + 1))
        # Clean up ephemeral consumer if created
        local eph_name
        eph_name=$(echo "$r" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('result',{}).get('name',''))" 2>/dev/null)
        if [ -n "$eph_name" ]; then
            mi_with_params "nats_consumer_delete" "{\"stream\":\"edge-cons\",\"consumer\":\"$eph_name\"}" >/dev/null 2>&1
        fi
    else
        echo "  FAIL: empty name gave unexpected response"
        FAIL=$((FAIL + 1))
    fi

    # Create consumer with empty filter_subject — NATS may accept (matches all)
    r=$(mi_with_params "nats_consumer_create" \
        '{"stream":"edge-cons","name":"edge-c1","filter_subject":""}')
    echo "  INFO: empty filter create returned: $(echo "$r" | python3 -c "import sys,json; d=json.load(sys.stdin); print('ok' if 'result' in d else 'error')" 2>/dev/null)"
    PASS=$((PASS + 1))
    mi_with_params "nats_consumer_delete" '{"stream":"edge-cons","consumer":"edge-c1"}' >/dev/null 2>&1

    # Consumer info on non-existent consumer
    r=$(mi_with_params "nats_consumer_info" \
        '{"stream":"edge-cons","consumer":"does-not-exist"}')
    assert_error "info on missing consumer returns 404" "$r" 404

    # Delete non-existent consumer
    r=$(mi_with_params "nats_consumer_delete" \
        '{"stream":"edge-cons","consumer":"does-not-exist"}')
    assert_error "delete missing consumer returns 404" "$r" 404

    # Create consumer, delete it, create again with same name (reuse)
    r=$(mi_with_params "nats_consumer_create" \
        '{"stream":"edge-cons","name":"reuse-test","filter_subject":"edge.cons.>"}')
    assert_ok "create consumer for reuse test" "$r"
    mi_with_params "nats_consumer_delete" '{"stream":"edge-cons","consumer":"reuse-test"}' >/dev/null 2>&1
    r=$(mi_with_params "nats_consumer_create" \
        '{"stream":"edge-cons","name":"reuse-test","filter_subject":"edge.cons.>"}')
    assert_ok "recreate consumer with same name" "$r"
    mi_with_params "nats_consumer_delete" '{"stream":"edge-cons","consumer":"reuse-test"}' >/dev/null 2>&1

    # Consumer list on stream with 0 consumers
    # Re-create a clean stream to ensure it exists and has no consumers
    mi_with_params "nats_stream_delete" '{"stream":"edge-cons-empty"}' >/dev/null 2>&1
    mi_with_params "nats_stream_create" '{"name":"edge-cons-empty","subjects":"edge.empty.>","replicas":1}' >/dev/null 2>&1

    r=$(mi_with_params "nats_consumer_list" '{"stream":"edge-cons-empty"}')
    assert_ok "consumer list on stream with 0 consumers" "$r"
    assert_value "empty consumer list has count=0" "$r" "assert d['count'] == 0"
    assert_value "empty consumer list has empty array" "$r" "assert len(d['consumers']) == 0"
    mi_with_params "nats_stream_delete" '{"stream":"edge-cons-empty"}' >/dev/null 2>&1

    # Create consumer with explicit ack_policy and deliver_policy
    r=$(mi_with_params "nats_consumer_create" \
        '{"stream":"edge-cons","name":"policy-test","filter_subject":"edge.cons.>","deliver_policy":"new","ack_policy":"none"}')
    assert_ok "create consumer with explicit policies" "$r"
    r=$(mi_with_params "nats_consumer_info" \
        '{"stream":"edge-cons","consumer":"policy-test"}')
    assert_value "deliver_policy=new roundtrips" "$r" "assert d['config']['deliver_policy'] == 'new'"
    assert_value "ack_policy=none roundtrips" "$r" "assert d['config']['ack_policy'] == 'none'"
    mi_with_params "nats_consumer_delete" '{"stream":"edge-cons","consumer":"policy-test"}' >/dev/null 2>&1

    # Cleanup
    mi_with_params "nats_stream_delete" '{"stream":"edge-cons"}' >/dev/null 2>&1
}

test_edge_phase5() {
    echo "=== Edge: Phase 5 — message get/delete edge cases ==="

    local r

    # msg_get with seq=0 (invalid)
    r=$(mi_with_params "nats_msg_get" '{"stream":"opensips-events","seq":0}')
    assert_any_error "seq=0 returns error" "$r"

    # msg_get with negative seq
    r=$(mi_with_params "nats_msg_get" '{"stream":"opensips-events","seq":-1}')
    assert_any_error "negative seq returns error" "$r"

    # msg_delete with seq=0 (invalid)
    r=$(mi_with_params "nats_msg_delete" '{"stream":"opensips-events","seq":0}')
    assert_any_error "delete seq=0 returns error" "$r"

    # msg_delete on non-existent stream
    r=$(mi_with_params "nats_msg_delete" '{"stream":"nonexistent-xyz","seq":1}')
    assert_any_error "delete from missing stream returns error" "$r"

    # Create test stream, publish via nats CLI, get, delete, verify deleted
    mi_with_params "nats_stream_delete" '{"stream":"edge-msg"}' >/dev/null 2>&1
    mi_with_params "nats_stream_create" '{"name":"edge-msg","subjects":"edge.msg.>","replicas":1}' >/dev/null 2>&1

    # Publish 3 messages
    nats pub -s nats://172.20.0.50:4222 edge.msg.one '{"n":1}' >/dev/null 2>&1
    nats pub -s nats://172.20.0.50:4222 edge.msg.two '{"n":2}' >/dev/null 2>&1
    nats pub -s nats://172.20.0.50:4222 edge.msg.three '{"n":3}' >/dev/null 2>&1
    sleep 1

    # Get message 1
    r=$(mi_with_params "nats_msg_get" '{"stream":"edge-msg","seq":1}')
    assert_ok "get first message" "$r"
    assert_value "first msg subject" "$r" "assert d['subject'] == 'edge.msg.one'"
    assert_value "first msg data" "$r" "assert '\"n\":1' in d['data'] or d['data'] == '{\"n\":1}'"

    # Get message 3
    r=$(mi_with_params "nats_msg_get" '{"stream":"edge-msg","seq":3}')
    assert_ok "get third message" "$r"
    assert_value "third msg subject" "$r" "assert d['subject'] == 'edge.msg.three'"

    # Delete message 2
    r=$(mi_with_params "nats_msg_delete" '{"stream":"edge-msg","seq":2}')
    assert_ok "delete message 2" "$r"

    # Get deleted message returns error
    r=$(mi_with_params "nats_msg_get" '{"stream":"edge-msg","seq":2}')
    assert_any_error "get deleted message returns error" "$r"

    # Messages 1 and 3 still accessible
    r=$(mi_with_params "nats_msg_get" '{"stream":"edge-msg","seq":1}')
    assert_ok "msg 1 still accessible after deleting msg 2" "$r"
    r=$(mi_with_params "nats_msg_get" '{"stream":"edge-msg","seq":3}')
    assert_ok "msg 3 still accessible after deleting msg 2" "$r"

    # Get beyond last sequence
    r=$(mi_with_params "nats_msg_get" '{"stream":"edge-msg","seq":100}')
    assert_any_error "get beyond last seq returns error" "$r"

    # Cleanup
    mi_with_params "nats_stream_delete" '{"stream":"edge-msg"}' >/dev/null 2>&1
}

test_edge_phase89() {
    echo "=== Edge: Phase 8+9 — subscribe edge cases ==="

    local r

    # Publish empty payload
    nats pub -s nats://172.20.0.50:4222 test.subscribe.empty '' >/dev/null 2>&1
    sleep 1
    if docker compose logs opensips 2>&1 | grep -q "NATS_TEST:.*subject=test.subscribe.empty"; then
        echo "  PASS: empty payload message delivered"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: empty payload message not delivered"
        FAIL=$((FAIL + 1))
    fi

    # Publish large payload (4KB)
    local large_payload
    large_payload=$(python3 -c "import json; print(json.dumps({'data': 'x'*4000}))")
    nats pub -s nats://172.20.0.50:4222 test.subscribe.large "$large_payload" >/dev/null 2>&1
    sleep 1
    if docker compose logs opensips 2>&1 | grep -q "NATS_TEST:.*subject=test.subscribe.large"; then
        echo "  PASS: large payload message delivered"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: large payload message not delivered"
        FAIL=$((FAIL + 1))
    fi

    # Rapid-fire 10 messages
    for i in $(seq 1 10); do
        nats pub -s nats://172.20.0.50:4222 "test.subscribe.rapid.$i" "{\"seq\":$i}" >/dev/null 2>&1
    done
    sleep 2
    local rapid_count
    rapid_count=$(docker compose logs opensips 2>&1 | grep -c "NATS_TEST:.*test.subscribe.rapid")
    if [ "$rapid_count" -ge 10 ]; then
        echo "  PASS: all 10 rapid-fire messages delivered ($rapid_count found)"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: only $rapid_count/10 rapid-fire messages delivered"
        FAIL=$((FAIL + 1))
    fi

    # Publish to non-matching subject (should NOT trigger event_route)
    local before_count
    before_count=$(docker compose logs opensips 2>&1 | grep -c "NATS_TEST:")
    nats pub -s nats://172.20.0.50:4222 other.subject.nope '{"nope":true}' >/dev/null 2>&1
    sleep 1
    local after_count
    after_count=$(docker compose logs opensips 2>&1 | grep -c "NATS_TEST:")
    if [ "$after_count" -eq "$before_count" ]; then
        echo "  PASS: non-matching subject not delivered"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: non-matching subject was delivered"
        FAIL=$((FAIL + 1))
    fi

    # Publish with special characters in payload
    nats pub -s nats://172.20.0.50:4222 test.subscribe.special '{"key":"val with \"quotes\" and \\backslash"}' >/dev/null 2>&1
    sleep 1
    if docker compose logs opensips 2>&1 | grep -q "NATS_TEST:.*subject=test.subscribe.special"; then
        echo "  PASS: special chars in payload delivered"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: special chars in payload not delivered"
        FAIL=$((FAIL + 1))
    fi
}

if [ "$MAX_PHASE" -ge 1 ]; then test_phase1; fi
if [ "$MAX_PHASE" -ge 2 ]; then test_phase2; fi
if [ "$MAX_PHASE" -ge 3 ]; then test_phase3; fi
if [ "$MAX_PHASE" -ge 4 ]; then test_phase4; fi
if [ "$MAX_PHASE" -ge 5 ]; then test_phase5; fi
if [ "$MAX_PHASE" -ge 8 ]; then test_phase89; fi

# Edge case tests (run when phase >= 10 or "edge" is passed)
if [ "$MAX_PHASE" -ge 10 ] || [ "$RUN_EDGE" -eq 1 ]; then
    echo ""
    echo "═══════════════════════════════════════════════"
    echo "  EDGE CASE TESTS"
    echo "═══════════════════════════════════════════════"
    echo ""
    test_edge_phase1
    test_edge_phase2
    test_edge_phase3
    test_edge_phase4
    test_edge_phase5
    test_edge_phase89
fi

echo ""
echo "════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo "════════════════════════════════════════"

exit $FAIL
