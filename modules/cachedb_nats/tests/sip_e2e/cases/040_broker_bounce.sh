# 040 — NATS broker bounce mid-traffic must not crash opensips and
# subsequent REGISTERs must succeed once the broker comes back.
#
# We can't kill the operator's NATS broker, so this case spins up its
# own disposable nats-server on $BOUNCE_NATS_PORT, points a fresh
# opensips instance at it, exercises the bounce, and tears it all
# down without touching the suite-level broker.
case_begin "040_broker_bounce"

# Resolve nats-server robustly.  On Debian it installs to /usr/sbin, which is
# often NOT on a non-login shell's PATH, so a bare `command -v nats-server`
# spuriously reports it missing.  Honour an explicit BOUNCE_NATS_BIN override,
# then search PATH and the usual absolute locations.
if [ -z "${BOUNCE_NATS_BIN:-}" ]; then
    for _cand in nats-server /usr/sbin/nats-server /usr/local/bin/nats-server \
                 /usr/bin/nats-server /usr/local/sbin/nats-server; do
        if command -v "$_cand" >/dev/null 2>&1; then
            BOUNCE_NATS_BIN="$(command -v "$_cand")"
            break
        fi
    done
fi
if [ -z "${BOUNCE_NATS_BIN:-}" ]; then
    check "nats-server available for disposable broker" fail \
        "skipping — install nats-server for this case"
    return 0
fi
export BOUNCE_NATS_BIN

BOUNCE_NATS_PORT=4322
BOUNCE_NATS_JS="$WORKDIR/bounce_jsdir"
mkdir -p "$BOUNCE_NATS_JS"

# Start the disposable broker
"$BOUNCE_NATS_BIN" -p "$BOUNCE_NATS_PORT" -js -sd "$BOUNCE_NATS_JS" \
    > "$WORKDIR/bounce_nats.log" 2>&1 &
BOUNCE_NATS_PID=$!
for i in $(seq 1 10); do
    nats --server "nats://127.0.0.1:${BOUNCE_NATS_PORT}" \
        server check connection >/dev/null 2>&1 && break
    sleep 0.5
done

# Start a separate opensips instance pointed at the disposable broker
BOUNCE_NATS_URL="nats://127.0.0.1:${BOUNCE_NATS_PORT}"
"$KVCTL" mk "$BOUNCE_NATS_URL" "$KV_BUCKET" "${KV_HISTORY:-1}" 30 \
    >/dev/null 2>&1 || true

BOUNCE_SIP_PORT=5076
BOUNCE_MI_PORT=8891
BOUNCE_CLUSTER_PORT=5668
BOUNCE_CFG="$WORKDIR/opensips_bounce.cfg"
sed -e "s|@@MODULES@@|${OPENSIPS_MODULES}|g" \
    -e "s|@@NATS_URL@@|${BOUNCE_NATS_URL}|g" \
    -e "s|@@CACHEDB_URL@@|nats:loc://127.0.0.1:${BOUNCE_NATS_PORT}/|g" \
    -e "s|@@SIP_PORT@@|${BOUNCE_SIP_PORT}|g" \
    -e "s|@@MI_PORT@@|${BOUNCE_MI_PORT}|g" \
    -e "s|@@CLUSTER_PORT@@|${BOUNCE_CLUSTER_PORT}|g" \
    -e "s|@@NODE_ID@@|9|g" \
    -e "s|@@KV_BUCKET@@|${KV_BUCKET}|g" \
    -e "s|@@INSTANCE@@|BOUNCE|g" \
    -e "s|@@ENABLE_INDEX@@|${ENABLE_INDEX:-1}|g" \
    -e "s|@@INDEX_BUCKETS@@|${INDEX_BUCKETS:-4096}|g" \
    -e "s|@@DEDICATED_WATCHER@@|${DEDICATED_WATCHER:-0}|g" \
    -e "s|@@EXPIRED_LINGER@@|${EXPIRED_LINGER:-0}|g" \
    -e "s|@@REAP_INTERVAL@@|${REAP_INTERVAL:-30}|g" \
    -e "s|@@UNSAFE_TTL_ONLY@@|${UNSAFE_TTL_ONLY:-0}|g" \
    "${HERE}/opensips.cfg.in" > "$BOUNCE_CFG"

LD_LIBRARY_PATH="${OPENSIPS_LIB_NATS}:/usr/local/lib:${LD_LIBRARY_PATH:-}" \
    "$OPENSIPS_BIN" -F -f "$BOUNCE_CFG" -m 64 -M 4 \
    > "$WORKDIR/opensips_bounce.log" 2>&1 &
BOUNCE_OPENSIPS_PID=$!
sleep 2

if ! kill -0 "$BOUNCE_OPENSIPS_PID" 2>/dev/null; then
    check "bounce-instance opensips boots" fail \
        "$(tail -10 "$WORKDIR/opensips_bounce.log" 2>/dev/null)"
    kill "$BOUNCE_NATS_PID" 2>/dev/null
    return 0
fi
check "bounce-instance opensips boots" ok

# Pre-bounce REGISTER lands
sipsak -U -C "sip:pre@127.0.0.1:${BOUNCE_SIP_PORT}" \
    -s "sip:pre@127.0.0.1:${BOUNCE_SIP_PORT}" -e 3600 -t 1 -O 1 \
    > "$WORKDIR/sipsak_pre.out" 2>&1
check "pre-bounce REGISTER ok" \
    $([ "$?" = 0 ] && echo ok || echo fail)

# Kill the broker mid-flight
kill "$BOUNCE_NATS_PID" 2>/dev/null
wait "$BOUNCE_NATS_PID" 2>/dev/null
sleep 1

# REGISTER attempted while broker is down; must not hang or crash.
# We use a 3-second timeout to bound the assertion.
timeout 5 sipsak -U -C "sip:mid@127.0.0.1:${BOUNCE_SIP_PORT}" \
    -s "sip:mid@127.0.0.1:${BOUNCE_SIP_PORT}" -e 3600 -t 1 -O 1 \
    > "$WORKDIR/sipsak_mid.out" 2>&1
mid_rc=$?
if kill -0 "$BOUNCE_OPENSIPS_PID" 2>/dev/null; then
    check "opensips survives broker outage" ok
else
    check "opensips survives broker outage" fail \
        "$(tail -20 "$WORKDIR/opensips_bounce.log" 2>/dev/null)"
fi

# Bring broker back up
"$BOUNCE_NATS_BIN" -p "$BOUNCE_NATS_PORT" -js -sd "$BOUNCE_NATS_JS" \
    > "$WORKDIR/bounce_nats.log" 2>&1 &
BOUNCE_NATS_PID=$!
for i in $(seq 1 10); do
    nats --server "$BOUNCE_NATS_URL" server check connection \
        >/dev/null 2>&1 && break
    sleep 0.5
done

# nats.c reconnect logic should re-establish the connection within ~5s
sleep 5

# Post-bounce REGISTER should succeed
timeout 5 sipsak -U -C "sip:post@127.0.0.1:${BOUNCE_SIP_PORT}" \
    -s "sip:post@127.0.0.1:${BOUNCE_SIP_PORT}" -e 3600 -t 1 -O 1 \
    > "$WORKDIR/sipsak_post.out" 2>&1
post_rc=$?
check "post-bounce REGISTER ok after reconnect" \
    $([ "$post_rc" = 0 ] && echo ok || echo fail) \
    "post_rc=$post_rc"

# Cleanup the case-local instance and broker
kill "$BOUNCE_OPENSIPS_PID" 2>/dev/null
kill "$BOUNCE_NATS_PID" 2>/dev/null
wait "$BOUNCE_OPENSIPS_PID" 2>/dev/null
wait "$BOUNCE_NATS_PID" 2>/dev/null
