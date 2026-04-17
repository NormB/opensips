#!/bin/sh
# Foreground opensips entrypoint for the integration-test image.
#
# Creates runtime dirs (compose volume may be empty), waits briefly
# for the nats service to become reachable, then execs opensips in
# the foreground so docker can track the process.
set -eu

mkdir -p /var/run/opensips /var/lib/opensips/nats_consumer

# Wait up to 20s for nats:4222 to resolve + accept.  The compose
# healthcheck gates service start, but DNS caches can lag.
i=0
while [ $i -lt 20 ]; do
    if getent hosts nats >/dev/null 2>&1; then
        break
    fi
    sleep 1
    i=$((i + 1))
done

exec /usr/local/sbin/opensips -F -f /etc/opensips/opensips.cfg
