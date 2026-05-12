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

# Bump shared memory to 512 MiB.  Stress tests (stress_multi_worker,
# stress_ack_wait_expiry) override ring_capacity to drain bursts without
# back-pressure; each ring slot is ~18 KiB so a 16k-slot ring is
# ~280 MiB.  The 64 MiB default is sized for steady-state drains, not
# burst-fill rings.
exec /usr/local/sbin/opensips -F -m 512 -M 64 -f /etc/opensips/opensips.cfg
