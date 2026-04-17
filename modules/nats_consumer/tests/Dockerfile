# nats_consumer integration-test image.
#
# Build from the repository root (so COPY sees the full tree):
#   docker build -f modules/nats_consumer/tests/Dockerfile -t nats_consumer_test .
#
# Builds OpenSIPS core and the minimum set of modules needed to exercise
# nats_consumer: event_nats (for the shared connection pool) and
# nats_consumer itself.  Skips db / sip-heavy modules to keep the build
# cycle tight -- this image is for functional + stress testing, not a
# production base.

FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        bison \
        flex \
        pkg-config \
        libssl-dev \
        libcurl4-openssl-dev \
        libnats-dev \
        libpcre2-dev \
        libxml2-dev \
        ca-certificates \
        netbase \
        git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src

# Build only the lib + modules we actually load in the harness.  The
# `include_modules` knob tells opensips' Makefile to only compile those
# modules.  The resulting opensips binary has mi_fifo + the two NATS
# modules + standard core.
RUN make include_modules="mi_fifo event_nats nats_consumer" -j"$(nproc)" \
        modules && \
    make include_modules="mi_fifo event_nats nats_consumer" \
        cfg_target=/etc/opensips/ \
        modules-cfg && \
    make include_modules="mi_fifo event_nats nats_consumer" \
        install-cfg install-modules install-bin

# --- runtime image ---------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 \
        libcurl4 \
        libnats2 \
        libpcre2-8-0 \
        libxml2 \
        ca-certificates \
        netbase \
        procps \
        jq \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/sbin/opensips    /usr/local/sbin/opensips
COPY --from=builder /usr/local/lib/opensips/    /usr/local/lib/opensips/
COPY modules/nats_consumer/tests/opensips.cfg   /etc/opensips/opensips.cfg
COPY modules/nats_consumer/tests/run.sh         /usr/local/bin/run.sh

RUN chmod +x /usr/local/bin/run.sh && \
    mkdir -p /var/run/opensips /var/lib/opensips/nats_consumer

EXPOSE 5060/udp
CMD ["/usr/local/bin/run.sh"]
