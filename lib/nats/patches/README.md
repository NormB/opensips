# Patches for libnats

## nats.c-wolfssl.patch

Adds a wolfSSL TLS backend to libnats ([nats.c](https://github.com/nats-io/nats.c)):
a `NATS_BUILD_WITH_WOLFSSL` CMake option that builds libnats against
wolfSSL's OpenSSL compatibility layer instead of OpenSSL.

It applies to nats.c v3.14.0 and to the commit CI pins in
`scripts/build/install_libnats.sh`, and is tested with wolfSSL v5.9.1
(the version the `tls_wolfssl` module bundles).

### Building

`build_libnats_wolfssl.sh` builds wolfSSL and a patched libnats under
`$PREFIX` (default `/opt/nats-wolfssl`); nothing is installed
system-wide:

```bash title="Build and use a wolfSSL-backed libnats"
PREFIX=/opt/nats-wolfssl sh lib/nats/patches/build_libnats_wolfssl.sh
# then, in OpenSIPS's environment (e.g. Environment= in the systemd unit):
NATS_DL_LIBNATS_PATH=/opt/nats-wolfssl/libnats/lib/libnats.so.3.15
```

`WOLFSSL_VERSION`, `LIBNATS_VERSION` and `WORKDIR` override the defaults.
The libnats major.minor must still match the headers OpenSIPS was built
against (see [Requirements](../README.md#requirements)).

### What the patch changes

- `CMakeLists.txt`, `src/CMakeLists.txt`: the option, the wolfSSL
  lookup (`NATS_WOLFSSL_DIR`) and linking.
- `src/natsp.h`: includes `<wolfssl/options.h>` before the OpenSSL
  headers, so the compatibility macros apply.
- `src/conn.c`:
  - hostname verification works under wolfSSL too. The flag that
    OpenSSL sets with `SSL_set_hostflags()` is set through the
    connection's verify parameters, and `SSL_set1_host()` is kept;
  - a failed handshake reports wolfSSL's own reason (for example
    "peer subject name mismatch") instead of an unrelated queued error.
- `src/opts.c`:
  - CA certificates passed as a PEM string
    (`natsOptions_SetCATrustedCertificates`, which OpenSIPS uses for a
    `tls_mgm` `ca_dir`) load correctly: the OpenSSL error queue is
    cleared first, because loading the system CA store can leave a
    stale error that wolfSSL's PEM reader treats as its own;
  - a client certificate and key passed as PEM strings are loaded with
    wolfSSL's native buffer calls, because the compatibility-layer
    `SSL_CTX_use_PrivateKey()` rejects the key wolfSSL's own PEM reader
    returns. A key that does not match the certificate is refused.

OpenSSL builds are unaffected: every change is under `NATS_HAS_WOLFSSL`.

### Provenance

The CMake and include changes come from
[nats-io/nats.c#867](https://github.com/nats-io/nats.c/pull/867) by
[@kerbert101](https://github.com/kerbert101). That pull request was closed
without merge on 2025-09-10; the nats.c maintainers chose not to support
a second TLS backend. The earlier rebase carried here (for v3.12.0)
dropped hostname verification under wolfSSL and could not load CA or
client certificates from memory; this version fixes both. The patch
should go away if upstream nats.c gains native wolfSSL support.

### Rebasing

1. Check out the new nats.c version and run `git apply --3way` with this
   patch; resolve any conflicts by hand.
2. Regenerate the patch with `git diff` against the base commit.
3. Run `build_libnats_wolfssl.sh` with `LIBNATS_VERSION` set to the new
   version, then both TLS smokes with `NATS_DL_LIBNATS_PATH` pointing at
   the result:
   `lib/nats/tests/test_tls_mgm_smoke.sh` and
   `modules/nats_consumer/tests/test_tls_mgm_consumer_smoke.sh`.
   The smoke's wrong-host scenario checks that hostname verification
   still works.
