# Vendored patches for NATS-side dependencies

This directory ships small, hand-maintained patches that we apply to
external NATS-related source trees during build.  Each patch is
independent; this README is the directory's index.

## nats.c-wolfssl-v3.12.0.patch

Adds wolfSSL TLS backend support to libnats (`nats-io/nats.c`) by
introducing a `NATS_BUILD_WITH_WOLFSSL` CMake option and wiring the
necessary header-include reordering + small source guards so libnats
links against wolfSSL's OpenSSL-compat layer instead of OpenSSL
itself.

### Provenance

- **Upstream PR:** [nats-io/nats.c#867](https://github.com/nats-io/nats.c/pull/867) by [@kerbert101](https://github.com/kerbert101) (Albert Bakker).
- **Upstream status:** **closed without merge** on 2025-09-10.  The
  upstream maintainer (kozlovic) explicitly decided libnats will not
  support alternative TLS backends:
  > *"we needed to decide if we would want to support different SSL
  > backend, and at this stage I would say no."*
- **Our rebase:** the original PR diff targeted a mid-2025 libnats
  master and doesn't apply cleanly to the v3.12.0 tag (drift in the
  CMake threads-find logic, the OpenSSL 1.1.1 requirement, and the
  removal of OpenSSL 1.0.x compat in src/conn.c).  This file is a
  hand-rebased version that applies cleanly against v3.12.0.

Because upstream rejected the integration, **this patch is now ours
to maintain forever.**  Operators who do not need wolfSSL should
load `nats_tls_openssl.so` instead and ignore this patch entirely.

### Applies to

- `nats.c` tag **v3.12.0** (commit `aed20fe4`)
- May need rebasing against future nats.c versions; the four touched
  files are:
  - `CMakeLists.txt`  (option + find_package logic + define gate)
  - `src/CMakeLists.txt`  (link wolfssl libraries)
  - `src/conn.c`  (`SSL_verify_cb` typedef + wolfssl exclusion around
    `SSL_set_hostflags` / `SSL_set1_host`)
  - `src/natsp.h`  (`<wolfssl/options.h>` include before openssl
    headers so the compat-layer macros take effect)

### Applying

```
git clone --depth 1 --branch v3.12.0 https://github.com/nats-io/nats.c
cd nats.c
git apply /path/to/this/patch
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/opt/libnats-wolfssl \
      -DNATS_BUILD_WITH_WOLFSSL=ON \
      -DNATS_WOLFSSL_DIR=/opt/wolfssl \
      ..
make -j$(nproc) && sudo make install
```

The resulting `libnats.so.3.12` has `libwolfssl.so` in its
`DT_NEEDED` and uses wolfSSL's OpenSSL-compat layer for the entire
TLS surface libnats touches.  See the top-level
[`docs/nats-tls-backends.md`](../nats-tls-backends.md) for the full
operator recipe.

### Maintenance

When bumping the nats.c version in
[`.github/workflows/nats-tls-backends.yml`](../../.github/workflows/nats-tls-backends.yml)
or the operator docs:

1. Clone the new tag.
2. Try `git apply --check docs/patches/nats.c-wolfssl-v3.12.0.patch`.
3. If it applies cleanly, you're done — rename the patch file to
   match the new version pin and update references.
4. If conflicts: hand-resolve, regenerate via `git diff > newpath`,
   keep the conflict resolution notes in the commit message.

The patch is small (60 net lines added across 4 files); expect
rebases to take 10-30 min when nats.c's TLS or CMake code changes.
