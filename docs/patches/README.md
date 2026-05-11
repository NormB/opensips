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
  support alternative TLS backends at this time:
  > *"we needed to decide if we would want to support different SSL
  > backend, and at this stage I would say no."*
- **Our rebase:** the original PR diff targeted a mid-2025 libnats
  master and doesn't apply cleanly to the v3.12.0 tag (drift in the
  CMake threads-find logic, the OpenSSL 1.1.1 requirement, and the
  removal of OpenSSL 1.0.x compat in src/conn.c).  This file is a
  hand-rebased version that applies cleanly against v3.12.0.

Because upstream rejected the integration, **this patch is now ours
to maintain forever** — until they reconsider.  Operators who do
not need wolfSSL should load `nats_tls_openssl.so` instead and
ignore this patch entirely.

### Why we ship this anyway

The maintainer's "no" is a *current* stance, not a permanent one.
The position upstream took is reasonable: maintaining two TLS
backends doubles the test matrix, and at the time only one
contributor was asking.  But the calculus shifts as more downstream
projects adopt wolfSSL for concrete reasons that aren't going away:

- **FIPS 140-2 / 140-3 audit pressure.**  wolfSSL ships
  FIPS-validated builds that some compliance regimes treat as
  preferable to OpenSSL's FIPS provider.  Operators in regulated
  industries (telecom, healthcare, financial messaging) increasingly
  see "what TLS library?" appear on audit checklists.
- **Footprint-sensitive deployments.**  wolfSSL is ~600 KB vs
  OpenSSL's ~5 MB.  For OpenSIPS instances running on edge
  appliances, container sidecars, or constrained VMs, that matters.
- **License surface review.**  OpenSSL is Apache-2.0 with the
  historical OpenSSL/SSLeay dual license.  wolfSSL is GPLv2 with a
  commercial option.  Some organizations prefer one over the other
  for reasons specific to their distribution model.

The OpenSIPS ecosystem already supports both backends on the
**SIP** side (`tls_mgm` + `tls_openssl` / `tls_wolfssl`).  Operators
who chose wolfSSL there understandably want the same on the NATS
side.  Shipping this patch gives them that option **and**
demonstrates to upstream nats.c that the integration:

1. Is small (~60 LoC across 4 files).
2. Has been hand-rebased onto a recent tag without trouble.
3. Has at least one downstream project (OpenSIPS) actively using
   and maintaining it.

If you are deploying this in production, **please consider
commenting on [PR #867](https://github.com/nats-io/nats.c/pull/867)
with your use case** — concrete adoption signals are the most
likely thing to change upstream's calculus.  A reopened PR with
multiple downstream voices is much more persuasive than a closed
one with a single contributor.

### Long-term goal

The intent is for this patch to **disappear from our tree** when
upstream nats.c adopts native wolfSSL support.  At that point
operators just bump their nats.c version pin; the rebased patch
becomes the empty file and gets deleted.  Until then we carry it,
keep it green, and treat it as a transitional cost.

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
