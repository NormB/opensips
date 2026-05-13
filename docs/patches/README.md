# Vendored patches for NATS-side dependencies

This directory ships small, hand-maintained patches that we apply to
external NATS-related source trees during build.  Each patch is
independent; this README is the directory's index.

> **Status (v4.0-nats-rc1):** `nats.c-wolfssl-v3.12.0.patch` is
> a CI-validated optional build path.  TLS routing through
> `tls_mgm`'s `nats` client domain is what the NATS modules
> actually use; the libnats variant the modules load against
> (OpenSSL-default or wolfSSL-built-from-this-patch) is selected
> by `ld.so` search or by `$NATS_DL_LIBNATS_PATH`.  See
> [`docs/nats-tls-backends.md`](../nats-tls-backends.md) for the
> operator guide and the wolfSSL build recipe.

## nats.c-wolfssl-v3.12.0.patch

Adds wolfSSL TLS backend support to libnats (`nats-io/nats.c`) by
introducing a `NATS_BUILD_WITH_WOLFSSL` CMake option and wiring the
necessary header-include reordering + small source guards so libnats
links against wolfSSL's OpenSSL-compat layer instead of OpenSSL
itself.

### Provenance

- **Upstream PR:** [nats-io/nats.c#867](https://github.com/nats-io/nats.c/pull/867) by [@kerbert101](https://github.com/kerbert101) (Albert Bakker).  Thanks to Albert for the original integration work and the careful CMake structure that made the rebase straightforward.
- **Upstream status:** closed without merge on 2025-09-10.  The
  nats.c maintainers weighed adding a second TLS backend and
  decided to hold for now:
  > *"we needed to decide if we would want to support different SSL
  > backend, and at this stage I would say no."*

  A reasonable call: a second backend roughly doubles the TLS test
  matrix, and at the time the PR landed there was only one
  downstream voice asking.  We respect the decision and the
  maintenance constraints behind it.
- **Our rebase:** the original PR diff targeted a mid-2025 libnats
  master and doesn't apply cleanly to the v3.12.0 tag (drift in the
  CMake threads-find logic, the OpenSSL 1.1.1 requirement, and the
  removal of OpenSSL 1.0.x compat in src/conn.c).  This file is a
  hand-rebased version that applies cleanly against v3.12.0.

Until native wolfSSL support is part of upstream, we carry this
patch in-tree so OpenSIPS operators who need wolfSSL on the NATS
side have a working path.  Operators who don't need wolfSSL skip
this patch entirely and use whichever libnats their distro ships
(typically the OpenSSL-backed `libnats.so.3.x`).

### Why we ship this anyway

The wolfSSL ask shows up across the broader open-source ecosystem
for concrete reasons that aren't going away:

- **FIPS 140-2 / 140-3 audit needs.**  wolfSSL ships FIPS-validated
  builds that some compliance regimes treat as preferable to
  OpenSSL's FIPS provider.  Operators in regulated industries
  (telecom, healthcare, financial messaging) increasingly see
  "what TLS library?" appear on audit checklists.
- **Footprint-sensitive deployments.**  wolfSSL is ~600 KB vs
  OpenSSL's ~5 MB.  For OpenSIPS instances running on edge
  appliances, container sidecars, or constrained VMs, that matters.
- **License surface review.**  OpenSSL is Apache-2.0 (with the
  historical OpenSSL/SSLeay legacy); wolfSSL is GPLv2 with a
  commercial option.  Different distribution models settle on
  different answers.

The OpenSIPS ecosystem already offers operators both backends on
the SIP side (`tls_mgm` + `tls_openssl` / `tls_wolfssl`), so it's
natural for operators who picked wolfSSL there to want feature
parity on the NATS side.

This patch is a contribution we'd like to share back upstream if
and when the timing makes sense.  The rebased diff is small
(~60 LoC across 4 files), green on our CI, and exercised in
production by the OpenSIPS deployments that adopt it.  That track
record may be useful evidence if the upstream conversation reopens.

### Helping the upstream conversation along

If you deploy this patch in production and would be willing to
share that context publicly, leaving a friendly note on
[upstream PR #867](https://github.com/nats-io/nats.c/pull/867) with
your specific use case (FIPS audit, footprint, license review,
embedded target — whatever) is genuinely useful.  Concrete adoption
data is the most respectful way to ask maintainers to revisit a
decision; it gives them something they can act on instead of just
"please".

If you'd rather not engage upstream directly, opening an issue on
the OpenSIPS side of this repo with your use case also helps —
we can aggregate context for a future joint conversation.

### Long-term goal

The intent is for this patch to **leave our tree** the day upstream
nats.c adopts native multi-backend TLS support.  At that point
operators just bump their nats.c version pin; the rebased patch
becomes empty and gets deleted.  Until then we carry it, keep it
green against current libnats releases, and treat the maintenance
burden as a transitional cost shared with the wider ecosystem.

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

# Register /opt/wolfssl/lib with the dynamic linker so libnats's
# DT_NEEDED libwolfssl.so.NN resolves at runtime.
echo "/opt/wolfssl/lib" | sudo tee /etc/ld.so.conf.d/wolfssl.conf
sudo ldconfig
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
