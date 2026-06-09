# uac_registrant 423 / Min-Expires integration tests (SIPp)

End-to-end tests for the registrant's handling of a `423 (Interval Too Brief)`
reply, i.e. the fix in GitHub issue #3910 and the `min_expires_strict` modparam.

A SIPp UAS plays the **registrar** and answers the registrant's `REGISTER` with a
crafted `423`. A real OpenSIPS instance runs the `uac_registrant` module under
test; the registrant is injected at runtime over the MI FIFO (`reg_upsert`), so a
single config drives every case.

## What is asserted

Each case checks two independent things:

1. **On-the-wire behaviour (SIPp).** Positive cases enforce that the retry
   `REGISTER` carries the expected `;expires=` value using an `ereg`
   `check_it="true"`; negative cases pass only if **no** retry arrives within the
   window.
2. **State-machine outcome (MI).** After the exchange, `reg_list` is queried over
   the MI FIFO and the registrant's `state` is compared against the expectation
   (`REGISTERED_STATE` vs `REGISTRAR_ERROR_STATE`).

## Cases

With requested expires `W = 60` and `M` = the `Min-Expires` we send back:

| Case | Reply | `min_expires_strict` | Expected behaviour | Final state |
|------|-------|----------------------|--------------------|-------------|
| A | `Min-Expires: 120` (`M > W`, conformant) | 1 | retry with 120, accept | `REGISTERED` |
| B | `Min-Expires: 30` (`M < W`) | 1 | registrar error, **no retry** | `REGISTRAR_ERROR` |
| C | `Min-Expires: 30` (`M < W`) | 0 | retry with 30 (legacy/tolerant), accept | `REGISTERED` |
| D | no `Min-Expires` header | 1 | registrar error, **no retry** | `REGISTRAR_ERROR` |
| E | `Min-Expires: 60` (`M == W`, boundary) | 1 | registrar error, **no retry** (pins the strict `>`) | `REGISTRAR_ERROR` |
| F | `Min-Expires: 120` (`M > W`), then a **forced refresh** | 1 | retry with 120, accept; the refresh re-REGISTER **still carries 120** | `REGISTERED` |

Case **F** pins *persistence* — the regression bogdan-iancu described on #3910. The
#3659 change made the record's `expires` field ephemeral (re-seeded from
`wanted_expires` each cycle), so the negotiated `Min-Expires` has to be stored in
the persistent `wanted_expires`; otherwise the immediate retry works but every
later re-REGISTER reverts to the originally requested value. After the conformant
423/retry/accept, the harness forces a re-REGISTER and the scenario asserts that
refresh **also** carries `expires=120`. (A revert to `60` here is invisible to
cases A–E, which each exercise a single cycle.)

## Running

```sh
cd modules/uac_registrant/test/sipp
./run.sh            # run all cases
./run.sh -v         # keep the per-case work dirs (/tmp/uacreg_sipp.*) for debugging
./run.sh A_conformant E_equal_strict   # run a subset
```

Requirements: a built `opensips` in the source root (`make`), `sipp`, `jq`. The
runner loads the freshly built modules from `../../..//modules/` and listens on
`udp:127.0.0.1:5060` (OpenSIPS) and `udp:127.0.0.1:5070` (SIPp registrar);
override with the `OPENSIPS_BIN`, `OPENSIPS_MPATH`, `SIPP_BIN` environment
variables if needed.

The runner passes `opensips -i` to skip the module git-revision cross-check,
which only matters in a local build tree that mixes revisions; version and
compile-flags are still verified.

## Expected output

On success every case prints `PASS` and the runner exits `0`:

```text
------------------------------------------------------------
PASS  A_conformant    sipp=ok  state=REGISTERED_STATE
PASS  B_low_strict    sipp=ok  state=REGISTRAR_ERROR_STATE
PASS  C_low_tolerant  sipp=ok  state=REGISTERED_STATE
PASS  D_missing       sipp=ok  state=REGISTRAR_ERROR_STATE
PASS  E_equal_strict  sipp=ok  state=REGISTRAR_ERROR_STATE
PASS  F_persist       sipp=ok  state=REGISTERED_STATE
------------------------------------------------------------
result: 6 passed, 0 failed
```

A failing case instead prints `FAIL` with the offending SIPp verdict and/or MI
state, and the runner exits non-zero.

## Files

| File | Purpose |
|------|---------|
| `run.sh` | orchestrator: per-case OpenSIPS + SIPp lifecycle, MI assertions |
| `opensips.cfg.template` | config template (placeholders filled in per run) |
| `db/version`, `db/registrant` | empty `db_text` seed (registrant added via MI) |
| `scenarios/case_*.xml` | the six SIPp registrar scenarios |

## Related unit tests

The pure decision behind these flows (`min_expires_decide()`) is also covered by
TAP unit tests in `../test.c`. The harness-native way to run them is a clean
rebuild followed by `make test`, which guarantees every object shares one git
revision before the assertions run:

```sh
make clean all modules && make test module=uac_registrant
```

On a local tree that mixes object revisions — typical right after a rebase,
amend, or branch checkout that leaves some objects built at a different commit —
you can skip the full rebuild and run the test binary directly. `-i` bypasses the
module git-revision cross-check (the module version string and compile flags are
still verified):

```sh
./opensips -dd -T uac_registrant -w . -a HP_MALLOC -i
```

(optionally preceded by `make modules modules=modules/uac_registrant` to pick up
local edits first).

These pin the full truth table — 17 assertions, including the strict `>`
boundary, the `Min-Expires: 0` case, and the over-maximum case.

**Read the TAP output, not the banner.** Success is the TAP `1..N` plan line —
here `1..17` — followed by `N` lines that all begin with `ok`, and zero `not ok`
lines. The `-i` invocation prints exactly that and nothing else:

```text
ok 15 - zero/missing Min-Expires, tolerant: registrar error (never self-de-register)
ok 16 - strict flips the non-conformant case
ok 17 - strict does not affect the conformant case
1..17
```

`make test` additionally prints a `Passed All Tests!` banner after the plan line.
Do **not** treat that banner alone as proof: `Makefile.test` echoes it whenever
the `opensips` process exits `0`, and the process can exit `0` without ever
reaching the test runner. The trap is a stale **built-in** module — if a
`CRITICAL:core:version_control ... revision mismatch` line appears (e.g. for
`proto_udp` after a rebase), `load_static_module()` calls `exit(0)`
(`sr_module.c`), so the binary stops before the assertions run yet `make` still
prints the banner. (A failing assertion, a wrong plan count, or a *dynamically*
loaded module mismatch each exit non-zero and abort `make` with `Error 1`, so
those are caught.) If you see that mismatch line, rebuild as above or pass `-i`,
and confirm the `1..17` plan line is actually present.
