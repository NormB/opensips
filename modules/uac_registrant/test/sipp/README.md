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
------------------------------------------------------------
result: 5 passed, 0 failed
```

A failing case instead prints `FAIL` with the offending SIPp verdict and/or MI
state, and the runner exits non-zero.

## Files

| File | Purpose |
|------|---------|
| `run.sh` | orchestrator: per-case OpenSIPS + SIPp lifecycle, MI assertions |
| `opensips.cfg.template` | config template (placeholders filled in per run) |
| `db/version`, `db/registrant` | empty `db_text` seed (registrant added via MI) |
| `scenarios/case_*.xml` | the five SIPp registrar scenarios |

## Related unit tests

The pure decision behind these flows (`min_expires_decide()`) is also covered by
TAP unit tests in `../test.c`, run with:

```sh
make test module=uac_registrant
```

These pin the full truth table — 20 assertions, including the strict `>`
boundary, the `Min-Expires: 0` case, and the over-maximum case — and on success
print `1..20` with every line reported `ok`.
