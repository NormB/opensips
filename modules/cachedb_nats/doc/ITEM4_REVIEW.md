# Item 4 — Dedicated KV-watcher process: review

**Branch:** `feature/nats`
**Worktree:** `/tmp/feature-nats`
**Status at write time:** uncommitted on `feature/nats`; all tests
green; ready for review and commit.

The point of Item 4 is to let operators move the JetStream KV
watcher out of the rank-1 SIP worker (where it lives as a pthread)
into a dedicated OpenSIPS child process. At ≥ 100k AoRs the
watcher event rate (~1 700 events/sec, ~17 % of one core) competes
with SIP request handling on rank 1. The dedicated proc removes
that contention. At smaller scales it's a no-op (and a small RSS
tax for the extra address space).

This document is the human-review record. The pre-merge contract
is: real numbers, not placeholders; tests that actually run, not
just compile.

---

## 1. What changed (file-by-file)

### Production source

#### `modules/cachedb_nats/cachedb_nats.c` (+182 / −36)
- L211–225: comments + `int nats_dedicated_watcher_proc = 0`
  global with default 0.
- L287: `dedicated_watcher_proc` registered as an `INT_PARAM` in
  the `params[]` array.
- L365–376: file-scope `static const proc_export_t
  nats_watcher_procs[]` declaring `{ "NATS Watcher", 0, 0,
  nats_watcher_proc_main, 1, 0 }`. Not attached to
  `module_exports` at file scope — assignment is runtime, in
  `mod_init`, so the proc is only declared when the operator opts
  in (see L591–602).
- L572–576: log a hint at LM_INFO when the operator sets
  `dedicated_watcher_proc=1` but `enable_search_index=0`
  (the dedicated process will not be forked because there's
  nothing to update).
- L591–602: `mod_init` attaches `exports.procs =
  nats_watcher_procs` only when both `enable_search_index` and
  `dedicated_watcher_proc` are 1 AND at least one `kv_watch`
  pattern is configured. This is the canonical late-assignment
  pattern; the core's `start_module_procs` reads `exports.procs`
  after `init_modules` returns.
- L685–710: `child_init` skips the rank-1 pthread spawn when
  `nats_dedicated_watcher_proc != 0`. Without this, the watcher
  would run twice on the same SHM index.
- L748–749: `destroy()` skips `nats_watch_stop()` in the
  dedicated-process mode. The pthread lives in another process,
  so `pthread_join` from main would deadlock on a tid this
  process never spawned. The OpenSIPS core delivers SIGTERM to
  the dedicated child directly at shutdown.

#### `modules/cachedb_nats/cachedb_nats_watch.c` (+127 / −0)
- L639–707: new `void nats_watcher_proc_main(int rank)`. Loops
  forever. Brings up the per-process NATS connection via
  `nats_pool_get()` (the lib/nats pool config was seeded
  pre-fork in `mod_init`). Validates the KV bucket via
  `nats_pool_get_kv()`. Builds the patterns array from the
  modparam-fed `kv_watch_list`. Sets the file-scope
  `_watcher_running` to 1 and calls `_watcher_loop()` — the
  same self-healing loop the rank-1 pthread runs.
- The function shares all of `_watcher_loop`, `_watcher_running`,
  `_watch_patterns`, `_num_patterns` with the legacy pthread
  path. After fork those become per-process copies, which is
  exactly what we want — the legacy gate in `child_init` keeps
  rank-1 from spawning its own pthread, so there's never any
  cross-thread access to the same statics.
- Index updates are written to the SHM-backed `g_idx` (allocated
  pre-fork in `mod_init`). Cross-process safety is the per-shard
  lock set added in commit 43ceca02b — no new synchronisation.
- Signal handling: relies on the OpenSIPS core's default SIGTERM
  delivery. Process-local NATS handles are released as part of
  the kernel's page cleanup; SHM is owned by the parent and
  freed in `destroy()`.

#### `modules/cachedb_nats/cachedb_nats_watch.h` (+36 / −0)
- L26–37: `kv_watch_entry` struct + `kv_watch_list` /
  `kv_watch_count` externs. Existed implicitly in `cachedb_nats.c`
  before; promoted to header so `nats_watcher_proc_main` in
  `cachedb_nats_watch.c` can build its patterns array from the
  same source the rank-1 pthread uses.
- L73–93: prototype for `nats_watcher_proc_main`. Marked as
  the dedicated-process entry point with the gate semantics
  documented inline.

### Tests

#### `modules/cachedb_nats/tests/test_dedicated_watcher_proc.c` (new, 107 lines)
Structural source-grep test. Asserts the modparam string,
proc_export_t entry, "NATS Watcher" name, watcher_proc_main
references, gate sites in `mod_init` / `child_init` / `destroy`,
and the cross-file symbol declaration. Eleven assertions.

**RED-proven** during this review: stripping the
`"dedicated_watcher_proc"` modparam string from `cachedb_nats.c`
flips the test red (1 failure, exit 1); restoring it flips it
green (exit 0). Verified by sed-replace + run + restore.

#### `modules/cachedb_nats/tests/Makefile` (+14 / −2)
Added `test_dedicated_watcher_proc` to `TESTS` and
`TESTS_TSAN_SAFE`; added a build rule and a `make check` target
line. Compiles with `-g -O0 -Wall`, no special sanitizer flags
(structural test, no UAF arms).

### Test harness wiring

#### `modules/cachedb_nats/tests/sip_e2e/opensips.cfg.in` (+8 / −0)
- Added `modparam("cachedb_nats", "dedicated_watcher_proc",
  @@DEDICATED_WATCHER@@)` rendered from the `DEDICATED_WATCHER`
  env knob.
- Added `modparam("cachedb_nats", "kv_watch", "json_>")`.
  Required for the dedicated proc to actually fork — the gate
  in `mod_init` skips the proc when `kv_watch_count == 0`,
  matching the rank-1 pthread gate. **Without this the entire
  sip_e2e suite was running with the watcher disabled in both
  modes**; an oversight in earlier work that this review
  surfaced and fixed.

#### `modules/cachedb_nats/tests/sip_e2e/run.sh` (+7 / −0)
Renders `@@DEDICATED_WATCHER@@` from `${DEDICATED_WATCHER:-0}`
in `render_cfg`, alongside the existing `ENABLE_INDEX` and
`INDEX_BUCKETS` substitutions.

#### `modules/cachedb_nats/tests/sip_e2e/bench_ul_register.sh` (+33 / −1)
- New `DEDICATED_WATCHER` env knob with default 0.
- Renders the placeholder.
- Logs `DEDICATED_WATCHER:` in the results block alongside
  `ENABLE_INDEX:` and `index_buckets:`.

#### `modules/cachedb_nats/tests/sip_e2e/cases/040_broker_bounce.sh` (+3 / −0)
Renders the new placeholder so the case-specific cfg matches the
shared template.

### Documentation

- `modules/cachedb_nats/doc/PERF_NOTES.md`: new "Item 4 —
  dedicated watcher process" section with the design rationale,
  the gating semantics, and the three-mode bench table from this
  review run. The `dedicated_watcher_proc` bullet was also moved
  out of "What's still on the table".
- `modules/cachedb_nats/doc/SCALING.md`: "Watcher CPU at scale"
  section already references the modparam by name with the
  17 %-of-core threshold. Per-scale recommendations updated to
  cite the modparam where appropriate.
- `modules/cachedb_nats/doc/cachedb_nats_admin.xml`: new
  `<section id="param_dedicated_watcher_proc">` modparam entry
  with the four-bullet behavior list, the gate semantics, the
  100k-AoR threshold guidance, and an `<example>` block.
- `modules/cachedb_nats/doc/cachedb_nats_usrloc_playbook.xml`:
  `dedicated_watcher_proc` `<varlistentry>` in the optional-knobs
  section + paragraph in the scale-tuning section. **DocBook XML
  validates clean** against the OASIS DTD via
  `xmllint --noout --valid cachedb_nats.xml`.

---

## 2. Why this is the right shape

### One process, not a thread pool, not a kernel of N

A single OpenSIPS child process is the right granularity because:

1. **The watcher is one ordered consumer per pattern.** JetStream
   ordered consumers don't fan out — adding more processes
   doesn't speed anything up at the broker side; you'd just have
   more idle subscriptions. So one process = one watcher loop.

2. **The bottleneck above 100k is per-event CPU**, not
   scheduling jitter. Splitting the watcher across processes
   wouldn't help past ~1 core's worth (which is also the rank-1
   pthread's ceiling). The architectural answer at 1MM is
   `enable_search_index=0` (Item 3), not "more watchers."

3. **`proc_export_t` is the canonical OpenSIPS pattern.**
   `event_routing`, `pua_dialoginfo`, `dialog`, and others all
   declare module-owned children this way. It hooks cleanly into
   the core's signal-handling and shutdown paths. A bespoke
   `fork()` from `mod_init` would have been less code but would
   have re-implemented the part of the core that already does
   this correctly.

### Late assignment of `exports.procs` in `mod_init`

The core reads `exports.procs` *after* `init_modules` returns
(via `start_module_procs` in `main_loop`). So we can leave
`module_exports.procs = NULL` at file scope and assign at runtime
based on modparam values. This keeps the proc declaration
**runtime-conditional** without polluting the static module
metadata for operators who never opt in.

Verified by reading the core sequence: `init_mod` → `init_modules`
→ `start_module_procs` (in `main.c`'s startup path).

### Sharing `_watcher_loop` between modes

The legacy pthread function `_watcher_thread_fn` calls
`_watcher_loop()` and so does `nats_watcher_proc_main`. After
fork, the file-scope statics (`_watcher_running`, `_watch_patterns`,
`_num_patterns`) are per-process — the rank-1 worker has its own
copy (zero-initialised, never used in dedicated mode because of
the `child_init` gate); the dedicated proc has its own. No cross-
thread synchronisation is needed because there's no cross-thread
access in either mode.

The alternative — a separate loop function for the dedicated
process — would have duplicated ~280 lines of self-healing
reconnect logic. Sharing wins on every axis.

---

## 3. Compatibility / migration

| Concern | Behavior |
|---|---|
| Default value of `dedicated_watcher_proc` | **0** — legacy pthread topology, unchanged |
| Module load order | Same as before; `proc_export_t` is honored only after `mod_init` returns |
| Existing deployments | No change unless operator sets the modparam |
| `enable_search_index=0` interaction | Dedicated proc not forked, with explicit LM_INFO log; rank-1 pthread also skipped (Item 3 behavior, unchanged) |
| `kv_watch_count == 0` interaction | Dedicated proc not forked (matches rank-1 pthread gate); LM_INFO message |
| Shutdown semantics | SIGTERM from core reaps dedicated child; `destroy()` skips `nats_watch_stop()` in dedicated mode so main doesn't deadlock on `pthread_join` |
| SHM index access | Dedicated process maps the same `g_idx` allocated pre-fork; per-shard locks (commit 43ceca02b) serialise cross-process writes — no new synchronisation |
| NATS connection | Dedicated process has its own per-process NATS connection from the shared pool config; no cross-process connection sharing |
| MI commands | Unaffected; MI runs in PROC_MODULE which doesn't touch the watcher in either mode |

Modparam evaluation order, observed in source:
1. `params[]` parsed by core during config load.
2. `mod_init` sees populated globals, decides whether to attach
   `exports.procs = nats_watcher_procs`.
3. Core's `start_module_procs` walks `exports.procs` after
   `init_modules` returns and forks each declared child.
4. `child_init(rank)` runs in each forked child — the rank-1
   SIP worker reads `nats_dedicated_watcher_proc` and skips its
   pthread spawn if set.

There is no race between the modparam value being read and the
mode being chosen because everything is single-threaded until
the post-`mod_init` fork barrier.

---

## 4. Test coverage

### Unit (structural)
- `test_dedicated_watcher_proc.c` — 11 assertions, RED-proven by
  stripping the modparam string. GREEN restored.

All other cachedb_nats unit tests still pass:
`test_intersect_uaf`, `test_kvget_copy_pattern`,
`test_json_escape`, `test_reply_size_cap`,
`test_disconnected_fastfail`, `test_timeout_normalize`,
`test_update_nested_dict`, `test_update_creates_doc`,
`test_cas_backoff`, `test_index_stale_recovery`,
`test_kv_key_encode`, `test_resync_modparams`,
`test_enable_search_index`. **13/13 GREEN.**

`event_nats` tests: GREEN.
`lib/nats` tests: GREEN.

### sip_e2e (functional / end-to-end)

The full suite exercises real OpenSIPS instances against a real
NATS broker, with real SIP REGISTERs over the wire and assertions
on KV bucket state. Run in three configurations:

| Config | Result | Behavioral evidence (from opensips_A.log) |
|---|---|---|
| Default (`DEDICATED_WATCHER=0`) | **30/30 PASS** | `nats_watch_start: NATS KV watcher started (1 pattern(s): kv_watch[0]: json_>)` and `_watcher_thread_fn: NATS KV watcher thread started` — pthread inside the SIP worker |
| `DEDICATED_WATCHER=1` | **30/30 PASS** | `mod_init: dedicated KV watcher process ENABLED (rank-1 SIP worker will skip the watcher pthread)` and (in the dedicated child's pid) `nats_watcher_proc_main: NATS watcher proc starting (pid=NNNN)` followed by `watcher proc: watching 1 pattern(s)` — separate process |
| `ENABLE_INDEX=0 DEDICATED_WATCHER=1` (regression) | **30/30 PASS** | `mod_init: search index DISABLED` then `mod_init: dedicated_watcher_proc=1 is meaningless when enable_search_index=0; the dedicated process will NOT be forked` — neither watcher starts; PK fast path serves all reads |

Three runs × 30 assertions = **90 e2e assertions GREEN**.

The e2e cases that exercise live watcher behavior in particular:
- `010_register_roundtrip` — REGISTER lands a `json_*` doc; watcher
  is the path that updates the index.
- `030_concurrent_reregister` — concurrent REGISTERs to the same
  AoR; watcher must not race the writer.
- `040_broker_bounce` — broker restart; watcher must reconnect
  without losing index.
- `130_instance_restart_isolation` — instance restart; rebuilt
  state must remain consistent.
- `140_stale_index_self_heal` — external KV mutation; watcher
  must propagate the change to the SHM index.

All five exercise the watcher path. All pass in the dedicated-proc
mode, demonstrating that an out-of-process watcher is functionally
equivalent to the in-process pthread for every behavior the
existing suite asserts.

---

## 5. Bench results

Single instance, loopback NATS broker, HP_MALLOC SHM allocator,
`-m 256 -M 8`, aarch64 (NVIDIA Thor). 10 000 unique AoRs, RPS=200
target, no pacing pause. Measured fields are deltas from MI
counters and per-call latency from sipp.

| Mode | p50 ms | p95 ms | p99 ms | max ms | eff. RPS | RSS MB | CAS retry | CAS exhausted |
|------|------:|------:|------:|------:|--------:|------:|----------:|--------------:|
| rank-1 pthread (default)        | 15.18 | 16.34 | 17.98 | 62.1 | 103.6 | 77.8 | 0 | 0 |
| dedicated watcher proc          | 15.21 | 16.41 | 18.21 | 63.2 | 103.6 | 84.4 | 0 | 0 |
| `enable_search_index=0` (regr.) | 15.01 | 16.11 | 17.68 | 61.9 | 103.6 | 72.1 | 0 | 0 |

### Honest interpretation

At 10 k AoRs single-instance the dedicated mode is **noise-level**
in latency (p50 +0.03 ms, p95 +0.07 ms, p99 +0.23 ms — well
inside run-to-run variance) and pays **+6.6 MB RSS** for the
extra address space.

Latency is broker-RTT-bound at this scale (~15 ms per CAS
roundtrip dominates everything). The watcher event rate at 10 k
AoRs is ~167 events/s consuming <2 % of one core — there is
nothing to isolate yet.

The expected payoff is at higher scale where the watcher's
projected CPU footprint stops being negligible:
- 100 k AoRs: ~1 700 events/s, ~17 % of one core (per
  SCALING.md). Rank-1 starts losing scheduling fairness with
  SIP routing.
- 1 MM AoRs: rank-1 watcher saturates; dedicated proc still
  saturates because the bottleneck is per-event CPU, not
  scheduling. Architectural answer at this scale is
  `enable_search_index=0` (Item 3).

We don't have a 100k bench rig in tree to measure that directly.
The design rationale stands on the SCALING.md projection plus
the empirical fact that at 10 k there's no measurable
regression from running the watcher out-of-process.

---

## 6. Known limits / non-goals

- **No 100k bench numbers.** SCALING.md cites 17 % of one core
  at 100k from a model (event rate × per-event cost), not a
  direct measurement. A 100k-AoR single-instance bench rig
  doesn't exist in tree. Adding one is filed as future work; it
  needs ~30 GB of broker stream storage and a sustained 30-min
  run to reach steady state.
- **Single dedicated proc, not a pool.** As argued in §2, more
  processes wouldn't help — JetStream ordered consumers don't
  fan out, and the per-event CPU bottleneck would still cap
  throughput at one core.
- **No watcher-side metrics yet.** The dedicated proc doesn't
  expose distinct counters from the rank-1 pthread; both write
  to the same `g_idx` and use the same `index_miss_kv` MI
  counter. Operators see the aggregate. Splitting per-mode
  metrics is filed for the next iteration if the deployment
  needs it.
- **No graceful watcher restart.** Killing and respawning just
  the watcher process (without restarting OpenSIPS) is not
  supported. The OpenSIPS core's child-management doesn't
  expose a "restart this child" hook; SIGKILL would leave the
  parent thinking the child is up. Filed.
- **Item 5 (async `nats_request`) is still on the table.** Item
  4 doesn't change the synchronous nature of `nats_request`;
  the rank-1 worker still blocks on RPCs in `request_route`.

---

## 7. Commit list

This review is being written before commit. There are **no Item 4
commits yet** on `feature/nats`. The working tree contains:

- `cachedb_nats.c` — modparam, proc_export_t, gates
- `cachedb_nats_watch.c` — `nats_watcher_proc_main`
- `cachedb_nats_watch.h` — header export
- `tests/test_dedicated_watcher_proc.c` — structural test
- `tests/Makefile` — wire test
- `tests/sip_e2e/opensips.cfg.in` — `dedicated_watcher_proc` +
  `kv_watch` modparam plumbing (the `kv_watch` line is the bug
  fix surfaced by this review)
- `tests/sip_e2e/run.sh`, `bench_ul_register.sh`,
  `cases/040_broker_bounce.sh` — `DEDICATED_WATCHER` env knob
- `doc/PERF_NOTES.md` — Item 4 section + bench table
- `doc/cachedb_nats_admin.xml` — `param_dedicated_watcher_proc`
  section
- `doc/cachedb_nats_usrloc_playbook.xml` — varlistentry +
  scale-tuning paragraph

This is mixed in with Items 1–3 working-tree changes (which
landed in earlier commits per `git log`, but were rebased into
the same uncommitted hunks during the work). When committing
Item 4, suggested split:

1. `cachedb_nats: dedicated KV watcher process (Item 4)` —
   the production source + header + structural test + Makefile.
2. `cachedb_nats: wire DEDICATED_WATCHER + kv_watch into
   sip_e2e harness` — the `tests/sip_e2e/*` changes. The
   `kv_watch` addition is independent of Item 4 and is its own
   bug fix; mentioning that in the commit body is accurate.
3. `cachedb_nats: doc updates for Item 4` — PERF_NOTES + admin
   XML + playbook XML.

---

## 8. Pre-merge checklist (for the reviewer)

- [x] `make all` clean from `/tmp/feature-nats`
- [x] `make check` GREEN: cachedb_nats (13/13), event_nats,
      lib/nats
- [x] `bash modules/cachedb_nats/tests/sip_e2e/run.sh`
      → pass=30 fail=0
- [x] `DEDICATED_WATCHER=1 bash …/run.sh` → pass=30 fail=0
- [x] `ENABLE_INDEX=0 DEDICATED_WATCHER=1 bash …/run.sh`
      → pass=30 fail=0 (regression, dedicated proc correctly
      not forked)
- [x] Bench in three modes captured with measured numbers
      (no placeholders)
- [x] DocBook XML validates against OASIS DTD
      (`xmllint --noout --valid`)
- [x] Structural test RED-proven by stripping the modparam
      and restoring
- [x] Behavioral proof in opensips logs of the dedicated proc
      forking with a distinct pid in mode 2 and being correctly
      skipped in modes 1 and 3
- [ ] **Reviewer decision:** commit and push, or revise

The work is ready for your call.
