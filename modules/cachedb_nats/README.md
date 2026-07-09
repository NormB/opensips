# cachedb_nats

NATS JetStream KV backend for the OpenSIPS CacheDB interface — including
the reaper-authoritative usrloc mode (`CM_FULL_SHARING_CACHEDB`) with
per-AoR CAS-serialized writes, redacted PII logging, and the
`kv_ttl_below_marker` native-TTL optimization (fork brokers only).

**Documentation is generated from docbook** (owner decision 4):

- `README` — the full generated module documentation (parameters, MI
  commands, usage; regenerate with
  `make modules-readme doc_modules=modules/cachedb_nats`).
- `doc/cachedb_nats_admin.xml` — the source of truth.
- `doc/cachedb_nats_usrloc_playbook.xml` — the usrloc deployment
  playbook chapter.
- Capacity/alerts/incidents: `CAPACITY-RUNBOOK.md` in the design
  package (opensips-usrloc-nats).

Tests: `tests/` (unit, ASan/TSan) and `tests/sip_e2e/` (live suite;
`STRICT=1` = release-gate mode). The pre-2026-07 hand-written README
content lives in git history and was folded into the docbook.
