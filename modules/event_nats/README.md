# event_nats

OpenSIPS Event Interface transport for NATS (publisher) plus the
JetStream/KV change-event surface (`E_NATS_KV_CHANGE`).

**Documentation is generated from docbook** (owner decision 4):

- `README` — the full generated module documentation (regenerate with
  `make modules-readme doc_modules=modules/event_nats`).
- `doc/event_nats_admin.xml` — the source of truth.

Tests: `tests/` (unit) and `tests/sip_e2e/` (self-provisioning docker
broker; runs nightly in CI). The pre-2026-07 hand-written README
content lives in git history and was folded into the docbook.
