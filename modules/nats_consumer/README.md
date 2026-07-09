# nats_consumer

JetStream pull-consumer for OpenSIPS: a dedicated consumer process
fetches messages into per-handle SHM rings for SIP workers, with
explicit ack/nak/term, a poison-message backstop
(`poison_max_deliver`, default 20), and the slot-based async
`nats_request` RPC transport (disconnects cancel on the next guard
tick).

**Documentation is generated from docbook** (owner decision 4):

- `README` — the full generated module documentation (regenerate with
  `make modules-readme doc_modules=modules/nats_consumer`).
- `doc/nats_consumer_admin.xml` — the source of truth (bind keys,
  modparams, MI incl. `nats_consumer_stats`, return codes).

Tests: `tests/` (unit + docker + stress; `run_all.sh`). The
pre-2026-07 hand-written README content lives in git history and was
folded into the docbook.
