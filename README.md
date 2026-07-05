# kasway-axum

Rust/Axum port of the `kasway-v2-api` HTTP layer (originally AdonisJS 6 + PostgreSQL).
Goal: **identical request/response contracts** for all ~221 endpoints, validated
test-first. External systems (Kaspa chain, queues, Redis, S3, mail, OAuth) are
stubbed behind clean interfaces in this phase — see scope decisions below.

## Scope (phase 1)

- **In:** every HTTP endpoint, DB persistence (SQLite via `sqlx`), validation,
  auth (Adonis-compatible: Bearer access tokens, `x-kasway-api-key`,
  internal token), request/response contract parity.
- **Stubbed/deferred:** KPR-1/Kaspa crypto & chain indexing, background jobs/queues
  (except webhook delivery, which runs as an in-process worker — see
  `crates/kasway-api/src/webhook_worker.rs`), mail, S3/R2, Google OAuth callback,
  SSE (transmit).
- **Contract definition:** tests assert request/response shape + status codes match
  Adonis (derived from reading the source controllers/validators/models).

## Layout (Cargo workspace)

```
crates/
  kasway-db/     # sqlx SQLite pool + migrations (ported from Lucid migrations)
  kasway-api/    # axum app: lib.rs (build_router), main.rs (bin), handlers, auth, error
    tests/       # integration tests: spawn app on ephemeral port, hit it with reqwest
```

## Workflow (per the migration rules)

1. Map endpoints (`ENDPOINTS.md` — the coverage contract; nothing left behind).
2. For each endpoint: read the Adonis controller/validator/model, write the Rust
   contract test first (red), then implement the handler (green).
3. `cargo test` must stay green; `ENDPOINTS.md` Status column tracks progress.

## Commands

```bash
cargo test                 # run all integration + unit tests (needs a local PostgreSQL)
cargo run -p kasway-api    # start server (DATABASE_URL, INTERNAL_API_TOKEN, HOST_PORT)
```

Default `DATABASE_URL=postgres://postgres:postgres@localhost:5432/kasway`,
`HOST_PORT=0.0.0.0:3333`. Tests create a disposable `kasway_test_*` database
per test on the server pointed at by `DATABASE_URL` (the database name in the
URL is ignored; the admin connection uses the `postgres` maintenance DB).

The webhook delivery worker runs in-process at startup; disable it with
`WEBHOOK_WORKER_ENABLED=0` (default on).

## Chain observer (KPR-1 on-chain verification)

The chain observer (`crates/kasway-api/src/chain_observer.rs`) closes the loop
for wallet-submitted KPR-1 payments: txid submitted at checkout → observed on
chain → confirmations tracked → invoice `paid` + `invoice.paid` webhook event
(delivered by the webhook worker).

- `KASPA_NODE_URL` — websocket URL of a Kaspa node's **wRPC JSON** endpoint,
  e.g. `ws://<ip>:17210` for a TN10 node serving the JSON encoding on that
  port (rusty-kaspa's stock JSON ports are 18110 mainnet / 18210 TN10, Borsh
  17110/17210 — always point this at the JSON listener; see
  `crates/kasway-api/src/kaspa_wrpc.rs`).
- `CHAIN_OBSERVER_ENABLED` — gate override (`0`/`false`/`off` disable).
  Default: on only when `KASPA_NODE_URL` is set; off otherwise.

What this slice does: every ~5s it picks up intents whose wallet submitted a
txid, verifies the transaction's outputs against the intent's required
outputs (exact address + amount — mismatches fail closed: intent
`verification_status = failed` + a `payment_anomaly_signals` row, the invoice
is never marked paid), records/updates the `payment_observations` row, and
settles (confirmed payment row, invoice `paid`, `invoice.paid` event) once
confirmations (virtual DAA − accepting DAA) meet the tenant's confirmation
policy (`payment_tenant_settings`, platform default 10). Progress is
checkpointed in `payment_indexer_checkpoints` (source `chain_observer`).

What it does NOT do yet: no address watching — payments are only observed for
transactions whose txid a wallet submitted; unsolicited/unknown transfers to
merchant addresses arrive with the address-watching phase.

## Status

Foundation + internal-token tier proven (health + payment-indexer). See `ENDPOINTS.md`.
