# kasway-axum

Rust/Axum port of the `kasway-v2-api` HTTP layer (originally AdonisJS 6 + PostgreSQL).
Goal: **identical request/response contracts** for all ~221 endpoints, validated
test-first. External systems (Kaspa chain, queues, Redis, S3, mail, OAuth) are
stubbed behind clean interfaces in this phase — see scope decisions below.

## Scope (phase 1)

- **In:** every HTTP endpoint, DB persistence (SQLite via `sqlx`), validation,
  auth (Adonis-compatible: Bearer access tokens, `x-kasway-api-key`,
  internal token), request/response contract parity.
- **Stubbed/deferred:** KPR-1/Kaspa crypto & chain indexing, background jobs/queues,
  webhook delivery, mail, S3/R2, Google OAuth callback, SSE (transmit).
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
cargo test                 # run all integration + unit tests
cargo run -p kasway-api    # start server (DATABASE_URL, INTERNAL_API_TOKEN, HOST_PORT)
```

Default `DATABASE_URL=sqlite://kasway.db`, `HOST_PORT=0.0.0.0:3333`.

## Status

Foundation + internal-token tier proven (health + payment-indexer). See `ENDPOINTS.md`.
