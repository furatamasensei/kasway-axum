# kasway-axum

Rust/Axum port of the `kasway-v2-api` HTTP layer (originally AdonisJS 6 + PostgreSQL).
Goal: **identical request/response contracts** for all endpoints, validated
test-first. All 240 endpoints are ported (see `ENDPOINTS.md`), and the KPR-1
payment path is settled on-chain through Kaspa covenants — the crypto/chain
layer that phase 1 originally stubbed is now real.

## Scope

- **In:** every HTTP endpoint, DB persistence (PostgreSQL via `sqlx`), validation,
  auth (Adonis-compatible: Bearer access tokens, `x-kasway-api-key`,
  internal token), request/response contract parity, real KPR-1 intent signing
  (ed25519), on-chain covenant settlement, and dispute resolution.
- **Real (no longer stubbed):** KPR-1 minting/signing, covenant compilation +
  P2SH derivation (`kasway-covenant`), on-chain payment observation, covenant
  release/refund, and the Tier-3 community-jury dispute layer.
- **Still stubbed/deferred:** mail, S3/R2 object storage, and external
  queue/broker infra. Webhook delivery runs as an in-process worker (see
  `crates/kasway-api/src/webhook_worker.rs`) rather than an external queue.
- **Contract definition:** tests assert request/response shape + status codes match
  Adonis (derived from reading the source controllers/validators/models).

## Layout (Cargo workspace)

```
crates/
  kasway-db/        # sqlx PostgreSQL pool + embedded migrations (ported from Lucid)
  kasway-covenant/  # SilverScript-compiled Kaspa covenants: escrow_v2 (tiered
                    #   dispute resolution), jury_escrow (K-of-N jury), juror_bond;
                    #   P2SH derivation + spend sig scripts. The ONLY place that
                    #   touches rusty-kaspa / assembles covenant script bytes.
  kasway-api/       # axum app: lib.rs (build_router), main.rs (bin), handlers,
                    #   auth, background workers, KPR-1, dispute orchestration
    tests/          # integration tests: spawn app on ephemeral port, hit it with reqwest
```

## Workflow (per the migration rules)

1. Map endpoints (`ENDPOINTS.md` — the coverage contract; nothing left behind).
2. For each endpoint: read the Adonis controller/validator/model, write the Rust
   contract test first (red), then implement the handler (green).
3. `cargo test` must stay green; `ENDPOINTS.md` Status column tracks progress.

## Running

The quickest path is the Docker Compose stack (server + PostgreSQL):

```bash
cp .env.example .env       # optional; adjust secrets/ports
docker compose up --build  # migrations run on startup; API on http://localhost:8080
docker compose logs -f api # follow logs
docker compose down        # stop (add -v to drop the DB volume)
```

Or run against a local PostgreSQL directly:

```bash
cargo test                 # run all integration + unit tests (needs a local PostgreSQL)
cargo run -p kasway-api    # start server
```

Key env vars (full list in `.env.example`):

- `DATABASE_URL` — PostgreSQL connection string
  (compose default `postgres://postgres:postgres@db:5432/kasway`).
- `HOST_PORT` — bind address (compose/`.env` use `0.0.0.0:8080`; code default
  `0.0.0.0:3333`).
- `INTERNAL_API_TOKEN` — Bearer token for `/internal/*` endpoints.

Embedded migrations are applied automatically on startup. Tests create a fresh
disposable `kasway_test_*` database per test on the server pointed at by
`DATABASE_URL` (the database name in the URL is ignored; the admin connection
uses the `postgres` maintenance DB).

## Background workers

Three workers start in-process at boot; each is independently gated:

- **Webhook delivery** (`webhook_worker.rs`) — delivers queued webhook events.
  `WEBHOOK_WORKER_ENABLED` (default on; `0`/`false`/`off` disables).
- **Chain observer** (`chain_observer.rs`) — observes/confirms on-chain KPR-1
  payments. `CHAIN_OBSERVER_ENABLED` (default on only when `KASPA_NODE_URL` is
  set). See below.
- **Covenant keeper** (`covenant_keeper.rs`) — auto-refunds expired covenants
  (returns gross to the customer, marks the invoice `expired`, emits
  `invoice.refunded`). Merchant *release* now requires the customer's
  "confirm delivery" signature and is driven by a customer-facing endpoint, not
  this worker — the keeper only ever signs its own fee input.
  `COVENANT_KEEPER_ENABLED` (default on when a keeper fee key and
  `KASPA_NODE_URL` are set); needs `COVENANT_KEEPER_FEE_SECRET`.

## Covenant settlement (KPR-1 on-chain)

KPR-1 is settled entirely through Kaspa covenants (zero legacy path). At mint,
the intent records the ordered payout split (merchant net, tax, splits, Kasway
fee) and the gross/expiry the covenant enforces; the covenant P2SH address
depends on the payer's refund address and is derived at finalize. Every covenant
script byte comes from the SilverScript compiler — there is no hand-assembled
opcode anywhere in Kasway. All Kaspa consensus crypto is confined to
`kasway-covenant`.

The **chain observer** closes the loop: txid submitted at checkout → observed on
chain → confirmations tracked → covenant `funded`, and (via the keeper /
customer confirmation) release or auto-refund. It verifies each transaction's
outputs against the intent's required outputs (exact address + amount —
mismatches fail closed: `verification_status = failed` + a
`payment_anomaly_signals` row; the invoice is never marked paid), records the
`payment_observations` row, and settles once confirmations (virtual DAA −
accepting DAA) meet the tenant's confirmation policy (`payment_tenant_settings`,
platform default 10). Progress is checkpointed in
`payment_indexer_checkpoints` (source `chain_observer`).

`KASPA_NODE_URL` must point at a Kaspa node's **wRPC JSON** websocket endpoint
(rusty-kaspa's stock JSON ports are 18110 mainnet / 18210 TN10 — always the JSON
listener, not Borsh 17110/17210; see `crates/kasway-api/src/kaspa_wrpc.rs`).

Not yet: no address watching — payments are only observed for transactions whose
txid a wallet submitted; unsolicited transfers to merchant addresses arrive with
the address-watching phase.

## Disputes (Tier-3 community jury)

Disputes escalate to an on-chain `JuryEscrow` settlement (see
`crates/kasway-api/src/dispute.rs` and `kasway-covenant/src/jury_escrow.rs`):
**open** (record evidence hashes, freeze the juror-pool + evidence roots) →
**select** (deterministically draw a K-of-N committee from the bonded pool using
a beacon seed, excluding the parties) → **vote** (collect each member's 64-byte
`datasig` over the verdict digest) → **settle** (once K sigs agree, broadcast
`release_jury` or `refund_jury`; the covenant verifies the committee sigs
on-chain via `checkSigFromStack`). The tiered `escrow_v2` covenant also supports
an M-of-N arbiter panel (`COVENANT_ARBITER_*`). Committee selection and digest
derivations are pure/deterministic so anyone can recompute and audit them.

## Status

All 240 endpoints ported (`ENDPOINTS.md`); KPR-1 covenant settlement, chain
observation, and the jury dispute layer are implemented and covered by
integration tests.
