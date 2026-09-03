# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
cargo test                                  # all tests; needs a local PostgreSQL (see below)
cargo test -p kasway-api --test subscriptions_proper_test          # one test file
cargo test -p kasway-api --test subscriptions_proper_test -- <fn>  # one test fn
cargo check --workspace                     # fast type-check
cargo run -p kasway-api                     # run server (default 0.0.0.0:3333)
docker compose up --build                   # server + PostgreSQL; API on :8080
make test-db-clean                          # force-drop leftover disposable test DBs
```

TN10 on-chain covenant smoke harness (never moves funds on its own; broadcast
is gated behind `SMOKE_BROADCAST=1`, dry-run otherwise):

```bash
KASPA_NODE_URL=ws://<node>:18210 cargo run -p kasway-api --example covenant_tn10_smoke -- <mode>
```

Subscription renewal is no longer a server-side covenant smoke: every cycle is
a fresh signed KPR-1 invoice and the wallet owns verification, signing, and
broadcast. Exercise that flow through the mobile TN10 E2E harness and keep the
backend contract covered by `subscription_autopay_test`.

Testing model: integration tests in `crates/kasway-api/tests/` spawn the app on
an ephemeral port and hit it with reqwest. Each test creates a fresh disposable
`kasway_test_<pid>_<millis>_<counter>` database on the server pointed at by
`DATABASE_URL` — the database name in the URL is ignored; the harness connects
to the `postgres` maintenance DB to create/drop. Migrations are embedded in
`kasway-db` and run automatically at startup.

## What this is

Kasway is a commerce-payment protocol on Kaspa: the API mints signed single-use
KPR-1 payment intents, a self-custodial wallet verifies and signs locally, an
independent chain observer confirms funding, and a Kaspa covenant is the only
authority that settles. `docs/WHITEPAPER.md` is the design source of truth —
its section 13 separates implemented draft behavior from remaining target work,
`docs/ARBITRATION_PROTOCOL_V1.md` defines the implemented evaluator protocol,
and Appendix A is the normative KPR-1 intent format.

Trust invariants every change must preserve:

- **No custody.** The API never receives or stores a private key, seed, or
  decryption key. Wallet signing is local; browser signing exists only as a
  fail-closed TN10 testing exception.
- **Fail closed.** Wallet-side and observer-side verification mismatches never
  mark an invoice paid (`verification_status = failed` + a
  `payment_anomaly_signals` row).
- **Covenant-only settlement.** No code path moves escrowed funds via a
  database decision; settlement is an authorized covenant spend.
- **Everything the payer consents to rides inside the Ed25519 signature** —
  including `display.items` and subscription identity. Never move data out of
  the signed intent into an unsigned response.

## Architecture

Cargo workspace, three crates:

- `crates/kasway-db` — sqlx PostgreSQL pool + embedded migrations.
- `crates/kasway-covenant` — the ONLY crate that touches rusty-kaspa or
  assembles covenant script bytes. Live escrow/dispute covenants and the legacy
  `subscription_v1.rs` protocol artifact are compiled by the SilverScript
  compiler (`silverscript_lang`) — there is no hand-assembled opcode anywhere.
  New subscriptions do not use the legacy pre-funded cell. This crate is
  licensed Apache-2.0, unlike the rest of the workspace (AGPL-3.0) — keep
  protocol logic here, server logic out.
- `crates/kasway-api` — axum app. `build_router` in `src/lib.rs` is the
  authoritative endpoint list. Auth is Adonis-compatible (Bearer access
  tokens, `x-kasway-api-key`, internal token for `/internal/*`).

Payment lifecycle across files (the flow you must understand before touching
payments):

1. `kpr1.rs` mints the signed intent: canonical JSON (sorted keys) → Ed25519 →
   SHA-256 canonical hash bound into the `kaspa-payment:` URI. Payment window
   capped at `PAYMENT_WINDOW_SECONDS` (900 s). `compute_split_plan` enforces
   the ordered payout split (merchant_net, tax, ≤5 splits, kasway_fee) and the
   KIP-9 storage-mass floor — tiny payout slices would make the covenant
   unspendable, so they are rejected at mint.
2. Finalize derives the covenant P2SH address from the signed terms plus the
   payer's refund address; `script_hash`/`covenant_address` are unknown at mint.
3. `chain_observer.rs` closes the loop for submitted txids only (no address
   watching): verifies the single covenant funding output (address + exact
   amount), tracks confirmations (virtual DAA − accepting DAA vs
   `payment_tenant_settings`), emits `payment.confirmed` on funding, checkpoints
   in `payment_indexer_checkpoints`.
4. `covenant_keeper.rs` settles funded covenants after the capture window; the
   keeper only ever signs its own fee input.

Five in-process workers start from `main.rs` (webhook delivery, chain observer,
covenant keeper, subscription biller, invoice expirer) — no external queue.
Each has an `*_ENABLED` env gate; see README "Background workers".

Subscriptions are a sequence of ordinary KPR-1 invoices (`subscription_biller.rs`
creates one per due cycle; `invoice_expirer.rs` retires unfunded ones). There is
no pre-funded balance, no autopay keeper, and the old `/autopay/*` routes are
gone. The API still accepts legacy `paymentMode: "wallet_autopay"` input but
stores `recurring_invoice`.

Disputes: evaluator protocol v1 uses signed profiles, quotes, three-party
engagements, encrypted case envelopes, commit-reveal, and the
`EscrowV3`/`DisputeV1` covenant transition. Legacy flows retain bilateral
co-signed settlement or an M-of-N arbiter panel
(`COVENANT_ARBITER_PANEL`/`COVENANT_ARBITER_THRESHOLD`).
`validate_production_arbiter` in `state.rs` refuses to boot a production config
whose panel is empty or contains Kasway's own arbiter key. Dev/test fall back
to a transitional 1-of-1 panel.

## Gotchas

- `KASPA_NODE_URL` must be a Kaspa node's **wRPC JSON** websocket endpoint
  (18110 mainnet / 18210 TN10) — not the Borsh listener (17110/17210). See
  `crates/kasway-api/src/kaspa_wrpc.rs`.
- Contract compatibility is the test suite's job: request/response shapes were
  ported test-first from the original AdonisJS API. Changes to payment or
  settlement logic need a contract/integration test.
- `.env.example` documents every env var; tests don't need a `.env`.
- Default branch is `staging`; `main` receives squash merges from it.
