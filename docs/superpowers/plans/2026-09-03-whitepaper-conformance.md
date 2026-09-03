# Whitepaper Conformance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan workstream-by-workstream. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Kasway implementation match every claim in `docs/WHITEPAPER.md` v0.4 that the whitepaper presents as implemented, and fix the three funds/verification bugs found in the 2026-09-03 audit.

**Architecture:** Three independent workstreams. (A) backend payment path in `kasway-axum`, (B) backend evaluator/arbitration protocol in `kasway-axum`, (C) wallet verification + subscription mandate in `kasway-mobile/src/wallet-shared` (submodule) and the `kasway-mobile` shell. A and B touch disjoint files except `lib.rs` (routes) and `docs/`. C consumes the HTTP contracts defined in B ("Interfaces" below) and does not need B to be finished to compile.

**Tech Stack:** Rust 2021 / axum / sqlx PostgreSQL / `kasway-covenant` (rusty-kaspa v2.0.1, SilverScript); TypeScript / Vue 3 / Ionic / Capacitor / vitest; new wallet dependency `@noble/curves` (only new dependency in the whole plan).

## Global Constraints

- Trust invariants from `CLAUDE.md`: no custody, fail closed, covenant-only settlement, everything the payer consents to rides inside the Ed25519 signature.
- No hand-assembled opcodes in `kasway-covenant`. No covenant script changes in this plan.
- Every payment/settlement logic change needs a contract or integration test (`crates/kasway-api/tests/`).
- Backend integration tests need PostgreSQL via `DATABASE_URL` (see "Verification").
- Wallet: never run `pnpm install` inside `src/wallet-shared`. Tests: `cd src/wallet-shared && ../../node_modules/.bin/vitest run`. Typecheck: `node_modules/.bin/vue-tsc --noEmit` from `kasway-mobile`.
- Do not commit. The owner commits.
- Canonical JSON everywhere = UTF-8, object keys sorted lexicographically at every depth, no whitespace (`serde_json::to_string` on the Rust side, `canonicalizeKpr1Json` on the wallet side).

---

## Interfaces (contracts shared across workstreams)

### I-1 Signed arbitration payload envelope (all domains)

Every signed payload MUST contain, in addition to its domain-specific fields:

```json
{
  "domain": "kasway/<name>/v1",
  "protocolVersion": "1",
  "network": "tn10" | "mainnet",
  "action": "<action string, see table>",
  "nonce": "<32-byte hex, caller-generated random>",
  "expiresAt": "<RFC3339, must be later than server time at submission>"
}
```

| domain | action |
| --- | --- |
| `kasway/evaluator-profile/v1` | `publish_profile` |
| `kasway/evaluator-quote/v1` | `issue_quote` |
| `kasway/evaluator-engagement/v1` | `accept_engagement` |
| `kasway/dispute-open/v1` | `open_case` |
| `kasway/case-message/v1` | one of `negotiation`, `evidence`, `question`, `response`, `statement` |
| `kasway/evaluator-decision-commit/v1` | `commit_decision` |
| `kasway/evaluator-decision-reveal/v1` | `reveal_decision` |
| `kasway/evaluator-feedback/v1` | `submit_feedback` |

Replay protection: table `arbitration_nonces(signer_key TEXT, nonce TEXT, created_at TEXT, PRIMARY KEY (signer_key, nonce))`. A payload whose `(signer_key, nonce)` already exists is rejected with HTTP 409 `{"code":"ARBITRATION_NONCE_REPLAY"}`. The engagement consumes the nonce once per signer (three rows).

Signature: 64-byte BIP-340 Schnorr over `SHA-256(canonical(payload))`, hex. Unchanged.

### I-2 Quote and engagement fee fields

Quote payload and engagement terms both carry:

```
feeSompi      string|int, required, > 0
feePayer      "customer", required
feeBps        int 0..10000, optional
feeCapSompi   string|int, optional, > 0
```

Validation (backend): if `feeBps` present, `feeSompi == min(feeCapSompi ?? u64::MAX, floor(invoiceGrossSompi * feeBps / 10000))`. Always: `profile.minimum_fee_sompi <= feeSompi <= profile.maximum_fee_sompi` (upper bound only when the profile sets one). Engagement values must equal the quote values.

### I-3 Engagement terms (canonical, three-party signed)

```
domain, protocolVersion, network, action, nonce, expiresAt   (I-1)
engagementId        string
engagementVersion   int >= 1
invoiceId           string (invoice public id)
orderId             string, optional; when present AND the invoice has external_id, must equal it
caseId              string, 1..128 chars; the case that a later dispute MUST open under
quoteId, profileId
customerKey, sellerKey, evaluatorKey        32-byte x-only hex
messagingKeys { customer, seller, evaluator }
caseKeyCommitment, policyHash, evidenceFormatHash   32-byte hex
rewardAddress       Schnorr P2PK Kaspa address
disputeDeadline     RFC3339
decisionSlaSeconds  int > 0
feeSompi, feePayer, feeBps?, feeCapSompi?   (I-2)
allowedOutcomes     ["release"] | ["refund"] | ["release","refund"]
backupEvaluatorKey  32-byte hex, optional
```

`engagementHash = SHA-256(canonical(terms))` hex.

### I-4 `GET /api/arbitration/engagements/:engagementId`

```json
{
  "engagementId": "...",
  "engagementHash": "<64 hex>",
  "status": "accepted|funded|disputed|settled|cancelled|expired",
  "terms": { ...exact stored terms object... },
  "customerSignature": "<128 hex>",
  "sellerSignature": "<128 hex>",
  "evaluatorSignature": "<128 hex>"
}
```

404 when unknown. Public, unauthenticated.

### I-5 Mutual settlement from a dispute (escape hatch)

`POST /api/arbitration/cases/:caseId/mutual-settlement/prepare`
Body: `{ "split": [{ "address": "kaspa:...", "amountSompi": "..." }], "feePayerAddress": "kaspa:..." }`
Preconditions: case `state IN ('open','committed','revealed')`, intent `covenant_state = 'dispute_open'`, `sum(split) == gross + evaluatorFee`, `feePayerAddress` is Schnorr P2PK and has a fee UTXO.
Response: `{ "caseId", "covenantSighash", "feeSighash", "feePayerAddress", "totalSompi", "sigHashType": "SIG_HASH_ALL", "algorithm": "schnorr" }`

`POST /api/arbitration/cases/:caseId/mutual-settlement/submit`
Body: prepare body plus `customerSignature`, `sellerSignature`, `feeSignature` (65-byte hex each).
Effect on success: `dispute_cases.state='settled'`, `settlement_tx_id`, `settled_at`; `evaluator_engagements.status='settled'`; `kpr1_payment_intents.covenant_state='settled_mutual'`, `status='settled'`, `release_tx_id`; `invoices.status='paid'`; webhook `invoice.paid`.
Response: `{ "caseId", "state": "settled", "resolution": "mutual", "settlementTxId" }`

### I-6 Evaluator registry listing

`GET /api/arbitration/evaluators?category=&language=&maxFeeSompi=&sort=newest|fee|cases|resolution_time|rating&order=asc|desc&limit=&offset=`

Defaults: `sort=newest`, `order=desc` (for `fee` and `resolution_time` the default order is `asc`), `limit=50` (max 100), `offset=0`. All filtering and ordering happens in SQL. Each item = profile JSON + `"reputation": <I-7 object>`. `meta: { limit, offset, count }`.

### I-7 Reputation object

```json
{
  "verifiedCases": 0,
  "ratings": 0,
  "customerAverage": null,
  "sellerAverage": null,
  "medianResponseSeconds": null,
  "medianResolutionSeconds": null,
  "slaCompletionRate": null,
  "outcomes": { "release": 0, "refund": 0 }
}
```

Definitions: `verifiedCases` = settled cases for the profile. `medianResponseSeconds` = median over settled cases of (first `dispute_messages` row with `participant_role='evaluator'`).created_at − case.opened_at; null when no evaluator message. `medianResolutionSeconds` = median of settled_at − opened_at. `slaCompletionRate` = settled cases with `settled_at <= decision_due_at` / settled cases. `outcomes` counts `decision_outcome`. Served by `GET /api/arbitration/evaluators/:profileId/reputation` and embedded in show/index.

### I-8 `GET /api/kpr1/signing-keys`

```json
{ "keys": [ { "keyId": "<cfg.signing_key_id>", "alg": "ed25519", "publicKey": "<base64 raw 32 bytes>", "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n<base64 SPKI>\n-----END PUBLIC KEY-----" } ] }
```

SPKI DER = `302a300506032b6570032100` ‖ raw 32 bytes.

### I-9 Webhooks

- `payment.confirmed` emitted by the chain observer when an intent becomes `funded` (payload = serialized invoice + `txId` + `confirmations`). Resource type `invoice`.
- `invoice.paid` / `invoice.refunded` emitted by evaluator settlement and mutual dispute settlement.

### I-10 KPR-1 intent output `percentage`

Split outputs serialize `percentage` as a JSON number that JavaScript's `JSON.stringify` reproduces byte-for-byte: integer when `bps % 100 == 0` (`10`), otherwise the shortest decimal (`2.5`, `0.01`). Never `10.0`.

---

## Workstream A — Backend payment path (`kasway-axum`)

**Files:**
- Modify: `crates/kasway-api/src/kpr1.rs` (`outputs_json` ~L376-392; `create_for_invoice` ~L569-576)
- Modify: `crates/kasway-api/src/handlers/invoices.rs` (~L902-910 `expires_at`)
- Modify: `crates/kasway-api/src/handlers/subscriptions.rs` (~L416-471; pass plan `invoice_expires_after_seconds` as `expiresAt` when set and < 900)
- Modify: `crates/kasway-api/src/chain_observer.rs` (`Candidate` L109-124 add `store_id`; funding check L211-238; `mark_funded` L371-388; header comment L17-23)
- Modify: `crates/kasway-api/src/covenant_keeper.rs` (header L1-12; `evaluator_settlement_submit` L896-965 emit webhooks)
- Modify: `crates/kasway-api/src/invoice_expirer.rs` (add `INVOICE_EXPIRER_ENABLED` gate like `subscription_biller.rs:30-35`)
- Modify: `crates/kasway-api/src/main.rs` (L39-41 comment, L58 gate)
- Modify: `crates/kasway-api/src/handlers/explorer_kpr1.rs:305` (`signaturePayloadRule`)
- Create: `crates/kasway-api/src/handlers/kpr1_keys.rs` + route in `lib.rs`
- Modify: `CLAUDE.md` (worker gate sentence), `README.md` (observer wording L137-146; add signing-keys endpoint; add `payment.confirmed`)
- Tests: `crates/kasway-api/src/kpr1.rs` unit test; `tests/chain_observer_test.rs`; `tests/invoices_create_test.rs`; new `tests/kpr1_signing_keys_test.rs`; `tests/webhook_delivery_test.rs` or `chain_observer_test.rs` for `payment.confirmed`

### Task A1: `percentage` canonicalization (I-10)
- [ ] Unit test in `kpr1.rs`: build a `SplitPlan` with a 10% split and a 2.5% split; assert `canonicalize(&outputs_json)` contains `"percentage":10` and `"percentage":2.5` and not `10.0`.
- [ ] Implement: derive from bps (`if bps % 100 == 0 { json!(bps / 100) } else { json!(bps as f64 / 100.0) }`). Keep the `SplitOut.percentage` field if other code reads it, but the JSON must come from bps.
- [ ] Run `cargo test -p kasway-api --lib kpr1`.

### Task A2: observer requires exactly one covenant output
- [ ] Test in `tests/chain_observer_test.rs`: a fake chain source returns a tx with two outputs to the covenant address that sum to gross. Expect intent `verification_status='failed'`, `failure_reason='covenant_output_count'`, one `payment_anomaly_signals` row with kind `kpr1_output_mismatch`, invoice still `open`.
- [ ] Implement in `chain_observer.rs`: collect outputs to the covenant address; if count != 1 → `fail_intent(..., "covenant_output_count", ...)` + anomaly; else compare the single value to `expected` as today.
- [ ] Update the module header (L17-23): funded keeps the invoice open; the keeper auto-captures to the merchant after the capture window (no auto-refund).

### Task A3: shorter payment window honored
- [ ] Test in `tests/invoices_create_test.rs`: `expiresAt = now + 300s` → intent/invoice `expiresAt` within ±5 s of the request; `expiresAt = now + 3600s` → clamped to now + 900 s; `expiresAt` in the past → 422 `expiresAt must be in the future`.
- [ ] Implement in `handlers/invoices.rs`: parse; reject past; `expires_at = min(requested, now + PAYMENT_WINDOW_SECONDS)`. Update the comment. `kpr1::create_for_invoice` already clamps.
- [ ] Subscription biller: if the plan's `invoice_expires_after_seconds` is `Some(s)` with `0 < s < 900`, pass `expiresAt = now + s` in the invoice body; otherwise omit.

### Task A4: signing-keys endpoint (I-8)
- [ ] Test `tests/kpr1_signing_keys_test.rs`: GET returns one key whose `keyId` equals the test config key id, `publicKey` decodes to 32 bytes, `publicKeyPem` starts with `-----BEGIN PUBLIC KEY-----`; verify a freshly minted intent's signature with that raw key using the same ed25519 crate the server uses.
- [ ] Implement `handlers/kpr1_keys.rs::index`, route `GET /api/kpr1/signing-keys` in the unauthenticated section of `lib.rs`. Reuse `kpr1::signing_public_key_b64` (L140).

### Task A5: explorer metadata + webhooks + expirer gate + stale docs
- [ ] `explorer_kpr1.rs:305`: `"signaturePayloadRule": "sign_canonical_unsigned_intent"`, add `"canonicalization": "json_sorted_keys_utf8"`. Update the assertion in `tests/explorer_kpr1_test.rs` if it checks the old string.
- [ ] `chain_observer.rs`: add `store_id` (from `invoices.store_id`) to `Candidate` and its query; in the `funded` branch after `mark_funded`, call `crate::handlers::webhooks::emit_event(state, c.user_id, c.store_id, "payment.confirmed", "invoice", &c.public_id, &payload)` where payload = serialized invoice (see `covenant_keeper::invoice_payload`) plus `txId` and `confirmations`. Delivery failure is logged, never fails the tick. Test: after a funded tick, one `webhook_events` row with `event_type='payment.confirmed'`.
- [ ] `covenant_keeper.rs::evaluator_settlement_submit`: after the DB commit, `emit_invoice_event(..., "invoice.paid" | "invoice.refunded", &tx_id)`.
- [ ] `invoice_expirer.rs`: `INVOICE_EXPIRER_ENABLED` gate (default on; `0/false/off` case-insensitive disables), used in `main.rs`. Make the keeper gate parsing case-insensitive too (`covenant_keeper.rs:112`).
- [ ] Stale comments: `covenant_keeper.rs:1-12`, `main.rs:39-41`.
- [ ] `CLAUDE.md`: worker gate sentence now true. `README.md`: observer verifies "the single covenant funding output (address + exact amount)"; document `GET /api/kpr1/signing-keys`; add `payment.confirmed` and `INVOICE_EXPIRER_ENABLED` to the workers section.
- [ ] `cargo check --workspace`, then `cargo test -p kasway-api`.

---

## Workstream B — Backend arbitration protocol (`kasway-axum`)

**Files:**
- Modify: `crates/kasway-api/src/arbitration.rs` (whole file)
- Modify: `crates/kasway-api/src/covenant_keeper.rs` (add `dispute_mutual_settle_prepare` / `dispute_mutual_settle_submit` next to `evaluator_settlement_*` ~L868-965)
- Modify: `crates/kasway-api/src/lib.rs` (routes)
- Create: `crates/kasway-db/migrations/0019_arbitration_v1_1.sql`
- Create: `crates/kasway-api/tests/arbitration_test.rs`
- Modify: `docs/ARBITRATION_PROTOCOL_V1.md`

### Task B1: migration 0019
- [ ] `arbitration_nonces` table (I-1).
- [ ] `evaluator_quotes` add `fee_bps BIGINT`, `fee_cap_sompi BIGINT`.
- [ ] `evaluator_engagements` add `engagement_version BIGINT NOT NULL DEFAULT 1`, `order_id TEXT`, `case_id TEXT UNIQUE`, `fee_bps BIGINT`, `fee_cap_sompi BIGINT`.
- [ ] `kpr1_payment_intents` `covenant_state` accepts `settled_mutual` if a CHECK constraint exists (grep migrations 0015/0018; add only if constrained).

### Task B2: envelope validation (I-1)
- [ ] `verify_payload` gains `expected_action: ActionRule` (`Exact(&str)` or `OneOf(&[&str])`), validates `action`, `nonce` (32-byte hex), `expiresAt` (RFC3339 > now). Returns `(payload_hash_hex, nonce)`.
- [ ] `async fn consume_nonce(executor, signer_key, nonce) -> AppResult<()>` inserting into `arbitration_nonces`; unique violation → `AppError::commerce(409, ...)` with code `ARBITRATION_NONCE_REPLAY` (follow how other handlers attach codes; if `AppError` has no code field, put the code in the message and the test asserts on 409).
- [ ] Every handler calls `consume_nonce` inside its transaction (or immediately after verify when there is no transaction). Engagement: once per signer.
- [ ] Message `expiresAt` becomes required.
- [ ] Unit test: `verify_payload` rejects a payload missing `nonce`, with wrong `action`, or with past `expiresAt`.

### Task B3: quote and engagement fields (I-2, I-3)
- [ ] `quote_store`: validate I-2 against the profile row (`fee_kind`, `fee_value`, `minimum_fee_sompi`, `maximum_fee_sompi`) and the invoice gross (`kpr1_payment_intents.gross_amount` for the invoice). Store `fee_bps`, `fee_cap_sompi`.
- [ ] `engagement_store`: require `engagementVersion >= 1`, `caseId` (1..128), optional `orderId` (must equal `invoices.external_id` when both present); fee fields equal the quote; reject when `quote.expires_at <= now` (422 `evaluator quote has expired`); store new columns.
- [ ] `case_open`: `payload.caseId` must equal `evaluator_engagements.case_id` (422 `caseId does not match the signed engagement`).
- [ ] `engagement_show` handler for I-4; route `GET /api/arbitration/engagements/:engagementId`.

### Task B4: mutual settlement from dispute (I-5)
- [ ] In `covenant_keeper.rs`: `gather_v3_dispute_mutual(state, client, case_id, fee_payer_address, split)` loading the case (`state IN ('open','committed','revealed')`), `load_v3_engagement(..., &["dispute_open"])`, `rebuild_v3`, dispute UTXO `== gross + fee`, fee UTXO; parse split into `Vec<(Destination, u64)>` summing to `gross + fee`.
- [ ] `dispute_mutual_settle_prepare` → `escrow_v3::prepare_dispute_settlement`, response per I-5.
- [ ] `dispute_mutual_settle_submit`: claim case `state='settling'` + intent `covenant_state='dispute_settling'` in one transaction (like `evaluator_settlement_submit`), build + `complete_dispute_settlement`, submit, then finalize DB state per I-5 and emit `invoice.paid`; on error restore both states.
- [ ] Handlers in `arbitration.rs` + two routes in `lib.rs`.

### Task B5: registry listing + reputation (I-6, I-7)
- [ ] `ListQuery` gains `max_fee_sompi`, `sort`, `order`, `offset`. Invalid `sort`/`order` → 422.
- [ ] One SQL query: profiles LEFT JOIN a CTE `rep` computing I-7 per `profile_id` (`percentile_cont(0.5) WITHIN GROUP`, timestamps cast `::timestamptz`), filters via `categories::jsonb ? $1`, `languages::jsonb ? $2`, `minimum_fee_sompi <= $max` (fee filter uses `CASE fee_kind WHEN 'fixed' THEN fee_value ELSE minimum_fee_sompi END`), ORDER BY per `sort` (`fee` → same CASE expression; `cases` → `verified_cases`; `resolution_time` → `median_resolution_seconds NULLS LAST`; `rating` → `COALESCE(customer_average, 0) + COALESCE(seller_average, 0)`; `newest` → `created_at`), then LIMIT/OFFSET.
- [ ] `reputation_value` returns I-7 (reuse the CTE for one profile).

### Task B6: integration test `tests/arbitration_test.rs`
Use `kasway_covenant::KeeperKey::from_secret_bytes` to make three keys (customer, seller, evaluator), `x_only_pubkey()` for keys, `sign_datasig(&sha256(canonical))` for signatures. Seed a merchant with setup whose payout address is the seller key's Schnorr P2PK address (see `tests/common/mod.rs::merchant_with_setup_at`) and an open invoice with a minted KPR-1 intent (POST `/api/commerce/invoices`).
- [ ] publish profile (200); list evaluators shows it with `reputation.verifiedCases == 0`.
- [ ] replay the same profile payload+signature → 409.
- [ ] quote with `feeSompi` below `minimumSompi` → 422; valid quote → 200.
- [ ] quote with `expiresAt` 1 s ahead; sleep 1.5 s; engagement → 422 `expired`.
- [ ] fresh quote; engagement with three signatures → 200; GET engagement returns terms + signatures and `engagementHash == sha256(canonical(terms))`.
- [ ] engagement missing `caseId` → 422.
- [ ] Seed DB: `evaluator_engagements.status='funded'`, `kpr1_payment_intents.covenant_state='dispute_submitted'`, `dispute_covenant_address='kaspatest:...'` (any string). case_open with the engagement `caseId` → 200; with another caseId → 422.
- [ ] message #0 (`previousMessageHash` absent, `action="statement"`, anchor commitment = envelope hash) → 200 `anchorStatus=submitted`; message #1 with wrong `previousMessageHash` → 409; message with `action="bogus"` → 422.
- [ ] commit → reveal with matching preimage → 200; reveal with wrong salt → 422.
- [ ] Seed `dispute_cases.state='settled'`, `settled_at`, `decision_outcome='release'`; feedback by customer score 5 → 200; second customer feedback → 409/422; reputation: `verifiedCases=1`, `outcomes.release=1`, `customerAverage=5`, `medianResolutionSeconds` not null.
- [ ] list with `sort=rating&order=desc` returns the profile first; `maxFeeSompi=1` returns empty.
- [ ] mutual-settlement prepare on a case whose intent is not `dispute_open` → 4xx (chain not required for the precondition failure).

### Task B7: `docs/ARBITRATION_PROTOCOL_V1.md`
- [ ] Document I-1..I-7 (envelope fields, action table, nonce replay, fee fields, engagement fields, GET engagement, mutual settlement routes, listing params, reputation fields). Remove "cross-language canonical payload vectors" from known incomplete only if vectors were added (they were not; keep it).

---

## Workstream C — Wallet (`kasway-mobile` + `src/wallet-shared` + `src/wallet-shared/core`)

**Files (core = `src/wallet-shared/core/src`, shared = `src/wallet-shared/src`, shell = `kasway-mobile/src`):**
- Modify: `core/types.ts`, `core/validate_outputs.ts`, `core/verify_request.ts`, `core/validate_intent.ts`, `core/index.ts`, `core/kpr1.spec.ts`
- Create: `core/engagement.ts`, `core/engagement.spec.ts`
- Modify: `shared/core/kaspa_address.ts` (add `schnorrPubkeyFromAddress`), `shared/core/payment_service.ts`, `shared/core/subscription_service.ts`, `shared/core/api/arbitration_client.ts`, `shared/core/api/checkout_client.ts`, `shared/core/kasway_wallet.ts` (`SubscriptionEntry`), `shared/facade/types.ts`, `shared/facade/wallet_facade.ts`, `shared/ui/views/SubscriptionDetailView.vue`, `shared/ui/views/ReviewView.vue`
- Modify: `shell/shell/mobile_facade.ts`, `shell/main.ts` (only if needed), `kasway-mobile/README.md`
- Add dependency: `@noble/curves` in `src/wallet-shared/core/package.json` and `kasway-mobile/package.json` (install from `kasway-mobile` root with `pnpm add @noble/curves` — NOT inside the submodule)
- Tests: `core/kpr1.spec.ts`, `core/engagement.spec.ts`, `shared/core/subscription_service.spec.ts`, `shared/core/kasway_wallet_subscriptions.spec.ts`

### Task C1: intent output verification (whitepaper A.2 step 4)
- [ ] `core/types.ts`: `Kpr1Intent.grossSompi: string`; `template: { id: string; version: string; kind?: string; status?: string }` (drop `scriptHash`); `Kpr1Output` add `identifier?: string; percentage?: number`. New codes: `outputs_sum_mismatch`, `amount_gross_mismatch`, `invalid_output_order`, `missing_gross`. Drop `script_hash_mismatch` and `missing_required_${string}_output`.
- [ ] `core/validate_outputs.ts`: `validateOutputs(intent)`: `grossSompi` present and numeric else `missing_gross`; `sum(outputs.amountSompi) === grossSompi` else `outputs_sum_mismatch`; `amountSompi === grossSompi` else `amount_gross_mismatch`; first output role `merchant_net` and last `kasway_fee` else `invalid_output_order`.
- [ ] `core/validate_intent.ts`: template accepted only when `id==='split_settlement' && version==='v1' && (kind === undefined || kind === 'refund_window_covenant')`.
- [ ] `core/verify_request.ts`: drop `candidateOutputs`/`scriptHash` params; call `validateOutputs`.
- [ ] Tests in `kpr1.spec.ts`: sum mismatch, gross/amount mismatch, order, happy path with a split output whose `percentage` is a JSON number.

### Task C2: engagement verification (`core/engagement.ts`)
- [ ] `pnpm add @noble/curves` from `kasway-mobile`; add the same version to `core/package.json` dependencies (do not run install in the submodule).
- [ ] `export interface EngagementTerms` (I-3 shape, loosely typed `Record<string, unknown>` plus the fields read). `export interface EngagementRecord { engagementId; engagementHash; status; terms; customerSignature; sellerSignature; evaluatorSignature }` (I-4).
- [ ] `export const verifyEngagement = async (record, expected: { engagementHash: string; invoiceId: string; feeSompi: string; customerKey: string; sellerKey: string; network: string }, now = Date.now()): Promise<{ ok: boolean; codes: EngagementCode[] }>` with codes `engagement_hash_mismatch | engagement_invoice_mismatch | engagement_fee_mismatch | engagement_customer_key_mismatch | engagement_seller_key_mismatch | engagement_network_mismatch | engagement_expired | engagement_signature_invalid | engagement_domain_invalid`. Hash = SHA-256 over `canonicalizeKpr1Json(terms)` (reuse `core/hash.ts` sha256). Signatures via `schnorr.verify(sigBytes, hashBytes, pubkeyBytes)` from `@noble/curves/secp256k1.js`, all three must pass. Domain must be `kasway/evaluator-engagement/v1`, `action` `accept_engagement`, `feePayer` `customer`.
- [ ] `core/engagement.spec.ts`: generate three keys with `schnorr.utils.randomSecretKey()`/`schnorr.getPublicKey`, sign a canonical terms hash, assert ok; flip one signature → `engagement_signature_invalid`; change `feeSompi` in expected → `engagement_fee_mismatch`; expired → `engagement_expired`.
- [ ] `shared/core/kaspa_address.ts`: `export const schnorrPubkeyFromAddress = (address: string): string | null` (cashaddr decode: prefix, 5-bit groups, checksum, version byte 0 = P2PK Schnorr with 32-byte payload → lowercase hex; otherwise null). Unit test with a known TN10 P2PK address round-trip through the existing encoder.

### Task C3: `PaymentService` guards and engagement check
- [ ] `ArbitrationClient.engagement(engagementId): Promise<EngagementRecord>` (GET I-4).
- [ ] `PaymentService` constructor: 5th optional param `arbitration?: ArbitrationClient`.
- [ ] `export type ProtectionTerms = { profileId: string; evaluatorKey: string; policyHash: string; feeSompi: string; rewardAddress: string }`.
- [ ] `export type PayGuards = { expectedAmountSompi?: string; expectedProtection?: ProtectionTerms | null }` (`null` = mandate has no protection, so any escrow_v3 cycle needs approval; `undefined` = no check).
- [ ] `export class Kpr1GuardError extends Error { code: 'needs_approval'; details: { amountSompi: string; protection: ProtectionTerms | null } }`.
- [ ] `payCovenant(uri, refundAddress, fetchedIntent?, options?: { guards?: PayGuards; onBeforeBroadcast?: () => Promise<void> }): Promise<{ txId; covenantAddress; amountSompi: string; protection: ProtectionTerms | null }>`.
  Order inside: verify → `canSign` → finalize → `assertOwnCovenant` (now also: v2 `covenant.amountSompi === intent.grossSompi`; v3 `protocol.commercialGrossSompi === intent.grossSompi`) → if v3: require `this.arbitration` (else throw `Evaluator-protected invoices cannot be verified in this wallet`), fetch engagement, `verifyEngagement` with `customerKey = schnorrPubkeyFromAddress(refundAddress)`, `sellerKey = schnorrPubkeyFromAddress(merchant_net output address)`, `feeSompi = protocol.evaluatorFeeSompi`, `engagementHash = protocol.engagementHash`; throw on failure listing codes → build `protection` from terms → guards: amount (`covenant.amountSompi !== expectedAmountSompi`) and protection (deep-equal or null rule) → throw `Kpr1GuardError` → `await options.onBeforeBroadcast?.()` → `signer.payToCovenant` → submit → return.
- [ ] Tests in a new `shared/core/payment_service.spec.ts` (fake fetch/checkout/signer): guard failure throws before `payToCovenant` is called; `onBeforeBroadcast` runs after finalize and before `payToCovenant`; v3 without arbitration client throws before signing.

### Task C4: subscription mandate + auto-renew semantics
- [ ] `SubscriptionEntry` (shared/core/kasway_wallet.ts) add `mandateAmountSompi: bigint`, `protection: ProtectionTerms | null`, `pendingApproval: { invoiceId: string; amountSompi: string; previousAmountSompi: string | null; protectionChanged: boolean; noticedAt: string } | null`. Stored form uses strings. Loading an old entry without `mandateAmountSompi` uses `amountSompi`; missing `protection`/`pendingApproval` → null.
- [ ] `SubscriptionSummary` (facade/types.ts) mirrors with strings. `SaveSubscriptionMandateInput` add `protection?: ProtectionTerms | null`. `SubscriptionAutoRenewResult` becomes `{ kind: 'paid'; ...existing fields } | { kind: 'needs_approval'; subscriptionId; invoiceId; amountSompi; previousAmountSompi: string | null; protectionChanged: boolean }`.
- [ ] `SubscriptionService.autoRenew(subscriptionId, refundAddress, options: { expectedAmountSompi: string; expectedProtection: ProtectionTerms | null; onBeforeBroadcast: () => Promise<void> })` returns `AutoRenewOutcome = { kind: 'paid'; payment: AutoRenewPayment } | { kind: 'needs_approval'; invoiceId; amountSompi; previousAmountSompi: string | null; protectionChanged: boolean } | { kind: 'skipped' }`. It catches `Kpr1GuardError` only; other errors propagate.
- [ ] `mobile_facade.ts::runSubscriptionAutoRenewals`:
  - skip when the shell network is mainnet and mainnet release is not ready (reuse the same source of truth as the UI's `writesBlocked`; if it lives only in `shared/ui/app/network.ts`, move the flag into `shared/core` or the facade so the facade can read it without importing UI).
  - per entry: fetch status; skip when no open invoice, or `invoice.publicId === entry.lastInvoiceId`, or `entry.pendingApproval?.invoiceId === invoice.publicId`.
  - call `autoRenew` with `expectedAmountSompi = entry.mandateAmountSompi.toString()`, `expectedProtection = entry.protection`, `onBeforeBroadcast = () => syncSubscription(status, true, { lastInvoiceId: invoice.publicId })`.
  - `needs_approval` → `syncSubscription(status, true, { pendingApproval: {...} })`, push the result.
  - `paid` → existing `recordKprPayment` + sync with `lastInvoiceId`, `lastPaidAmountSompi`, `lastPaymentAt` (mandate unchanged).
  - errors: `console.warn` with subscription id; do NOT persist `lastInvoiceId` (the hook did not run).
- [ ] `saveSubscriptionMandate`: set `mandateAmountSompi = paidAmountSompi` when given, `protection` from input, clear `pendingApproval` when its `invoiceId === paidInvoiceId`, set `priceChangeNotice` when the previous mandate amount differs.
- [ ] `facade.payKpr1` (or whatever ReviewView calls to pay) returns `protection` so ReviewView can pass it to `saveSubscriptionMandate`.
- [ ] `SubscriptionDetailView.vue`: when `entry.pendingApproval` → banner "New price {amount} (was {previous}). Auto-renew paused for this cycle." (+ "Evaluator terms changed." when `protectionChanged`) and a "Review and pay" button that opens the existing review flow with `status.paymentRequestUri` (find how `QrScanView` navigates to `ReviewView` and reuse it). Replace the "The wallet paid the new signed price" copy with "You approved the new price on {noticedAt}".
- [ ] Tests: `subscription_service.spec.ts` (needs_approval path, paid path calls `onBeforeBroadcast`), `kasway_wallet_subscriptions.spec.ts` (old stored entry migrates; pendingApproval persists).
- [ ] `kasway-mobile/README.md` "Subscription auto-renew": describe the stop-and-approve rule and the before-broadcast record.
- [ ] Run `node_modules/.bin/vue-tsc --noEmit` from `kasway-mobile` and `cd src/wallet-shared && ../../node_modules/.bin/vitest run`.

---

## Workstream D — Whitepaper (after A, B, C)

**Files:** `docs/WHITEPAPER.md` (regenerate `WHITEPAPER.pdf` only if the repo has a script for it; otherwise leave the PDF and note it in the report).
- [ ] Sec 6.2: engagement field list = I-3 (order id optional, case id, fee amount with optional percentage/cap, payer, engagement version, expiry); payload includes `action`, `nonce`, `expiresAt`; nonce replay stored by signer.
- [ ] Sec 7 envelope: `network` (not `networkId`); `action` values from I-1.
- [ ] Sec 8: `decisionCommit = SHA-256(canonical({domain:"kasway/evaluator-decision/v1", protocolVersion, network, engagementHash, caseId, outcome, reasonHash, salt}))`.
- [ ] Sec 6.4: escape hatch now has an API route (I-5).
- [ ] Sec 9: implemented metrics = I-7; category history remains future.
- [ ] Sec 10: auto-renew pauses and requests approval when the amount or evaluator terms differ from the approved mandate.
- [ ] Sec 13: add to implemented: wallet output-sum and gross checks, wallet engagement verification, mutual settlement route, registry sort/filter, reputation metrics, nonce/expiry replay protection, `payment.confirmed` webhook, published signing keys. Remove nothing from the incomplete list except items now done.
- [ ] Sec 14/A.2 unchanged.

## Verification

- PostgreSQL for backend tests: `docker run -d --name kasway-test-pg -e POSTGRES_PASSWORD=postgres -p 5433:5432 postgres:16` then `DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5433/postgres cargo test -p kasway-api` (the harness creates disposable `kasway_test_*` databases).
- `cargo test --workspace` green.
- Wallet: `vue-tsc --noEmit` clean; vitest green (existing 35 + new).
- `pnpm ios:device` from `kasway-mobile` (repo rule) when a device is attached; otherwise report.
