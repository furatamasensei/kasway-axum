# Kasway Evaluator Protocol v1

Status: implemented draft. The database migration, verifier, HTTP routes, and
`escrow_v3`/`DisputeV1` contracts are normative until a standalone standard is
published.

## Security boundary

All mutable protocol objects are authenticated by a 64-byte BIP-340 signature
over the SHA-256 digest of canonical JSON. Canonical JSON sorts object keys
lexicographically at every depth, preserves array order, and uses UTF-8. Each
payload contains `protocolVersion: "1"`, `network`, and one exact domain:

| Object | Domain |
| --- | --- |
| Evaluator profile | `kasway/evaluator-profile/v1` |
| Quote | `kasway/evaluator-quote/v1` |
| Engagement | `kasway/evaluator-engagement/v1` |
| Case opening | `kasway/dispute-open/v1` |
| Case message | `kasway/case-message/v1` |
| Decision commitment | `kasway/evaluator-decision-commit/v1` |
| Decision reveal | `kasway/evaluator-decision-reveal/v1` |
| Feedback | `kasway/evaluator-feedback/v1` |

The API accepts public profile fields, x-only public keys, hashes, signatures,
ciphertext, and transaction references. It has no field for a seed phrase,
private key, decryption key, legal name, email, telephone number, address, or
identity document.

## Signed envelope and replay protection

Every signed payload carries, in addition to its domain-specific fields:

```json
{
  "domain": "kasway/<name>/v1",
  "protocolVersion": "1",
  "network": "tn10",
  "action": "<see table>",
  "nonce": "<32-byte hex, caller-generated random>",
  "expiresAt": "<RFC3339, later than server time at submission>"
}
```

| Domain | `action` |
| --- | --- |
| `kasway/evaluator-profile/v1` | `publish_profile` |
| `kasway/evaluator-quote/v1` | `issue_quote` |
| `kasway/evaluator-engagement/v1` | `accept_engagement` |
| `kasway/dispute-open/v1` | `open_case` |
| `kasway/case-message/v1` | `negotiation`, `evidence`, `question`, `response`, or `statement` |
| `kasway/evaluator-decision-commit/v1` | `commit_decision` |
| `kasway/evaluator-decision-reveal/v1` | `reveal_decision` |
| `kasway/evaluator-feedback/v1` | `submit_feedback` |

`(signer key, nonce)` is stored in `arbitration_nonces` when the write is
accepted; a payload whose pair already exists is rejected with HTTP 409
`{ "message": "...", "code": "ARBITRATION_NONCE_REPLAY" }`. The engagement
consumes the nonce once per signer (three rows). A request refused by
validation does not spend its nonce.

## Fee fields (quote and engagement)

```
feeSompi      string|int, required, > 0
feePayer      "customer", required
feeBps        int 0..10000, optional
feeCapSompi   string|int, optional, > 0
```

The quote must satisfy `profile.fee.minimumSompi <= feeSompi <=
profile.fee.maximumSompi` (upper bound only when the profile sets one). When
`feeBps` is present, `feeSompi == min(feeCapSompi ?? unbounded,
floor(invoiceGrossSompi * feeBps / 10000))`. Engagement values must equal the
quote values, and the quote must not have expired.

## Engagement terms

The canonical, three-party-signed terms object contains the envelope fields plus:

```
engagementId        string
engagementVersion   int >= 1
invoiceId           string (invoice public id)
orderId             string, optional; must equal the invoice external id when both exist
caseId              string, 1..128 chars; a later dispute MUST open under this id
quoteId, profileId
customerKey, sellerKey, evaluatorKey        32-byte x-only hex
messagingKeys { customer, seller, evaluator }
caseKeyCommitment, policyHash, evidenceFormatHash   32-byte hex
rewardAddress       Schnorr P2PK Kaspa address
disputeDeadline     RFC3339
decisionSlaSeconds  int > 0
feeSompi, feePayer, feeBps?, feeCapSompi?
allowedOutcomes     ["release"] | ["refund"] | ["release","refund"]
backupEvaluatorKey  32-byte hex, optional
```

`engagementHash = SHA-256(canonical(terms))`. `GET
/api/arbitration/engagements/:engagementId` returns the stored terms verbatim
with all three signatures so a wallet can re-verify before funding:

```json
{
  "engagementId": "...",
  "engagementHash": "<64 hex>",
  "status": "accepted|funded|disputed|settled|cancelled|expired",
  "terms": { "...": "exact stored terms object" },
  "customerSignature": "<128 hex>",
  "sellerSignature": "<128 hex>",
  "evaluatorSignature": "<128 hex>"
}
```

## Lifecycle

1. An evaluator publishes a versioned, expiring signed profile.
2. The evaluator issues a signed quote for one open invoice and customer key.
3. Customer, seller, and evaluator sign the same engagement terms. The seller
   key must equal the invoice merchant's Schnorr P2PK key.
4. Finalization verifies that the customer's refund address matches the
   engagement customer key. It compiles `DisputeV1`, commits its script hash
   inside `EscrowV3`, and returns a KPR-signed receipt containing both redeem
   scripts and the exact `gross + evaluator fee` funding amount.
5. The observer verifies that exact output and marks both intent and engagement
   funded.
6. Customer or seller requests two Kaspa sighashes, signs both the covenant
   input and their fee input locally, and submits the dispute transition. The
   original escrow outpoint is consumed, so normal capture is disabled.
7. The opener signs a case-opening payload containing the accepted dispute
   transaction ID and the precommitted dispute address.
8. Participants exchange signed encrypted envelopes. Each envelope references
   the prior envelope hash. Its Kaspa anchor is a separate object so the hash is
   not self-referential.
9. The evaluator commits, then reveals, a binary `release` or `refund` decision.
10. The evaluator and a chosen fee payer sign a deterministic terminal spend.
    `DisputeV1` enforces the exact commercial outcome and fixed evaluator reward.
11. After the transaction is accepted, the case becomes settled and customer
    and seller may each publish one signed rating.

## HTTP routes

| Method and path | Purpose |
| --- | --- |
| `GET/POST /api/arbitration/evaluators` | List or publish evaluator profiles |
| `GET /api/arbitration/evaluators/:profileId` | Profile plus reputation |
| `GET /api/arbitration/evaluators/:profileId/reputation` | Settled-case aggregates |
| `POST /api/arbitration/quotes` | Publish an evaluator-signed quote |
| `POST /api/arbitration/engagements` | Submit all three engagement signatures |
| `GET /api/arbitration/engagements/:id` | Stored terms plus all three signatures |
| `POST /api/arbitration/engagements/:id/dispute/prepare` | Build participant and fee sighashes |
| `POST /api/arbitration/engagements/:id/dispute/submit` | Attach signatures and broadcast transition |
| `POST /api/arbitration/cases` | Publish signed case opening |
| `GET /api/arbitration/cases/:caseId` | Public case state and commitments |
| `GET/POST /api/arbitration/cases/:caseId/messages` | Retrieve or publish ciphertext envelopes |
| `POST /api/arbitration/cases/:caseId/decision/commit` | Store signed decision commitment |
| `POST /api/arbitration/cases/:caseId/decision/reveal` | Verify and store reveal |
| `POST /api/arbitration/cases/:caseId/settlement/prepare` | Build evaluator and fee sighashes |
| `POST /api/arbitration/cases/:caseId/settlement/submit` | Broadcast and record terminal spend |
| `POST /api/arbitration/cases/:caseId/mutual-settlement/prepare` | Customer+seller escape hatch sighashes |
| `POST /api/arbitration/cases/:caseId/mutual-settlement/submit` | Broadcast the co-signed escape hatch |
| `POST /api/arbitration/cases/:caseId/feedback` | Publish one bounded role-specific rating |

### Evaluator listing

`GET /api/arbitration/evaluators?category=&language=&maxFeeSompi=&sort=&order=&limit=&offset=`

`sort` is one of `newest` (default), `fee`, `cases`, `resolution_time`, or
`rating`; `order` is `asc` or `desc` (default `desc`, except `fee` and
`resolution_time` default to `asc`). `limit` defaults to 50 (max 100),
`offset` to 0. `maxFeeSompi` compares against the fixed fee or, for bps
profiles, the minimum fee. Filtering and ordering happen in SQL. Each item is
the profile plus `reputation`; `meta` is `{ limit, offset, count }`.

### Reputation

Served by `GET /api/arbitration/evaluators/:profileId/reputation` and embedded
in the profile show/index responses:

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

`verifiedCases` counts settled cases. `medianResponseSeconds` is the median of
(first evaluator message − case opened) over settled cases, null when the
evaluator never wrote. `medianResolutionSeconds` is the median of (settled −
opened). `slaCompletionRate` is the share of settled cases with `settledAt <=
decisionDueAt`. `outcomes` counts revealed decisions.

### Mutual settlement from a dispute

After the dispute transition, customer and seller may still settle without
the evaluator by co-signing a spend of the `DisputeV1` covenant
(`EP_RELEASE_SETTLED`):

`POST /api/arbitration/cases/:caseId/mutual-settlement/prepare` with
`{ "split": [{ "address": "kaspa:...", "amountSompi": "..." }], "feePayerAddress": "kaspa:..." }`.
The case must be `open`, `committed`, or `revealed`, the intent
`dispute_open`, `sum(split) == gross + evaluatorFee`, and `feePayerAddress`
a Schnorr P2PK address holding a fee UTXO. Response:
`{ caseId, covenantSighash, feeSighash, feePayerAddress, totalSompi, sigHashType: "SIG_HASH_ALL", algorithm: "schnorr" }`.

`POST /api/arbitration/cases/:caseId/mutual-settlement/submit` takes the same
body plus `customerSignature`, `sellerSignature`, and `feeSignature` (65-byte
hex each). On success the case is `settled` (`settlementTxId`, `settledAt`),
the engagement `settled`, the intent `covenant_state = settled_mutual`, the
invoice `paid`, and `invoice.paid` is emitted. Response:
`{ caseId, state: "settled", resolution: "mutual", settlementTxId }`.

## Message envelope and anchor

The signed message payload includes the envelope (`action` is the message
kind, `expiresAt` is required) plus `messageId`, `caseId`, `participantRole`,
`senderKey`, `sequence`, `previousMessageHash`, `payloadHash`, `ciphertext`,
and `createdAt`. The request wraps it as:

```json
{
  "payload": { "domain": "kasway/case-message/v1", "ciphertext": "…" },
  "signature": "<64-byte BIP-340 hex>",
  "anchor": {
    "chainTxId": "<32-byte transaction ID hex>",
    "commitment": "<SHA-256 of canonical signed payload>"
  }
}
```

The current backend validates the commitment equality and stores
`anchorStatus: "submitted"`. It does not yet retrieve the historical transaction
payload independently. Consumers must not treat `submitted` as on-chain proof.

## Decision commitment

The commitment is SHA-256 over this canonical object:

```json
{
  "domain": "kasway/evaluator-decision/v1",
  "protocolVersion": "1",
  "network": "tn10",
  "engagementHash": "<32-byte hex>",
  "caseId": "<case id>",
  "outcome": "release",
  "reasonHash": "<32-byte hex>",
  "salt": "<32-byte hex>"
}
```

The API verifies commit/reveal consistency. The terminal covenant verifies the
evaluator's Kaspa transaction signature and exact outputs, but cannot inspect a
prior transaction payload. This distinction is intentional and must remain
visible in client copy and audits.

## Known incomplete work

- independent observation of message and decision anchors;
- cross-language canonical payload vectors;
- wallet UI and lifecycle recovery for case messaging keys;
- backup evaluator rotation, appeals, bonds, and blind feedback;
- complete TN10 evidence and external security review.
