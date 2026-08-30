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
| `POST /api/arbitration/engagements/:id/dispute/prepare` | Build participant and fee sighashes |
| `POST /api/arbitration/engagements/:id/dispute/submit` | Attach signatures and broadcast transition |
| `POST /api/arbitration/cases` | Publish signed case opening |
| `GET /api/arbitration/cases/:caseId` | Public case state and commitments |
| `GET/POST /api/arbitration/cases/:caseId/messages` | Retrieve or publish ciphertext envelopes |
| `POST /api/arbitration/cases/:caseId/decision/commit` | Store signed decision commitment |
| `POST /api/arbitration/cases/:caseId/decision/reveal` | Verify and store reveal |
| `POST /api/arbitration/cases/:caseId/settlement/prepare` | Build evaluator and fee sighashes |
| `POST /api/arbitration/cases/:caseId/settlement/submit` | Broadcast and record terminal spend |
| `POST /api/arbitration/cases/:caseId/feedback` | Publish one bounded role-specific rating |

## Message envelope and anchor

The signed message payload includes at least `domain`, `protocolVersion`,
`network`, `messageId`, `caseId`, `participantRole`, `senderKey`, `sequence`,
`previousMessageHash`, `payloadHash`, `ciphertext`, and `createdAt`. The request
wraps it as:

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
