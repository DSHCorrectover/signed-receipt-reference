# Signed Receipt — minimal reference

A **side-effect-only**, zero-dependency reference for the evidence layer over
the existing idempotency model:

```
logical identity → effect binding → UNKNOWN/CONFIRMED
                 → authoritative reconciliation → replay/CONFLICT
```

It does **not** retry, call a provider, or replace the framework. It only makes
the "enough truth to reconcile" condition **checkable rather than assumed**.

- Pure ESM, runs on Node ≥ 20 and Workers/V8 isolates (only `crypto.subtle`).
- No network, no clock except where injected.
- `npm test` → 70 pinned positive/negative vectors. `npm run demo` → the canary path.

## The central distinctions

A signature authenticates the **bytes it is given**. It cannot make an incorrect
or incomplete canonicalization correct — signing bad canonical bytes yields
tamper-evident garbage. And it cannot make an **external effect true** — a
receipt that verifies cryptographically still need not establish the effect it
claims. So three questions are kept as **separate layers**, each with tests:

1. **Semantic binding** — does the digest capture the effect-bearing inputs?
   (`lib/canonical.js`, tested before any key exists.)
2. **Evidence authenticity** — were those bytes tampered with after signing?
   (`lib/receipt.js`.)
3. **Effect establishment** — given a valid record, is the external effect
   actually established, or does it only *look* true? (`lib/effect.js`.)

## 1. Canonicalization — `lib/canonical.js`

Deterministic JSON following the RFC 8785 (JCS) method: keys sorted by UTF-16
code-unit order, arrays in order, no whitespace, and deterministic numbers:

- `-0` → `0`; integers with magnitude ≤ 2<sup>53</sup>−1 print with no exponent;
- otherwise the **shortest round-trippable** form, built by searching
  `toPrecision(1..17)` rather than relying on `JSON.stringify`'s incidental
  exponent cut-off, so it is identical across engines;
- fixed notation for leading-digit exponent in `[-6, 20]`, scientific
  (`e+`/`e-`) beyond. Thus `1e20` → `100000000000000000000` while the
  called-out case `{"big":1e21}` → `{"big":1e+21}`.

It **fails closed** on `undefined`, functions, symbols, `BigInt`, `NaN`, and
`Infinity`. Vectors §1 pin accepted/rejected cases plus a round-trip invariant
over the tricky magnitudes. This remains a compact readable reference, not a
line-for-line RFC implementation; the vectors state exactly what is covered.

## 2. Issuer / key model — `lib/keys.js`

Two trust roots are never conflated:

- the **local enforcer** signs receipts for what *it observed*;
- the **provider**, only when it natively signs an effect, is a separate root.

A local signature means "this enforcer saw this." It does **not** make the
external effect true.

## 3. Exactly what is signed — `lib/receipt.js`

The signature covers the **canonical bytes of a fixed signed field set**
(`SIGNED_FIELDS`):

```
v, logical_id, effect_inputs_hash, state, trust,
result_ref, provider_effect_ref, issued_at, previous_receipt_hash
```

`content_hash` and `signature` are computed over that set and are themselves
excluded. Verification recomputes the hash (body tamper) and then checks the
signature (identity). Replay/`CONFLICT` is a pure hash comparison on
`effect_inputs_hash`, not an application decision.

## 4. Trust tiers, checked against the key root — `TRUST`

Every receipt carries an explicit tier; a signature's mere presence never
upgrades it. Critically, the tier must match what the **authenticating key is
empowered to prove** — a local key signing `trust:"PROVIDER_SIGNED"` does not
gain provider authority.

| tier | meaning |
|---|---|
| `LOCAL_OBSERVATION` | enforcer signed its own observation; external truth not established |
| `AUTHENTICATED_LOOKUP` | identity/resource-bound GET, truth holds only while a fresh confirming read is supplied |
| `PROVIDER_SIGNED` | provider root signed a canonicalizable effect binding this logical id |

## 5. Chain continuity: anchor **and** ancestry — `lib/anchor.js`

A self-contained hash chain cannot detect substitution by another internally
valid chain, since every signature in the replacement still verifies. Two
properties must both hold:

1. an **independently trusted root outside the ledger** records a head (the
   anchor); an attacker-replaceable or in-ledger anchor establishes nothing;
2. any presented head proves **ancestry** back to that anchored head.

`verifyAncestry(head, { resolveReceipt, resolvePublicKey, trustedHeadHash })`
walks `previous_receipt_hash` links backwards. At every hop it checks the link
equals the canonical hash of the actual parent bytes (link integrity) and that
the parent verifies cryptographically, stopping successfully only on the
trusted head. Reaching genesis without that match is a **broken chain**; a
missing ancestor, a pointer to different bytes, or a link cycle are all
rejected. `verifyAgainstAnchor` uses this to accept a forward extension only
when the higher sequence genuinely descends from the anchored head — a bare
higher seq proves nothing.

A real deployment swaps the in-memory anchor for a transparency-log head,
public-ledger timestamp, quorum notary, or trusted monotonic service — same
interface.

## 6. Valid signature ≠ established effect — `lib/effect.js`

`evaluateEffect(receipt, { publicKey, keyRoot, effectObserved })` answers the
two questions independently and returns one of:

| result | meaning |
|---|---|
| `EFFECT_ESTABLISHED` | provider-signed, or authenticated lookup with a fresh confirming read |
| `EFFECT_NOT_ESTABLISHED` | signature valid but effect unconfirmed (`UNKNOWN`, no `result_ref`, local-only, or stale lookup) |
| `TRUST_CLAIM_UNSUPPORTED` | signature valid but a claimed `PROVIDER_SIGNED` tier is backed only by a local root |

The headline adversarial vector is pinned: a receipt verifies cryptographically
yet **does not establish the claimed external effect** — the system reports
`crypto_valid: true` together with a non-established effect instead of letting
"signature valid" imply "effect true".

## Files

```
lib/canonical.js   deterministic canonical JSON (standalone, fail-closed)
lib/keys.js        Ed25519 issuer/provider key model
lib/receipt.js     claim lifecycle, tiers, sign/verify, replay decision
lib/anchor.js      external anchor + previous_receipt_hash ancestry walk
lib/effect.js      cryptographic validity vs external-effect establishment
test/vectors.test.mjs   70 pinned vectors, no framework
examples/demo.mjs  full canary path, no side effects
```

## Boundary

This helps only where the effect is canonicalizable and (for the top tier)
provider-signed. Where the provider cannot return that, the state stays
`UNKNOWN` and you escalate rather than replay — the receipt gives a crisp test
for which world you are in.
