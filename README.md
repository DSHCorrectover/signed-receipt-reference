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
- `npm test` → 33 pinned positive/negative vectors. `npm run demo` → the canary path.

## The central distinction

A signature authenticates the **bytes it is given**. It cannot make an incorrect
or incomplete canonicalization correct — signing bad canonical bytes yields
tamper-evident garbage. So two properties are kept as **separate layers**, each
with its own tests:

1. **Semantic binding** — does the digest actually capture the effect-bearing
   inputs? (`lib/canonical.js`, tested before any key exists.)
2. **Evidence authenticity** — were those bytes tampered with after signing?
   (`lib/receipt.js`.)

## What Once asked to see

### 1. Canonicalization — `lib/canonical.js`

JCS-style (RFC 8785 method): keys sorted by UTF-16 code-unit order, arrays in
order, no whitespace, and deterministic numbers — safe integers print fixed;
beyond that the shortest round-trippable form, so `{"big":1e21}` → `{"big":1e+21}`.

It **fails closed** on `undefined`, functions, symbols, `BigInt`, `NaN`, and
`Infinity`, rather than silently producing an ambiguous or lossy result. The
vectors in `test/vectors.test.mjs` §1 pin both the accepted and rejected cases.
This is a compact reference, not a line-for-line RFC implementation; the
vectors state exactly what is covered.

### 2. Issuer / key model — `lib/keys.js`

Two trust roots are never conflated:

- the **local enforcer** signs receipts for what *it observed*;
- the **provider**, only when it natively signs an effect, is a separate root.

A local signature means "this enforcer saw this." It does **not** make the
external effect true.

### 3. Exactly what is signed — `lib/receipt.js`

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

### 4. Provider-authenticated vs locally signed — `TRUST` tiers

Every receipt carries an explicit tier; a signature's mere presence never
upgrades it:

| tier | meaning |
|---|---|
| `LOCAL_OBSERVATION` | enforcer signed its own observation; external truth not established |
| `AUTHENTICATED_LOOKUP` | authenticated, identity/resource-bound GET, but no native provider signature (the ordinary GitHub-canary case) |
| `PROVIDER_SIGNED` | provider signed a canonicalizable effect that verifies under a configured provider root and binds this logical id |

So an unsigned provider GET is recorded honestly and is never presented as
provider-signed truth.

## Rollback needs an anchor outside the ledger — `lib/anchor.js`

A self-contained hash chain cannot detect substitution by an **older but
internally valid** chain, because every signature in it still verifies. This
reference therefore keeps an external anchor interface (`publish` / `head`) with
an in-memory implementation, and pins two failures: sequence moved backwards
(`rollback`) and a different head at the same anchored sequence (`replacement`).
A real deployment swaps in a transparency-log head, public-ledger timestamp,
quorum notary, or trusted monotonic service — same interface.

## Files

```
lib/canonical.js   deterministic canonical JSON (standalone, fail-closed)
lib/keys.js        Ed25519 issuer/provider key model
lib/receipt.js     claim lifecycle, tiers, sign/verify, replay decision
lib/anchor.js      external anchor: rollback/replacement detection
test/vectors.test.mjs   33 pinned vectors, no framework
examples/demo.mjs  full canary path, no side effects
```

## Boundary

This helps only where the effect is canonicalizable and (for the top tier)
provider-signed. Where the provider cannot return that, the state stays
`UNKNOWN` and you escalate rather than replay — the receipt gives a crisp test
for which world you are in.
