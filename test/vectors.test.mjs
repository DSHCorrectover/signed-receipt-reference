// Pinned positive/negative vectors, zero deps. Run: `node test/vectors.test.mjs`
// Exits non-zero on any failure (use in CI). No test framework required.

import { canonicalJSON, canonicalNumber } from "../lib/canonical.js";
import {
  createClaim,
  issueReceipt,
  verifyReceipt,
  retryDecision,
  receiptLinkHash,
  STATE,
  TRUST,
} from "../lib/receipt.js";
import { generateIssuer } from "../lib/keys.js";
import { MemoryAnchor, anchorReceipt, verifyAgainstAnchor, verifyAncestry } from "../lib/anchor.js";
import { evaluateEffect, KEY_ROOT, EFFECT } from "../lib/effect.js";

let pass = 0;
let fail = 0;
function check(name, cond, extra = "") {
  if (cond) {
    pass++;
  } else {
    fail++;
    console.error("FAIL:", name, extra);
  }
}
function eq(name, got, want) {
  check(name, got === want, `got=${JSON.stringify(got)} want=${JSON.stringify(want)}`);
}
async function throws(name, fn) {
  let threw = false;
  try {
    await fn();
  } catch {
    threw = true;
  }
  check(name, threw);
}

// ---------------------------------------------------------------------------
// 1. Canonicalization — independent of any key. MUST pass before signing.
// ---------------------------------------------------------------------------

eq("key sort", canonicalJSON({ b: 1, a: 2 }), '{"a":2,"b":1}');
eq("nested sort", canonicalJSON({ z: { y: 1, x: 2 } }), '{"z":{"x":2,"y":1}}');
eq("array order", canonicalJSON([3, 1, 2]), "[3,1,2]");
eq("no whitespace", canonicalJSON({ a: 1, b: [2, 3] }), '{"a":1,"b":[2,3]}');

// Numbers per JCS §3.2.2.1. Fixed notation for leading-digit exponent
// [-6, 20]; scientific beyond, including the exact 1e21 boundary case.
eq("int fixed", canonicalNumber(42), "42");
eq("neg int fixed", canonicalNumber(-7), "-7");
eq("zero", canonicalNumber(0), "0");
eq("neg zero is zero", canonicalNumber(-0), "0");
eq("safe int no exponent", canonicalNumber(9007199254740991), "9007199254740991");
eq("1e20 stays fixed integer", canonicalNumber(1e20), "100000000000000000000");
eq("1e21 scientific JCS style", canonicalNumber(1e21), "1e+21");
eq("big in object", canonicalJSON({ big: 1e21 }), '{"big":1e+21}');
eq("neg big", canonicalNumber(-1e21), "-1e+21");
eq("fractional big", canonicalNumber(1.5e21), "1.5e+21");
eq("1e-6 fixed", canonicalNumber(0.000001), "0.000001");
eq("1e-7 scientific", canonicalNumber(1e-7), "1e-7");
eq("small fraction", canonicalNumber(0.00123), "0.00123");
eq("float roundtrip", canonicalNumber(0.1), "0.1");

// Semantic equality: different spellings of the same value canonicalize equal.
eq("semantic same", canonicalJSON({ x: 1e0, y: 1 }), canonicalJSON({ y: 1, x: 1 }));

// Determinism sanity for the tricky range: re-parsing the canonical form must
// return the identical number (shortest round-trip invariant).
for (const v of [1e21, 1e20, 1e-7, 123456789.123, 1e22, 9.999999999999999e20]) {
  check(`round-trip ${v}`, Number(canonicalNumber(v)) === v, canonicalNumber(v));
}

// Negative controls — fail closed.
await throws("reject undefined", () => canonicalJSON({ a: undefined }));
await throws("reject function", () => canonicalJSON({ a: () => 1 }));
await throws("reject BigInt coercion", () => canonicalJSON({ a: 1n }));
await throws("reject NaN", () => canonicalNumber(NaN));
await throws("reject Infinity", () => canonicalNumber(Infinity));

// ---------------------------------------------------------------------------
// 2. Tamper detection on the RECEIPT layer.
// ---------------------------------------------------------------------------

const issuer = await generateIssuer();
const claim = await createClaim({
  logical_id: "charge_8842",
  effect_inputs: { amount: 100, currency: "CNY", to: "acct_7" },
  now: () => 1759900000000,
});
let receipt = await issueReceipt(claim, {
  issuerPrivateKey: issuer.privateKey,
  state: STATE.CONFIRMED,
  trust: TRUST.AUTHENTICATED_LOOKUP,
  result_ref: "https://api.example.com/v1/charges/ch_8842",
});

eq("confirmed state", receipt.state, STATE.CONFIRMED);
eq("trust labelled", receipt.trust, TRUST.AUTHENTICATED_LOOKUP);
check("has content_hash", typeof receipt.content_hash === "string");
check("has signature", typeof receipt.signature === "string");

const v0 = await verifyReceipt(receipt, issuer.publicKey);
check("valid receipt verifies", v0.ok, JSON.stringify(v0));

const tampered = { ...receipt, result_ref: "https://attacker/evil" };
const v1 = await verifyReceipt(tampered, issuer.publicKey);
eq("tampered body rejected", v1.ok, false);
eq("tamper reason", v1.reason, "content_hash mismatch");

const other = await generateIssuer();
const forged = await issueReceipt(claim, {
  issuerPrivateKey: other.privateKey,
  state: STATE.CONFIRMED,
  trust: TRUST.PROVIDER_SIGNED, // lie on the tier as well
});
const v2 = await verifyReceipt(forged, issuer.publicKey);
eq("foreign signature rejected", v2.ok, false);

// ---------------------------------------------------------------------------
// 3. Replay vs CONFLICT.
// ---------------------------------------------------------------------------
const sameInputs = { amount: 100, currency: "CNY", to: "acct_7" };
const changedInputs = { amount: 100, currency: "CNY", to: "acct_9" };
eq("same inputs -> REPLAY", await retryDecision(receipt, sameInputs), "REPLAY");
eq("changed payee -> CONFLICT", await retryDecision(receipt, changedInputs), "CONFLICT");

const unknownClaim = await createClaim({
  logical_id: "charge_8843",
  effect_inputs: { amount: 5 },
  now: () => 1759900000001,
});
const unknownReceipt = await issueReceipt(unknownClaim, {
  issuerPrivateKey: issuer.privateKey,
  state: STATE.UNKNOWN,
  trust: TRUST.LOCAL_OBSERVATION,
});
eq("UNKNOWN blocks -> UNKNOWN_PRESENT", await retryDecision(unknownReceipt, { amount: 5 }), "UNKNOWN_PRESENT");

// ---------------------------------------------------------------------------
// 4. External anchor + ANCESTRY (the chain-continuity property Once flagged).
// ---------------------------------------------------------------------------

// Build a genuine forward chain: r1 <- r2 <- r3, each link binding parent bytes.
async function chainStep(prevReceipt, id, t) {
  const prevHash = prevReceipt ? await receiptLinkHash(prevReceipt) : null;
  const c = await createClaim({
    logical_id: id,
    effect_inputs: { t },
    previous_receipt_hash: prevHash,
    now: () => 1700000000000 + t,
  });
  return issueReceipt(c, {
    issuerPrivateKey: issuer.privateKey,
    state: STATE.CONFIRMED,
    trust: TRUST.AUTHENTICATED_LOOKUP,
    result_ref: "https://x/" + id,
  });
}

const r1 = await chainStep(null, "op_1", 1);
const r2 = await chainStep(r1, "op_2", 2);
const r3 = await chainStep(r2, "op_3", 3);

const store = new Map();
for (const r of [r1, r2, r3]) store.set(await receiptLinkHash(r), r);
const resolveReceipt = async (h) => (store.has(h) ? store.get(h) : null);
const resolvePublicKey = async () => issuer.publicKey;

const chainId = "op-chain";
const anchor = new MemoryAnchor();
await anchorReceipt(chainId, r1, 1, anchor);

// Same head at anchored seq.
const same = await verifyAgainstAnchor(chainId, r1, 1, anchor);
check("same head at same seq ok", same.ok, JSON.stringify(same));

// Rollback: older valid receipt at lower seq.
const rb = await verifyAgainstAnchor(chainId, unknownReceipt, 0, anchor);
eq("rollback seq rejected", rb.ok, false);
check("rollback reason", String(rb.reason).startsWith("rollback"));

// Replacement: different receipt at the same anchored seq.
const replacement = await chainStep(null, "op_other", 99);
const rp = await verifyAgainstAnchor(chainId, replacement, 1, anchor);
eq("replacement rejected", rp.ok, false);
eq("replacement reason", rp.reason, "replacement: head differs at anchored seq");

// Forward extension WITHOUT ancestry resolvers: a higher seq proves nothing.
const noRes = await verifyAgainstAnchor(chainId, r3, 3, anchor);
eq("forward without resolvers rejected", noRes.ok, false);
eq("no-resolvers reason", noRes.reason, "forward extension unproven: ancestry resolvers required");

// Forward extension WITH a complete, unbroken path back to the anchored head.
const fwd = await verifyAgainstAnchor(chainId, r3, 3, anchor, { resolveReceipt, resolvePublicKey });
check("unbroken ancestry ok", fwd.ok, JSON.stringify(fwd));
eq("ancestry depth", fwd.depth, 2);

// One-hop extension.
const fwd1 = await verifyAgainstAnchor(chainId, r2, 2, anchor, { resolveReceipt, resolvePublicKey });
check("one hop ok", fwd1.ok, JSON.stringify(fwd1));
eq("one hop depth", fwd1.depth, 1);

// Broken ancestry: an ancestor is unavailable (pruned) -> cannot reach head.
const missingRes = async (h) => (h === (await receiptLinkHash(r1)) ? null : resolveReceipt(h));
const bm = await verifyAgainstAnchor(chainId, r3, 3, anchor, {
  resolveReceipt: missingRes,
  resolvePublicKey,
});
eq("missing ancestor rejected", bm.ok, false);
check("missing reason", String(bm.reason).includes("missing ancestor"));

// Link mismatch: resolver hands back a different receipt for the named hash.
const wrongRes = async (h) => (h === (await receiptLinkHash(r2)) ? replacement : resolveReceipt(h));
const bl = await verifyAgainstAnchor(chainId, r3, 3, anchor, {
  resolveReceipt: wrongRes,
  resolvePublicKey,
});
eq("link mismatch rejected", bl.ok, false);
check("link mismatch reason", String(bl.reason).includes("link mismatch"));

// Fork: a separate internally-valid chain whose genesis never meets the
// anchored head. Every signature verifies, but ancestry does not reach ours.
const forkIssuer = await generateIssuer();
async function forkStep(prev, id, t) {
  const prevHash = prev ? await receiptLinkHash(prev) : null;
  const c = await createClaim({ logical_id: id, effect_inputs: { t }, previous_receipt_hash: prevHash, now: () => t });
  return issueReceipt(c, {
    issuerPrivateKey: forkIssuer.privateKey,
    state: STATE.CONFIRMED,
    trust: TRUST.AUTHENTICATED_LOOKUP,
    result_ref: "https://f/" + id,
  });
}
const f1 = await forkStep(null, "f_1", 1);
const f2 = await forkStep(f1, "f_2", 2);
const forkStore = new Map();
forkStore.set(await receiptLinkHash(f1), f1);
const fork = await verifyAncestry(f2, {
  resolveReceipt: async (h) => (forkStore.has(h) ? forkStore.get(h) : null),
  resolvePublicKey: async () => forkIssuer.publicKey,
  trustedHeadHash: await receiptLinkHash(r1), // our head, not the fork's
});
eq("fork rejected", fork.ok, false);
check("fork reason", String(fork.reason).includes("genesis without the trusted head"));

// ---------------------------------------------------------------------------
// 5. Cryptographic validity vs EFFECT establishment — separate judgments.
//    The headline adversarial case: signature valid, effect not established.
// ---------------------------------------------------------------------------

// Local observation authenticates the record, never the external effect.
const localRc = await issueReceipt(
  await createClaim({ logical_id: "loc_1", effect_inputs: { x: 1 }, now: () => 1 }),
  {
    issuerPrivateKey: issuer.privateKey,
    state: STATE.CONFIRMED,
    trust: TRUST.LOCAL_OBSERVATION,
    result_ref: "https://x/loc_1",
  }
);
const eLocal = await evaluateEffect(localRc, { publicKey: issuer.publicKey, keyRoot: KEY_ROOT.LOCAL_ISSUER });
check("local crypto valid", eLocal.crypto_valid);
eq("local effect not established", eLocal.effect, EFFECT.UNVERIFIED);

// *** The key case: receipt self-declares PROVIDER_SIGNED but only a LOCAL key
// backs it. Signature verifies; the claimed trust is unsupported. ***
const lieRc = await issueReceipt(
  await createClaim({ logical_id: "lie_1", effect_inputs: { x: 1 }, now: () => 2 }),
  {
    issuerPrivateKey: issuer.privateKey,
    state: STATE.CONFIRMED,
    trust: TRUST.PROVIDER_SIGNED,
    result_ref: "https://x/lie_1",
  }
);
const eLie = await evaluateEffect(lieRc, { publicKey: issuer.publicKey, keyRoot: KEY_ROOT.LOCAL_ISSUER });
check("lie crypto valid", eLie.crypto_valid);
eq("self-escalated trust unsupported", eLie.effect, EFFECT.UNSUPPORTED_CLAIM);

// Authenticated lookup: stale without a fresh confirming observation...
const eLookupStale = await evaluateEffect(receipt, {
  publicKey: issuer.publicKey,
  keyRoot: KEY_ROOT.AUTHENTICATED_LOOKUP,
});
check("lookup stale crypto valid", eLookupStale.crypto_valid);
eq("stale lookup not established", eLookupStale.effect, EFFECT.UNVERIFIED);

// ...established when a fresh independent read confirms it.
const eLookupFresh = await evaluateEffect(receipt, {
  publicKey: issuer.publicKey,
  keyRoot: KEY_ROOT.AUTHENTICATED_LOOKUP,
  effectObserved: true,
});
eq("fresh lookup established", eLookupFresh.effect, EFFECT.ESTABLISHED);

// A genuine provider root signing PROVIDER_SIGNED establishes the effect.
const provider = await generateIssuer();
const provRc = await issueReceipt(
  await createClaim({ logical_id: "prov_1", effect_inputs: { x: 9 }, now: () => 3 }),
  {
    issuerPrivateKey: provider.privateKey,
    state: STATE.CONFIRMED,
    trust: TRUST.PROVIDER_SIGNED,
    result_ref: "https://provider/prov_1",
  }
);
const eProv = await evaluateEffect(provRc, { publicKey: provider.publicKey, keyRoot: KEY_ROOT.PROVIDER });
eq("provider signed established", eProv.effect, EFFECT.ESTABLISHED);

// Durable UNKNOWN: even a provider-adjacent claim is not established.
const eUnknown = await evaluateEffect(unknownReceipt, {
  publicKey: issuer.publicKey,
  keyRoot: KEY_ROOT.LOCAL_ISSUER,
});
check("unknown crypto valid", eUnknown.crypto_valid);
eq("unknown not established", eUnknown.effect, EFFECT.UNVERIFIED);

// Tampered record fails at the cryptographic stage outright.
const eTamp = await evaluateEffect(tampered, {
  publicKey: issuer.publicKey,
  keyRoot: KEY_ROOT.LOCAL_ISSUER,
});
eq("tampered crypto invalid", eTamp.crypto_valid, false);
eq("tampered not established", eTamp.effect, EFFECT.UNVERIFIED);

// ---------------------------------------------------------------------------
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
