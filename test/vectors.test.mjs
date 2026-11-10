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
import { generateIssuer, signBytes } from "../lib/keys.js";
import { paeBytes, RECEIPT_PAYLOAD_TYPE } from "../lib/pae.js";
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
  try { await fn(); } catch { threw = true; }
  check(name, threw);
}
const payloadB64Ok = (s) => /^[A-Za-z0-9+/]+={0,2}$/.test(s);

// ---------------------------------------------------------------------------
// 1. Canonicalization — independent of any key. MUST pass before signing.
// ---------------------------------------------------------------------------

eq("key sort", canonicalJSON({ b: 1, a: 2 }), '{"a":2,"b":1}');
eq("nested sort", canonicalJSON({ z: { y: 1, x: 2 } }), '{"z":{"x":2,"y":1}}');

// RFC 8785 §3.2.3 orders member names by UTF-16 code unit, so "10" precedes
// "9" and "" precedes everything. Object.keys() returns integer-index-like keys
// first in ascending NUMERIC order regardless of insertion order, which used to
// undo the sort performed in canonical() -- emitting {"9":2,"10":1} and
// {"0":1,"":"\t"}. Those bytes match no conforming JCS implementation, so a
// receipt signed here failed verification elsewhere purely on key spelling.
eq("index-like keys keep code-unit order", canonicalJSON(JSON.parse('{"10":1,"9":2}')), '{"10":1,"9":2}');
eq("index-like keys, other insertion order", canonicalJSON(JSON.parse('{"9":2,"10":1}')), '{"10":1,"9":2}');
eq("empty key sorts before index-like key", canonicalJSON(JSON.parse('{"":"\\t","0":1}')), '{"":"\\t","0":1}');
eq("non-canonical numeric string is a plain key", canonicalJSON(JSON.parse('{"007":1,"21":2}')), '{"007":1,"21":2}');
eq("punctuation before digits", canonicalJSON(JSON.parse('{"3":1,"-":2}')), '{"-":2,"3":1}');
eq("past the array-index bound", canonicalJSON(JSON.parse('{"4294967295":1,"4294967294":2}')), '{"4294967294":2,"4294967295":1}');
check(
  "output order is independent of insertion order",
  canonicalJSON({ 5: "x", 3: "y", b: 1 }) === canonicalJSON({ b: 1, 3: "y", 5: "x" })
);
// UTF-16 CODE-UNIT order, not code-point order: U+10000 is the pair
// D800 DC00, and 0xD800 < 0xFFFF, so the astral key sorts BEFORE U+FFFF even
// though its code point is larger. A code-point sort would silently disagree
// with every other JCS implementation.
eq("astral key sorts before U+FFFF", canonicalJSON({ "\u{10000}": 1, "\uffff": 2 }), '{"\u{10000}":1,"\uffff":2}');

// __proto__ regression: a "__proto__" own-property (as produced by
// JSON.parse) must survive as a regular key. With a plain {} canonical
// target the Object.prototype setter silently dropped it, and
// {"__proto__":1,"a":1} collided with {"a":1} — a signature-layer
// collision (two distinct inputs, identical signed bytes).
const withProto = JSON.parse('{"__proto__":1,"a":1}');
eq("__proto__ key preserved", canonicalJSON(withProto), '{"__proto__":1,"a":1}');
check("__proto__ no collision", canonicalJSON(withProto) !== canonicalJSON({ a: 1 }));
eq("__proto__ nested", canonicalJSON(JSON.parse('{"n":{"__proto__":true}}')), '{"n":{"__proto__":true}}');

// Same collision class, remaining siblings: a Date, Map, Set, RegExp or class
// instance has no own enumerable properties, so each previously canonicalized
// to "{}" for EVERY instance — two distinct inputs, identical signed bytes.
// An array hole likewise emitted "[1,,3]", bytes no JSON parser accepts.
// All are now hard errors rather than silent collisions.
for (const [label, v] of [
  ["Date", new Date(1)],
  ["Map", new Map([["k", 1]])],
  ["Set", new Set([1, 2])],
  ["RegExp", /a\.b/],
  ["class instance", new (class { constructor() { this.x = 1; } })()],
]) {
  await throws(`reject ${label} (was a silent {} collision)`, () => canonicalJSON({ x: v }));
}
eq(
  "Date via explicit ISO conversion still signs",
  canonicalJSON({ x: new Date(0).toISOString() }),
  '{"x":"1970-01-01T00:00:00.000Z"}'
);
await throws("reject array hole", () => canonicalJSON([1, , 3]));
eq("array null element is fine", canonicalJSON([1, null, 3]), "[1,null,3]");
check("distinct timestamps do not collide", canonicalJSON([new Date(1).getTime()]) !== canonicalJSON([new Date(2).getTime()]));
check("null-prototype plain object accepted", canonicalJSON(Object.assign(Object.create(null), { a: 1 })) === '{"a":1}');
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
// v2: the B-vs-own-JCS consistency layer fires before the hash check.
eq("tamper reason", v1.reason, "payload is not its own JCS serialization");

const other = await generateIssuer();
const forged = await issueReceipt(claim, {
  issuerPrivateKey: other.privateKey,
  state: STATE.CONFIRMED,
  trust: TRUST.PROVIDER_SIGNED, // lie on the tier as well
});
const v2 = await verifyReceipt(forged, issuer.publicKey);
eq("foreign signature rejected", v2.ok, false);

// ---------------------------------------------------------------------------
// 2b. PAE domain separation (v2 receipt format — breaking vs v1, by design).
//     Decisive properties: a signature binds payloadType AND bytes; the
//     verifier consumes the TRANSPORTED bytes and never re-derives coverage.
// ---------------------------------------------------------------------------
check("receipt carries payload_type", receipt.payload_type === "application/vnd.correctover.receipt.v2+json", receipt.payload_type);
check("receipt carries payload_b64", typeof receipt.payload_b64 === "string" && payloadB64Ok(receipt.payload_b64));

// (i) Type-swap vector: same receipt, payloadType changed => MUST reject.
const typeSwapped = { ...receipt, payload_type: "application/other+json" };
const vts = await verifyReceipt(typeSwapped, issuer.publicKey);
eq("type-swap rejected", vts.ok, false);
check("type-swap reason is the format gate", /payload_type/.test(vts.reason), vts.reason);

// (ii) Transplanted-signature vector: same body signed under a DIFFERENT
//      type, presented with OUR type => MUST reject (PAE differs).
const evilSig = await signBytes(issuer.privateKey, paeBytes("application/other+json", new Uint8Array(Buffer.from(receipt.payload_b64, "base64"))));
const transplant = { ...receipt, signature: evilSig };
const vtp = await verifyReceipt(transplant, issuer.publicKey);
eq("cross-type transplanted signature rejected", vtp.ok, false);

// (iii) Transported-bytes vector: reorder every key of the transported claim
//       (payload_b64/signature untouched) => still verifies. The verifier
//       signs/verifies against payload_b64, never a re-derivation; JCS
//       determinism keeps the consistency layer green.
const reordered = {};
for (const k of Object.keys(receipt).reverse()) reordered[k] = receipt[k];
const vro = await verifyReceipt(reordered, issuer.publicKey);
check("reordered JSON still verifies", vro.ok, JSON.stringify(vro));

// (iv) Legacy fail-closed: a v1-style receipt (bare JCS signature, no PAE,
//      no payload_b64) MUST NOT verify under v2 rules.
const legacy = { ...receipt };
delete legacy.payload_type;
delete legacy.payload_b64;
delete legacy.signature;
const legacySig = await signBytes(issuer.privateKey, await (async () => {
  const { canonicalBytes } = await import("../lib/canonical.js");
  const { content_hash, payload_type, payload_b64, signature, ...body } = legacy;
  return canonicalBytes(body);
})());
const legacyReceipt = { ...legacy, signature: legacySig };
const vlg = await verifyReceipt(legacyReceipt, issuer.publicKey);
eq("legacy bare-JCS receipt rejected", vlg.ok, false);

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
