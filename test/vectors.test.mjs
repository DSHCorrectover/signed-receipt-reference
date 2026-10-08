// Pinned positive/negative vectors, zero deps. Run: `node test/vectors.test.mjs`
// Exits non-zero on any failure (use in CI). No test framework required.

import { canonicalJSON, canonicalNumber } from "../lib/canonical.js";
import {
  createClaim,
  issueReceipt,
  verifyReceipt,
  retryDecision,
  STATE,
  TRUST,
} from "../lib/receipt.js";
import { generateIssuer } from "../lib/keys.js";
import { MemoryAnchor, anchorReceipt, verifyAgainstAnchor } from "../lib/anchor.js";

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
// 1. Canonicalization — independent of any key. These MUST pass before signing
//    is ever considered, proving canonicalization is correct on its own.
// ---------------------------------------------------------------------------

// Key ordering (UTF-16 code-unit), nested + array preserved.
eq("key sort", canonicalJSON({ b: 1, a: 2 }), '{"a":2,"b":1}');
eq("nested sort", canonicalJSON({ z: { y: 1, x: 2 } }), '{"z":{"x":2,"y":1}}');
eq("array order", canonicalJSON([3, 1, 2]), "[3,1,2]");
eq("no whitespace", canonicalJSON({ a: 1, b: [2, 3] }), '{"a":1,"b":[2,3]}');

// Numbers — the JCS §3.2.2.1 cases, including the exact 1e21 case in the
// conformance discussion.
eq("int fixed", canonicalNumber(42), "42");
eq("neg int fixed", canonicalNumber(-7), "-7");
eq("zero", canonicalNumber(0), "0");
eq("safe int no exponent", canonicalNumber(9007199254740991), "9007199254740991");
eq("big exponent JCS style", canonicalJSON({ big: 1e21 }), '{"big":1e+21}');
eq("float shortest", canonicalNumber(0.000001), "0.000001");
eq("float roundtrip", canonicalNumber(0.1), "0.1");

// Semantic equality: different spellings of the same value canonicalize equal.
eq(
  "semantic same",
  canonicalJSON({ x: 1e0, y: 1 }),
  canonicalJSON({ y: 1, x: 1 })
);

// Negative controls — these MUST be rejected (fail closed), proving the
// canonicalizer refuses to silently produce a wrong/ambiguous result.
await throws("reject undefined", () => canonicalJSON({ a: undefined }));
await throws("reject function", () => canonicalJSON({ a: () => 1 }));
await throws("reject BigInt coercion", () => canonicalJSON({ a: 1n }));
await throws("reject NaN", () => canonicalNumber(NaN));
await throws("reject Infinity", () => canonicalNumber(Infinity));

// ---------------------------------------------------------------------------
// 2. Tamper detection on the RECEIPT layer (after the body is correct).
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

// Tamper a body field but keep signature -> hash mismatch.
const tampered = { ...receipt, result_ref: "https://attacker/evil" };
const v1 = await verifyReceipt(tampered, issuer.publicKey);
eq("tampered body rejected", v1.ok, false);
eq("tamper reason", v1.reason, "content_hash mismatch");

// Re-sign with a different key -> signature invalid under the real issuer.
const other = await generateIssuer();
const forged = await issueReceipt(claim, {
  issuerPrivateKey: other.privateKey,
  state: STATE.CONFIRMED,
  trust: TRUST.PROVIDER_SIGNED, // lie: escalated trust without provider key
});
const v2 = await verifyReceipt(forged, issuer.publicKey);
eq("foreign signature rejected", v2.ok, false);

// ---------------------------------------------------------------------------
// 3. Replay vs CONFLICT — a pure hash decision.
// ---------------------------------------------------------------------------
const sameInputs = { amount: 100, currency: "CNY", to: "acct_7" };
const changedInputs = { amount: 100, currency: "CNY", to: "acct_9" }; // changed payee
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
// 4. Rollback / replacement detection via the EXTERNAL anchor.
// ---------------------------------------------------------------------------
const chainId = "charge-chain-1";
await anchorReceipt(chainId, receipt, 1, new MemoryAnchor()); // dummy to show shape
const anchor = new MemoryAnchor();
await anchorReceipt(chainId, receipt, 1, anchor);

const okNow = await verifyAgainstAnchor(chainId, receipt, 1, anchor);
check("same head at same seq ok", okNow.ok, JSON.stringify(okNow));

// Attacker presents an older, internally-valid receipt at a lower sequence.
const older = unknownReceipt; // valid signature, but prior point in history
const rb = await verifyAgainstAnchor(chainId, older, 0, anchor);
eq("rollback seq rejected", rb.ok, false);
check("rollback reason", String(rb.reason).startsWith("rollback"));

// Attacker presents a DIFFERENT receipt at the SAME anchored sequence.
const replacement = await issueReceipt(
  await createClaim({ logical_id: "charge_other", effect_inputs: { amount: 1 }, now: () => 1 }),
  { issuerPrivateKey: issuer.privateKey, state: STATE.CONFIRMED, trust: TRUST.LOCAL_OBSERVATION }
);
const rp = await verifyAgainstAnchor(chainId, replacement, 1, anchor);
eq("replacement rejected", rp.ok, false);
eq("replacement reason", rp.reason, "replacement: head differs at anchored seq");

// ---------------------------------------------------------------------------
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
