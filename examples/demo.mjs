// End-to-end walkthrough of the exact path in the payment canary — with NO
// network and NO side effects. Run: `node examples/demo.mjs`
//
// Scenario: one charge is submitted, the ack is lost, a fresh worker must
// decide whether it is safe to act. Everything it relies on is recomputable.

import { createClaim, issueReceipt, verifyReceipt, retryDecision, STATE, TRUST } from "../lib/receipt.js";
import { generateIssuer } from "../lib/keys.js";
import { MemoryAnchor, anchorReceipt, verifyAgainstAnchor } from "../lib/anchor.js";

const log = (...a) => console.log(...a);

// The local enforcer's identity (separate from any provider trust root).
const issuer = await generateIssuer();

// --- Step 1: write the claim BEFORE the effect, over effect-bearing inputs.
const effect_inputs = { amount: 100, currency: "CNY", to: "acct_7" };
let claim = await createClaim({ logical_id: "charge_8842", effect_inputs });

// --- Step 2: effect submitted, ack lost -> durable UNKNOWN, blocks redispatch.
let receipt = await issueReceipt(claim, {
  issuerPrivateKey: issuer.privateKey,
  state: STATE.UNKNOWN,
  trust: TRUST.LOCAL_OBSERVATION,
});
log("after lost ack:", receipt.state, "/", receipt.trust);
log("retry while UNKNOWN ->", await retryDecision(receipt, effect_inputs), "(no retry)");

// Publish this head to the external anchor so it cannot be silently rewound.
const anchor = new MemoryAnchor();
await anchorReceipt("charge-chain-1", receipt, 1, anchor);

// --- Step 3: reconciliation. An authenticated GET locates the effect. It is
// identity/resource-bound but NOT provider-signed, so the tier is honest.
receipt = await issueReceipt(
  { ...claim, state: receipt.state, trust: receipt.trust, issued_at: receipt.issued_at, previous_receipt_hash: receipt.previous_receipt_hash },
  {
    issuerPrivateKey: issuer.privateKey,
    state: STATE.CONFIRMED,
    trust: TRUST.AUTHENTICATED_LOOKUP, // NOT provider-signed truth
    result_ref: "https://api.example.com/v1/charges/ch_8842",
  }
);
await anchorReceipt("charge-chain-1", receipt, 2, anchor);

// --- Step 4: a fresh worker verifies everything from the receipt alone.
const v = await verifyReceipt(receipt, issuer.publicKey);
log("\nstructural+signature verify:", v);
log("same inputs retry ->", await retryDecision(receipt, effect_inputs), "(replay retained result)");
log("changed payee retry ->", await retryDecision(receipt, { ...effect_inputs, to: "acct_9" }), "(fail closed)");
log("anchor check ->", await verifyAgainstAnchor("charge-chain-1", receipt, 2, anchor));

log("\nIf the provider instead returned a signature over the effect and it",
  "\nverified under a configured provider root, trust would be PROVIDER_SIGNED —",
  "\nand only then.", );
