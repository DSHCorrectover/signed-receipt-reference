// Claim lifecycle + signed receipts. Pure, side-effect-free (no network, no
// clock unless one is injected), no framework assumptions.
//
// Logical model (unchanged from the issue):
//   logical identity -> effect binding -> UNKNOWN/CONFIRMED
//                    -> authoritative reconciliation -> replay/CONFLICT
//
// This module only adds the EVIDENCE layer on top; it does not retry, call the
// provider, or make policy beyond the fail-closed checks below.

import { canonicalJSON, canonicalBytes, canonicalHash } from "./canonical.js";
import { signBytes, verifyBytes, exportPublicId } from "./keys.js";
import { paeBytes, RECEIPT_PAYLOAD_TYPE } from "./pae.js";

export const STATE = Object.freeze({
  UNKNOWN: "UNKNOWN", // effect submitted, outcome not yet established
  CONFIRMED: "CONFIRMED", // external effect located and bound to this claim
});

// Trust tiers — the answer to "provider-authenticated vs locally observed".
// A signature's mere existence never upgrades a tier.
export const TRUST = Object.freeze({
  // Enforcer signed its own observation only. External truth NOT established.
  LOCAL_OBSERVATION: "LOCAL_OBSERVATION",
  // Recovered over an authenticated channel and identity/resource-bound,
  // but the provider returned no native signature over the effect.
  AUTHENTICATED_LOOKUP: "AUTHENTICATED_LOOKUP",
  // Provider natively signed a canonicalizable effect that verifies under a
  // configured provider trust root and binds this logical id.
  PROVIDER_SIGNED: "PROVIDER_SIGNED",
});

// Fields that are part of the signed body. content_hash + signature are
// computed over this set and are themselves excluded.
const SIGNED_FIELDS = [
  "v",
  "logical_id",
  "effect_inputs_hash",
  "state",
  "trust",
  "result_ref",
  "provider_effect_ref",
  "issued_at",
  "previous_receipt_hash",
];

function signedBody(claim) {
  const body = {};
  for (const k of SIGNED_FIELDS) {
    if (claim[k] !== undefined) body[k] = claim[k];
  }
  return body;
}

/**
 * Create the pre-execution CLAIM for a logical operation.
 *
 * @param {object} p
 * @param {string} p.logical_id      stable id derived from the logical op
 * @param {object} p.effect_inputs   ONLY the effect-bearing arguments
 * @param {string} [p.previous_receipt_hash] links the chain
 * @param {function} [p.now]         injectable clock -> epoch ms (string)
 */
export async function createClaim({ logical_id, effect_inputs, previous_receipt_hash, now }) {
  const effect_inputs_hash = await canonicalHash(effect_inputs);
  const claim = {
    v: 2,
    logical_id,
    effect_inputs_hash,
    state: STATE.UNKNOWN,
    trust: TRUST.LOCAL_OBSERVATION,
    result_ref: null,
    provider_effect_ref: null,
    issued_at: String(now ? now() : Date.now()),
    previous_receipt_hash: previous_receipt_hash ?? null,
  };
  return claim; // unsigned until issueReceipt()
}

/**
 * Bind the outcome and sign, producing an immutable receipt.
 *
 * @param {object} claim      a claim from createClaim
 * @param {object} p
 * @param {CryptoKey} p.issuerPrivateKey  local enforcer signing key
 * @param {string} p.state
 * @param {string} p.trust
 * @param {string} [p.result_ref]
 * @param {string} [p.provider_effect_ref]
 */
export async function issueReceipt(claim, { issuerPrivateKey, state, trust, result_ref, provider_effect_ref }) {
  const finalized = {
    ...claim,
    state,
    trust,
    result_ref: result_ref ?? claim.result_ref,
    provider_effect_ref: provider_effect_ref ?? claim.provider_effect_ref,
  };
  // Exactly what is signed: PAE(payloadType, B) where B is the JCS canonical
  // byte string of the signed body. JCS gives producer-side byte
  // determinism; PAE gives domain separation — the same bytes under any
  // other payloadType (or purpose) verify to a different pre-auth encoding,
  // so signatures cannot be transplanted across message types.
  const B = canonicalBytes(signedBody(finalized));
  const content_hash = await canonicalHash(signedBody(finalized));
  const signature = await signBytes(issuerPrivateKey, paeBytes(RECEIPT_PAYLOAD_TYPE, B));
  // payload_b64 carries the ORIGINAL signed bytes. A verifier decodes and
  // uses these directly (PAE + signature) instead of re-deriving what was
  // covered — re-serialization differences can then never flip a verdict.
  const receipt = {
    ...finalized,
    payload_type: RECEIPT_PAYLOAD_TYPE,
    payload_b64: Buffer.from(B).toString("base64"),
    content_hash,
    signature,
  };
  return receipt;
}

/**
 * Verify a receipt structurally and cryptographically.
 * Pure: does not consult the outside world. External anchoring is separate
 * (see anchor.js) because rollback detection needs a trust root outside the
 * replaceable ledger.
 *
 * @returns {Promise<{ok:boolean, reason?:string}>}
 */
export async function verifyReceipt(receipt, issuerPublicKey) {
  if (!receipt || typeof receipt !== "object") return { ok: false, reason: "not an object" };
  const { content_hash, signature, payload_type, payload_b64, ...rest } = receipt;
  if (!content_hash || !signature) return { ok: false, reason: "missing content_hash/signature" };

  // 0) Format gate (fail-closed). v1 receipts (bare JCS signature, no PAE, no
  // payload_b64) are NOT verifiable under v2 rules — accept nothing older.
  if (payload_type !== RECEIPT_PAYLOAD_TYPE) {
    return { ok: false, reason: "payload_type not recognized (v2 required; type-swapped receipts also rejected here)" };
  }
  if (typeof payload_b64 !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(payload_b64)) {
    return { ok: false, reason: "missing or malformed payload_b64" };
  }
  const B = new Uint8Array(Buffer.from(payload_b64, "base64"));

  // 1) PRIMARY: verify the issuer signature over PAE(payload_type, B) using
  //    the TRANSPORTED bytes. Nothing about "what was signed" is re-derived.
  const sigOk = await verifyBytes(issuerPublicKey, signature, paeBytes(payload_type, B));
  if (!sigOk) return { ok: false, reason: "signature invalid" };

  // 2) Consistency layer: reject B that is not its own RFC 8785 (JCS)
  //    serialization of the signed body (the transported claim must match
  //    the signed bytes). Reordering JSON keys is fine — JCS determinism
  //    makes the re-serialization identical — but replacing content is not.
  const reCan = canonicalBytes(signedBody(rest));
  const reCanStr = Buffer.from(reCan).toString("base64");
  if (reCanStr !== payload_b64) return { ok: false, reason: "payload is not its own JCS serialization" };

  // 3) content_hash over the signed body; mismatch => tampered.
  const expectHash = await canonicalHash(signedBody(rest));
  if (expectHash !== content_hash) return { ok: false, reason: "content_hash mismatch" };

  return { ok: true };
}

/**
 * Replay decision for a retry under an existing confirmed receipt.
 * Pure hash comparison — CONFLICT is a hash mismatch, not an app judgement.
 *
 * @returns {Promise<"REPLAY"|"CONFLICT"|"UNKNOWN_PRESENT">}
 */
export async function retryDecision(existingReceipt, nextEffectInputs) {
  if (existingReceipt.state === STATE.UNKNOWN) return "UNKNOWN_PRESENT";
  const h = await canonicalHash(nextEffectInputs);
  return h === existingReceipt.effect_inputs_hash ? "REPLAY" : "CONFLICT";
}

/** sha256 over a full receipt's canonical form — used to link the chain. */
export async function receiptLinkHash(receipt) {
  return canonicalHash(receipt);
}

export { canonicalJSON };
