// Effect establishment — a SEPARATE judgment from signature validity.
//
// Once's most valuable adversarial case: a receipt can be cryptographically
// valid (content_hash matches, signature verifies) while NOT establishing the
// external effect it claims. Cryptographic validity is a property of the
// RECORD; an external effect is a property of the WORLD, and no amount of
// signing upgrades one into the other. A correct verifier must answer both
// questions separately and must never let "signature valid" imply
// "effect established".
//
// Three honest outcomes are possible.
//
// The trust tier is a LABEL, not a right. A receipt whose issuer unilaterally
// writes `trust:"PROVIDER_SIGNED"` does not gain provider authority: the tier
// must match what the authenticating key is actually empowered to prove.
// Hence tier claims are checked against the resolved key ROOT.
//
// This module performs no network I/O. Fresh external observation
// (re-fetching an authenticated endpoint, verifying a provider signature) is
// supplied by the caller and represented by the trust root resolution.

import { verifyReceipt } from "./receipt.js";

/**
 * Trust roots available to a verifier. Conflating local and provider roots is
 * the trap keys.js warns about.
 */
export const KEY_ROOT = Object.freeze({
  LOCAL_ISSUER: "LOCAL_ISSUER",
  AUTHENTICATED_LOOKUP: "AUTHENTICATED_LOOKUP",
  PROVIDER: "PROVIDER",
});

/** Result of judging whether a receipt establishes its external effect. */
export const EFFECT = Object.freeze({
  ESTABLISHED: "EFFECT_ESTABLISHED",
  UNVERIFIED: "EFFECT_NOT_ESTABLISHED",
  UNSUPPORTED_CLAIM: "TRUST_CLAIM_UNSUPPORTED",
});

/**
 * Evaluate whether `receipt` both authenticates and establishes its effect.
 *
 * @param {object} receipt
 * @param {object} opts
 * @param {CryptoKey} opts.publicKey  key the receipt must verify under
 * @param {string} opts.keyRoot       one of KEY_ROOT — what that key is
 *        empowered to prove (a local enforcer key is NEVER "PROVIDER")
 * @param {boolean} [opts.effectObserved]  caller's fresh observation: for
 *        AUTHENTICATED_LOOKUP, whether a current independent read confirms the
 *        effect. Absent/true treated as observed only for PROVIDER roots.
 * @returns {Promise<{crypto_valid:boolean, effect:string, reason:string}>}
 */
export async function evaluateEffect(receipt, { publicKey, keyRoot, effectObserved }) {
  // 1. Cryptographic validity, on its own.
  const v = await verifyReceipt(receipt, publicKey);
  if (!v.ok) {
    return { crypto_valid: false, effect: EFFECT.UNVERIFIED, reason: v.reason };
  }

  // 2. Does the claimed tier match what THIS key is empowered to prove?
  //    This is the "self-escalated trust" attack: a local-issuer key signing
  //    trust:"PROVIDER_SIGNED" is still local truth, not provider truth.
  const claimed = receipt.trust;
  if (claimed === "PROVIDER_SIGNED" && keyRoot !== KEY_ROOT.PROVIDER) {
    return {
      crypto_valid: true,
      effect: EFFECT.UNSUPPORTED_CLAIM,
      reason: `signature valid but PROVIDER_SIGNED tier is not backed by a provider root (resolved: ${keyRoot})`,
    };
  }

  // 3. Given a coherent tier, is the effect actually established?
  if (receipt.state === "UNKNOWN") {
    return {
      crypto_valid: true,
      effect: EFFECT.UNVERIFIED,
      reason: "outcome UNKNOWN: the effect is not confirmed, hold and reconcile",
    };
  }
  if (!receipt.result_ref) {
    return {
      crypto_valid: true,
      effect: EFFECT.UNVERIFIED,
      reason: "signature valid but no result reference locates the effect",
    };
  }

  if (claimed === "LOCAL_OBSERVATION") {
    // The local enforcer can only attest "I observed this". That is not
    // independent evidence the external world changed.
    return {
      crypto_valid: true,
      effect: EFFECT.UNVERIFIED,
      reason: "local observation authenticates the record, not the external effect",
    };
  }

  if (claimed === "AUTHENTICATED_LOOKUP") {
    // Truth rests on a fresh independent read. Without a current observation,
    // a stored lookup is stale, not a proof.
    if (effectObserved !== true) {
      return {
        crypto_valid: true,
        effect: EFFECT.UNVERIFIED,
        reason: "effect rests on an authenticated lookup and no fresh confirming observation was supplied",
      };
    }
    return { crypto_valid: true, effect: EFFECT.ESTABLISHED, reason: "fresh authenticated lookup confirms the effect" };
  }

  if (claimed === "PROVIDER_SIGNED") {
    // A signature from a provider trust root over the effect is strong
    // evidence the external system recorded it.
    return { crypto_valid: true, effect: EFFECT.ESTABLISHED, reason: "provider-signed effect reference" };
  }

  return { crypto_valid: true, effect: EFFECT.UNVERIFIED, reason: `unknown trust tier: ${claimed}` };
}
