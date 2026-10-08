// External anchor + chain ancestry. This is the continuity boundary Once
// flagged: a self-contained hash chain cannot detect substitution by another
// internally valid chain, because every signature inside the replaced chain
// still verifies. Two distinct properties therefore have to hold:
//
//   1. An independently trusted root OUTSIDE the replaceable ledger records a
//      head (the anchor).
//   2. Any presented head must prove ANCESTRY back to that anchored head: each
//      previous_receipt_hash link must bind the actual parent bytes, and every
//      receipt along the path must verify. A forward sequence is not accepted
//      merely because its sequence number is higher.
//
// This file defines the interface with an in-memory demo anchor. A real
// deployment swaps in a transparency-log head, a public ledger timestamp, a
// quorum notary, or a trusted monotonic service — same interface. Crucially,
// the ANCHOR itself must not be rewriteable by whoever can rewrite the
// ledger: an in-ledger or attacker-replaceable anchor establishes no
// independent continuity.

import { receiptLinkHash, verifyReceipt } from "./receipt.js";

/**
 * An anchor records, at a point in time, the head of a chain as observed by a
 * trust root that the attacker cannot rewrite.
 */
export class MemoryAnchor {
  constructor() {
    this.heads = new Map(); // chainId -> { seq, headHash, at }
  }

  /** Record the latest head for a chain. Returns the anchored record. */
  async publish(chainId, seq, headHash, at = Date.now()) {
    const rec = { seq, headHash, at };
    this.heads.set(chainId, rec);
    return rec;
  }

  async head(chainId) {
    return this.heads.get(chainId) ?? null;
  }
}

/**
 * Append a receipt to a chain and publish the new head to the anchor.
 */
export async function anchorReceipt(chainId, receipt, seq, anchor, at) {
  const headHash = await receiptLinkHash(receipt);
  return anchor.publish(chainId, seq, headHash, at);
}

/**
 * Prove that `headReceipt` descends, unbroken, from a trusted head.
 *
 * Walks previous_receipt_hash links backwards. For every hop it checks:
 *   - the stored link equals the canonical hash of the actual parent bytes
 *     (link integrity — a pointer that names no/wrong parent is rejected),
 *   - the parent receipt verifies cryptographically under a resolved key
 *     (signature + recomputed content_hash; see receipt.verifyReceipt).
 * The walk stops successfully only when it reaches a receipt whose link hash
 * equals `trustedHeadHash`. Reaching genesis without that match is a broken
 * chain, not a valid one.
 *
 * Pure except for the injected resolvers — this reference never fetches.
 *
 * @param {object} headReceipt
 * @param {object} opts
 * @param {(prevHash:string)=>Promise<object|null>} opts.resolveReceipt
 *        return the receipt for a given previous_receipt_hash, or null.
 * @param {(receipt:object)=>Promise<CryptoKey|null>} opts.resolvePublicKey
 *        return the key a receipt must verify under (local issuer vs provider
 *        roots are resolved here; null => the receipt cannot be authenticated).
 * @param {string} opts.trustedHeadHash  hash of the anchor-issued trusted head
 * @param {number} [opts.maxDepth]
 * @returns {Promise<{ok:boolean, depth?:number, reason?:string}>}
 */
export async function verifyAncestry(headReceipt, { resolveReceipt, resolvePublicKey, trustedHeadHash, maxDepth = 1000 }) {
  if (!headReceipt || typeof headReceipt !== "object") return { ok: false, reason: "head is not an object" };
  if (!trustedHeadHash) return { ok: false, reason: "no trusted head hash supplied" };

  // Authenticate the presented head itself before trusting any of its links.
  const headKey = await resolvePublicKey(headReceipt);
  if (!headKey) return { ok: false, reason: "no key for presented head" };
  const headV = await verifyReceipt(headReceipt, headKey);
  if (!headV.ok) return { ok: false, reason: `presented head invalid: ${headV.reason}` };

  let current = headReceipt;
  let currentHash = await receiptLinkHash(current);
  const seen = new Set();

  for (let depth = 0; depth <= maxDepth; depth++) {
    if (currentHash === trustedHeadHash) return { ok: true, depth };

    const prevLink = current.previous_receipt_hash;
    if (prevLink === null || prevLink === undefined) {
      return { ok: false, reason: "broken ancestry: reached genesis without the trusted head" };
    }
    if (seen.has(prevLink)) return { ok: false, reason: "broken ancestry: link cycle" };
    seen.add(prevLink);

    const parent = await resolveReceipt(prevLink);
    if (!parent) return { ok: false, reason: `broken ancestry: missing ancestor ${String(prevLink).slice(0, 12)}` };

    // The link must name the exact parent bytes; otherwise the pointer does
    // not actually commit to this parent.
    const parentHash = await receiptLinkHash(parent);
    if (parentHash !== prevLink) {
      return { ok: false, reason: "link mismatch: previous_receipt_hash does not bind the parent bytes" };
    }

    const parentKey = await resolvePublicKey(parent);
    if (!parentKey) return { ok: false, reason: `no key to authenticate ancestor at depth ${depth + 1}` };
    const pv = await verifyReceipt(parent, parentKey);
    if (!pv.ok) return { ok: false, reason: `ancestor invalid at depth ${depth + 1}: ${pv.reason}` };

    current = parent;
    currentHash = parentHash;
  }
  return { ok: false, reason: `broken ancestry: exceeded max depth ${maxDepth}` };
}

/**
 * Verify a candidate ledger against the external anchor.
 *
 * @param {string} chainId
 * @param {object} candidateHeadReceipt   head presented by the ledger under test
 * @param {number} candidateSeq
 * @param {MemoryAnchor} anchor
 * @param {object} [ancestry]   injected resolvers, required to accept a FORWARD
 *        extension (candidateSeq > anchored seq):
 *          { resolveReceipt, resolvePublicKey }
 * @returns {Promise<{ok:boolean, reason?:string, depth?:number}>}
 */
export async function verifyAgainstAnchor(chainId, candidateHeadReceipt, candidateSeq, anchor, ancestry) {
  const anchored = await anchor.head(chainId);
  if (!anchored) return { ok: false, reason: "no anchor record for chain" };

  const candidateHash = await receiptLinkHash(candidateHeadReceipt);

  // Sequence moved backwards -> rollback, regardless of valid signatures.
  if (candidateSeq < anchored.seq) {
    return { ok: false, reason: `rollback: seq ${candidateSeq} < anchored ${anchored.seq}` };
  }
  // Same sequence but a different head -> replacement of a seen record.
  if (candidateSeq === anchored.seq) {
    if (candidateHash !== anchored.headHash) {
      return { ok: false, reason: "replacement: head differs at anchored seq" };
    }
    return { ok: true, depth: 0 };
  }

  // Higher sequence: only acceptable if the presented head actually extends
  // the anchored head, link by link. A bare higher seq proves nothing.
  if (!ancestry || typeof ancestry.resolveReceipt !== "function" || typeof ancestry.resolvePublicKey !== "function") {
    return { ok: false, reason: "forward extension unproven: ancestry resolvers required" };
  }
  return verifyAncestry(candidateHeadReceipt, {
    resolveReceipt: ancestry.resolveReceipt,
    resolvePublicKey: ancestry.resolvePublicKey,
    trustedHeadHash: anchored.headHash,
  });
}
