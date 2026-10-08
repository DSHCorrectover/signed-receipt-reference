// External anchor: detects rollback / replacement with an older but internally
// valid chain. This is the continuity boundary Once flagged: a self-contained
// hash chain cannot detect substitution by another valid chain, because every
// signature inside the replaced chain still verifies. Detection requires an
// independently trusted root OUTSIDE the replaceable ledger.
//
// This file defines the shape only, with an in-memory demo anchor. A real
// deployment swaps in a transparency-log head, a public ledger timestamp, a
// quorum notary, or a trusted monotonic service — same interface.

import { receiptLinkHash } from "./receipt.js";

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
 * @param {string} chainId
 * @param {object} receipt      signed receipt (should already include previous link)
 * @param {number} seq           monotonic sequence number
 * @param {MemoryAnchor} anchor
 */
export async function anchorReceipt(chainId, receipt, seq, anchor, at) {
  const headHash = await receiptLinkHash(receipt);
  return anchor.publish(chainId, seq, headHash, at);
}

/**
 * Verify a candidate ledger against the external anchor.
 *
 * @param {string} chainId
 * @param {object} candidateHeadReceipt  the current head as presented by the
 *                                        ledger under test
 * @param {number} candidateSeq
 * @param {MemoryAnchor} anchor
 * @returns {Promise<{ok:boolean, reason?:string}>}
 */
export async function verifyAgainstAnchor(chainId, candidateHeadReceipt, candidateSeq, anchor) {
  const anchored = await anchor.head(chainId);
  if (!anchored) return { ok: false, reason: "no anchor record for chain" };

  const candidateHash = await receiptLinkHash(candidateHeadReceipt);

  // Sequence moved backwards -> rollback, regardless of valid signatures.
  if (candidateSeq < anchored.seq) {
    return { ok: false, reason: `rollback: seq ${candidateSeq} < anchored ${anchored.seq}` };
  }
  // Same sequence but a different head -> replacement of a seen record.
  if (candidateSeq === anchored.seq && candidateHash !== anchored.headHash) {
    return { ok: false, reason: "replacement: head differs at anchored seq" };
  }
  // A forward move is only acceptable if it actually extends the known head;
  // full implementations walk the previous_receipt_hash links back to the
  // anchored head here. This reference pins the two failure cases above.
  return { ok: true };
}
