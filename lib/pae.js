// Pre-Authentication Encoding (PAE) — domain separation for signed receipts.
//
// Why this layer exists: a signature authenticates bytes. If the same key
// signs messages of more than one type, a bare payload signature can be
// TRANSPLANTED across types ("same bytes, different payloadType"). The fix is
// a pre-authentication encoding that binds the type INTO the signed bytes.
//
// Form (identical to DSSE / PEP 740 §4.1, and to the field-tested
// signed-evaluation-receipts §4.1):
//
//   PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
//
//   * LEN(x) is the ASCII decimal byte length of x
//   * type is a UTF-8 string (see RECEIPT_PAYLOAD_TYPE, §4.2 semantics:
//     it MUST NOT change for this format; a new format uses a new type)
//   * body is the exact byte string being signed (here: the RFC 8785 (JCS)
//     canonical bytes of the receipt body — JCS remains the producer-side
//     determinism guarantee; PAE is the cross-type/domain guarantee)
//
// Verification consumes the TRANSPORTED body bytes (payload_b64) directly and
// never re-derives what was signed; a separate consistency check rejects
// bodies whose own JCS re-serialization differs from B.

export const PAE_PREFIX = "DSSEv1";

/** Fixed payload type for receipt format v2 (§4.2: new format ⇒ new type). */
export const RECEIPT_PAYLOAD_TYPE =
  "application/vnd.correctover.receipt.v2+json";

const te = new TextEncoder();

/** ASCII decimal byte length (LEN in the PAE grammar). */
function lenOf(bytes) {
  return String(bytes.length);
}

/**
 * PAE(type, bodyBytes) -> Uint8Array
 * Pure byte plumbing, no crypto, no I/O.
 */
export function paeBytes(type, bodyBytes) {
  if (typeof type !== "string") throw new TypeError("type must be a string");
  if (!(bodyBytes instanceof Uint8Array)) throw new TypeError("body must be bytes");
  const typeBytes = te.encode(type);
  const head = te.encode(`${PAE_PREFIX} ${lenOf(typeBytes)} `);
  const mid = te.encode(`${lenOf(bodyBytes)} `);
  const out = new Uint8Array(head.length + typeBytes.length + mid.length + bodyBytes.length);
  out.set(head, 0);
  out.set(typeBytes, head.length);
  out.set(mid, head.length + typeBytes.length);
  out.set(bodyBytes, head.length + typeBytes.length + mid.length);
  return out;
}

/** UTF-8 bytes of a string (helper for callers holding strings, not bytes). */
export function utf8Bytes(s) {
  return te.encode(s);
}
