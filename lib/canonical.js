// JCS-style deterministic canonical JSON (RFC 8785 method), pure ESM.
//
// Why this module stands ALONE: a signature only authenticates whatever bytes
// were signed. If canonicalization is wrong or incomplete, signing it produces
// tamper-evident garbage — the signature proves the garbage is unchanged, not
// that it is correct. So canonicalization is its own layer, with its own
// positive/negative vectors (see test/vectors.test.mjs), independent of keys.
//
// Scope of this reference:
//   * object keys sorted by UTF-16 code-unit order (JCS §3.2.3)
//   * arrays preserved in order
//   * deterministic number serialization (JCS §3.2.2.1):
//       - integers in [-(2^53)+1, 2^53-1] serialize without exponent
//       - other finite numbers use the shortest round-trippable representation
//   * strings/booleans/null via JSON.stringify (already UTF-8 safe)
// Deliberately rejected (fail closed, see canonicalJSON):
//   * undefined / functions / symbols  -> not representable
//   * BigInt                           -> use a string; never silently coerce
//
// This is a compact, readable reference, not a line-for-line RFC 8785
// implementation. The pinned vectors document exactly which cases are covered.

const MAX_SAFE_INT = Number.MAX_SAFE_INTEGER; // 2^53 - 1
const MIN_SAFE_INT = Number.MIN_SAFE_INTEGER; // -(2^53) + 1

function isInteger(n) {
  return Number.isInteger(n);
}

/**
 * Deterministic string for a finite number per JCS §3.2.2.1.
 * Safe integers print in fixed form; everything else uses the shortest
 * round-trippable ECMAScript number string (which already collapses the
 * "1e+21" case JCS calls out: {"big":1e21} -> {"big":1e+21}).
 */
export function canonicalNumber(n) {
  if (!Number.isFinite(n)) {
    throw new TypeError("Cannot canonicalize non-finite number: " + n);
  }
  if (isInteger(n) && n >= MIN_SAFE_INT && n <= MAX_SAFE_INT) {
    return String(n); // never an exponent for safe integers
  }
  // Non-integer or beyond safe-int range: shortest round-trippable form.
  let s = JSON.stringify(n);
  // Normalize the exponent marker to the JCS style ("e+" / "e-").
  // V8 emits "1e+21"; keep it. Engines that emit "1E+21" are lowercased.
  s = s.replace(/E/, "e");
  return s;
}

/** Recursively produce the canonical structure (keys sorted). */
export function canonical(value) {
  if (value === null) return null;
  const t = typeof value;
  if (t === "string" || t === "boolean") return value;
  if (t === "number") return value; // number text fixed at serialization time
  if (t === "bigint") {
    throw new TypeError("BigInt is not representable in JCS; pass a string");
  }
  if (t === "undefined" || t === "function" || t === "symbol") {
    throw new TypeError("Value is not representable in JSON: " + String(value));
  }
  if (Array.isArray(value)) {
    return value.map(canonical);
  }
  const out = {};
  for (const k of Object.keys(value).sort()) {
    out[k] = canonical(value[k]);
  }
  return out;
}

/** Serializer with per-type number handling. */
function toJson(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "number") return canonicalNumber(value);
  if (t === "boolean") return value ? "true" : "false";
  if (t === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(toJson).join(",") + "]";
  }
  return "{" + Object.keys(value).map((k) => JSON.stringify(k) + ":" + toJson(value[k])).join(",") + "}";
}

/** Canonical JSON string, no whitespace. */
export function canonicalJSON(value) {
  return toJson(canonical(value));
}

/** Canonical UTF-8 bytes — the exact thing that gets hashed/signed. */
export function canonicalBytes(value) {
  return new TextEncoder().encode(canonicalJSON(value));
}

/** sha256 hex digest over the canonical bytes of a value. */
export async function canonicalHash(value) {
  const digest = await crypto.subtle.digest("SHA-256", canonicalBytes(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
