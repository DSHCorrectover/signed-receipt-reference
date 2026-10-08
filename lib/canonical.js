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
 * Shortest round-trippable representation, returned as normalized scientific
 * parts: { neg, digits, exp } where value = (neg?-1:1) * 0.digits * 10^(exp+1)
 * i.e. digits[0] is the leading significant digit at weight 10^exp.
 *
 * Only relies on Number.prototype.toPrecision and round-trip parsing, both
 * stable across ECMAScript engines — not on JSON.stringify's incidental
 * exponent cut-off — so the result is identical on every conforming runtime.
 */
function shortestScientific(n) {
  let s = null;
  for (let p = 1; p <= 17; p++) {
    const c = n.toPrecision(p);
    if (Number(c) === n) {
      s = c;
      break;
    }
  }
  if (s === null) throw new TypeError("Could not find shortest round-trip for " + n);

  let neg = false;
  if (s[0] === "-") {
    neg = true;
    s = s.slice(1);
  }
  const m = s.match(/^(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/);
  if (!m) throw new TypeError("Unparseable number form: " + s);
  const intPart = m[1];
  let digits = intPart + (m[2] ?? "");
  let exp = m[3] ? parseInt(m[3], 10) : 0;
  exp += intPart.length - 1; // weight of the first integer digit

  // Drop leading zeros ("0.00123" -> digits "000123"), adjusting the weight.
  const first = digits.search(/[1-9]/);
  if (first > 0) {
    digits = digits.slice(first);
    exp -= first;
  }
  digits = digits.replace(/0+$/, "") || "0"; // shortest form has no trailing zeros
  return { neg, digits, exp };
}

/**
 * Deterministic string for a finite number per JCS §3.2.2.1 (RFC 8785):
 *   - -0 serializes as "0"
 *   - integers with magnitude <= 2^53-1 print with no exponent
 *   - otherwise the shortest round-trippable form is used in FIXED notation
 *     when the leading-digit exponent is in [-6, 20], else scientific notation
 *     ("e+"/"e-"). This yields exactly the called-out case
 *     {"big":1e21} -> {"big":1e+21}, while 1e20 stays a fixed integer.
 */
export function canonicalNumber(n) {
  if (typeof n !== "number" || !Number.isFinite(n)) {
    throw new TypeError("Cannot canonicalize non-finite number: " + n);
  }
  if (Object.is(n, -0)) return "0";
  if (isInteger(n) && n >= MIN_SAFE_INT && n <= MAX_SAFE_INT) {
    return String(n); // never an exponent for safe integers
  }

  const { neg, digits, exp } = shortestScientific(n);
  let out;
  if (exp >= -6 && exp <= 20) {
    if (exp < 0) {
      out = "0." + "0".repeat(-exp - 1) + digits;
    } else if (exp >= digits.length - 1) {
      out = digits + "0".repeat(exp - (digits.length - 1));
    } else {
      out = digits.slice(0, exp + 1) + "." + digits.slice(exp + 1);
    }
  } else {
    const head = digits[0];
    const rest = digits.slice(1);
    out = head + (rest ? "." + rest : "") + "e" + (exp >= 0 ? "+" : "") + String(exp);
  }
  return (neg ? "-" : "") + out;
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
