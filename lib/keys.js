// Issuer / key model over the Web Crypto API (crypto.subtle).
// Zero runtime deps; runs unchanged on Node >= 20 and Workers/V8 isolates.
//
// Two distinct signers exist in this reference, and conflating them is exactly
// the trap to avoid:
//
//   * The LOCAL issuer (the enforcer/observer) signs RECEIPTS recording what
//     it observed. Its key authenticates the record ("this enforcer saw this"),
//     it does NOT make the external effect true.
//
//   * The PROVIDER, when it natively returns a signed effect, is a separate
//     trust root. A provider signature over the effect can be strong evidence
//     the external world changed; an ordinary authenticated GET (e.g. the
//     GitHub canary) is NOT provider-signed truth and must be labelled so.
//
// Trust is therefore represented as a named tier on every claim (see receipt.js),
// never implied by "a signature exists."

const b64url = {
  enc(buf) {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
  dec(str) {
    const pad = str.length % 4 === 0 ? "" : "=".repeat(4 - (str.length % 4));
    const bin = atob(str.replace(/-/g, "+").replace(/_/g, "/") + pad);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  },
};

/** Generate a fresh Ed25519 keypair for a local issuer. */
export async function generateIssuer() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  return pair; // { publicKey: CryptoKey, privateKey: CryptoKey }
}

/** Export an Ed25519 public key to raw 32 bytes, then base64url (a key id). */
export async function exportPublicId(publicKey) {
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", publicKey));
  // last 32 bytes of SPKI are the raw Ed25519 public key
  return b64url.enc(spki.slice(spki.length - 32));
}

/** Export private key as PKCS#8 base64url (for tests/demo; protect in prod). */
export async function exportPrivate(privateKey) {
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);
  return b64url.enc(pkcs8);
}

/** Sign raw bytes with an Ed25519 private key; returns base64url signature. */
export async function signBytes(privateKey, bytes) {
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, privateKey, bytes);
  return b64url.enc(sig);
}

/** Verify a base64url signature against bytes with an Ed25519 public key. */
export async function verifyBytes(publicKey, signatureB64u, bytes) {
  return crypto.subtle.verify({ name: "Ed25519" }, publicKey, b64url.dec(signatureB64u), bytes);
}

// ---------------------------------------------------------------------------
// Small-order public-key rejection (zero-scalar forgery class).
//
// A public key that is an 8-torsion point (identity, (0,-1), the order-4/8
// points, even the all-zero encoding) lets an attacker produce signatures
// verifying under ANY message without holding any secret: pick S, set
// R = S·B; the [k·A] term vanishes. Whether this is accepted depends ENTIRELY
// on the verifier's library (measured 2026-11-10: @noble/curves 2.4.0 default
// and 1.4.2 accept ALL torsion keys; pyca/tweetnacl accept identity; OpenSSL
// rejects but its own CLI 3.5.7 accepts one order-4 encoding). We fail closed
// explicitly instead of relying on the platform's OpenSSL behavior.
// Encodings = the full 8-torsion subgroup, enumerated via [l]P coset math.
// See research/small-order/FINDING.md for the measurement.
// ---------------------------------------------------------------------------
const SMALL_ORDER_ENCODINGS = new Set([
  "0100000000000000000000000000000000000000000000000000000000000000", // identity (order 1)
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // (0,-1)  (order 2)
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order-4/8 pair
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order-4/8 pair
  "0000000000000000000000000000000000000000000000000000000000000080",
  "0000000000000000000000000000000000000000000000000000000000000000", // all-zero encoding
]);

export async function issuerRawBytes(publicKey) {
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", publicKey));
  return spki.slice(spki.length - 32);
}

export function isSmallOrderRaw(raw) {
  const hex = [...new Uint8Array(raw)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return SMALL_ORDER_ENCODINGS.has(hex);
}

export { b64url };
