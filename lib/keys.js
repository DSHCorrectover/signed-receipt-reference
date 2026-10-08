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

export { b64url };
