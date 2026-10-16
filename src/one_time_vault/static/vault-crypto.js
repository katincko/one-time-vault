// @ts-check
// Everything the browser does with secrets. No network here.
//
// One random 256-bit key per secret, never sent anywhere. HKDF-SHA256 splits it into two
// subkeys by label: "encryption" (AES-256-GCM) and "password" (reserved for the access
// password of a later lot). The plaintext is padded to blocks of 256 bytes before encrypting,
// so the ciphertext length only tells the block count.

/** @typedef {Uint8Array<ArrayBuffer>} Bytes */

export const KEY_BYTES = 32;
export const IV_BYTES = 12;
export const BLOCK_BYTES = 256;
export const MAX_TEXT_BYTES = 10 * 1024;

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

/**
 * @param {Bytes} bytes
 * @returns {string} base64url without padding
 */
export function b64urlEncode(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/**
 * Strict: only the base64url alphabet, no padding, and it must round-trip.
 * @param {string} text
 * @returns {Bytes}
 */
export function b64urlDecode(text) {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) throw new Error("bad base64url");
  const std = text.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(std + "=".repeat((4 - (std.length % 4)) % 4));
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  if (b64urlEncode(bytes) !== text) throw new Error("non-canonical base64url");
  return bytes;
}

/**
 * The key from the link fragment, or null unless it is a whole 256-bit key.
 * @param {string} fragment text after the #
 * @returns {Bytes | null}
 */
export function parseKey(fragment) {
  try {
    const key = b64urlDecode(fragment);
    return key.length === KEY_BYTES ? key : null;
  } catch {
    return null;
  }
}

/** @returns {Bytes} */
export function newKey() {
  return crypto.getRandomValues(new Uint8Array(KEY_BYTES));
}

/**
 * ISO/IEC 7816-4 padding: 0x80, then zeros, up to a multiple of 256 bytes.
 * @param {Bytes} plain
 * @returns {Bytes}
 */
export function pad(plain) {
  const size = (Math.floor(plain.length / BLOCK_BYTES) + 1) * BLOCK_BYTES;
  const out = new Uint8Array(size);
  out.set(plain);
  out[plain.length] = 0x80;
  return out;
}

/**
 * @param {Bytes} padded
 * @returns {Bytes}
 */
export function unpad(padded) {
  let end = padded.length;
  while (end > 0 && padded[end - 1] === 0) end--;
  if (end === 0 || padded[end - 1] !== 0x80) throw new Error("bad padding");
  return padded.slice(0, end - 1);
}

/**
 * @param {Bytes} key 256-bit secret key
 * @param {string} label
 * @param {KeyUsage[]} usages
 */
async function hkdf(key, label, usages) {
  const base = await crypto.subtle.importKey("raw", key, "HKDF", false, usages);
  return {
    base,
    params: { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: encoder.encode(label) },
  };
}

/**
 * @param {Bytes} key
 * @returns {Promise<{encryption: CryptoKey, password: Bytes}>}
 */
export async function deriveKeys(key) {
  const enc = await hkdf(key, "encryption", ["deriveKey"]);
  const pw = await hkdf(key, "password", ["deriveBits"]);
  return {
    encryption: await crypto.subtle.deriveKey(
      enc.params,
      enc.base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    ),
    password: new Uint8Array(await crypto.subtle.deriveBits(pw.params, pw.base, 256)),
  };
}

/**
 * @param {string} text
 * @param {Bytes} key
 * @returns {Promise<{iv: Bytes, ciphertext: Bytes}>}
 */
export async function encrypt(text, key) {
  const plain = encoder.encode(text);
  if (plain.length === 0 || plain.length > MAX_TEXT_BYTES) throw new Error("bad length");
  const { encryption } = await deriveKeys(key);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const sealed = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryption, pad(plain));
  return { iv, ciphertext: new Uint8Array(sealed) };
}

/**
 * Throws if the key is wrong or anything (iv, ciphertext, tag) was altered.
 * @param {Bytes} key
 * @param {Bytes} iv
 * @param {Bytes} ciphertext
 * @returns {Promise<string>}
 */
export async function decrypt(key, iv, ciphertext) {
  const { encryption } = await deriveKeys(key);
  const padded = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, encryption, ciphertext);
  return decoder.decode(unpad(new Uint8Array(padded)));
}
