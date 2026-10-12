/**
 * Libsodium WebAssembly initialization and safe memory/encoding helpers.
 * Uses libsodium-wrappers-sumo to provide Argon2id (crypto_pwhash) and
 * XChaCha20-Poly1305 authenticated encryption.
 */

import _sodium from "libsodium-wrappers-sumo";

let sodiumInstance = null;

/**
 * Initialize and return the ready libsodium instance.
 */
export async function getSodium() {
  if (sodiumInstance) {
    return sodiumInstance;
  }
  const candidate = _sodium && _sodium.ready ? _sodium : _sodium?.default;
  if (!candidate) {
    throw new Error("Failed to load libsodium cryptographic module.");
  }
  await candidate.ready;
  sodiumInstance = candidate;
  return sodiumInstance;
}

/**
 * Generate cryptographically secure random bytes via libsodium.
 * @param {number} byteLength
 * @returns {Promise<Uint8Array>}
 */
export async function randomBytes(byteLength) {
  if (!Number.isInteger(byteLength) || byteLength <= 0) {
    throw new Error("byteLength must be a positive integer.");
  }
  const sodium = await getSodium();
  return ensureSodiumUint8Array(sodium, sodium.randombytes_buf(byteLength));
}

/**
 * Ensure a Uint8Array belongs to the current globalThis.Uint8Array realm.
 * @param {any} _sodium
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */
export function ensureSodiumUint8Array(_sodium, bytes) {
  if (bytes instanceof Uint8Array) {
    return bytes;
  }
  return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

/**
 * Encode a Uint8Array to standard padded Base64.
 * @param {Uint8Array} bytes
 * @returns {Promise<string>}
 */
export async function toBase64(bytes) {
  if (!(bytes instanceof Uint8Array) && !ArrayBuffer.isView(bytes)) {
    throw new TypeError("Expected Uint8Array for Base64 encoding.");
  }
  const sodium = await getSodium();
  return sodium.to_base64(
    ensureSodiumUint8Array(sodium, bytes),
    sodium.base64_variants.ORIGINAL
  );
}

/**
 * Decode a standard padded Base64 string into a Uint8Array.
 * @param {string} encoded
 * @returns {Promise<Uint8Array>}
 */
export async function fromBase64(encoded) {
  if (typeof encoded !== "string" || encoded.trim().length === 0) {
    throw new Error("Invalid Base64 string.");
  }
  const sodium = await getSodium();
  const decoded = sodium.from_base64(
    encoded.trim(),
    sodium.base64_variants.ORIGINAL
  );
  return ensureSodiumUint8Array(sodium, decoded);
}

/**
 * Best-effort zeroing of sensitive Uint8Array buffers in memory.
 * Note: JavaScript engines do not guarantee erasure of immutable strings or GC copies,
 * but Uint8Array key material can and should be overwritten immediately when locked.
 * @param {...(Uint8Array|null|undefined)} buffers
 */
export function zeroBuffers(...buffers) {
  for (const buf of buffers) {
    if (buf && ArrayBuffer.isView(buf) && typeof buf.fill === "function") {
      buf.fill(0);
    }
  }
}
