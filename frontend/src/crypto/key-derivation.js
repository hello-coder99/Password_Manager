/**
 * Versioned Argon2id key derivation in the browser using libsodium.js.
 * Validates KDF parameters strictly before derivation to prevent DoS attacks.
 */

import {
  ensureSodiumUint8Array,
  fromBase64,
  getSodium,
  randomBytes,
  toBase64,
} from "./sodium.js";

export const KDF_ALGORITHM_ARGON2ID13 = "argon2id13";
export const CURRENT_KDF_VERSION = 1;
export const SALT_BYTES = 16;
export const WRAPPING_KEY_BYTES = 32;

// Bounded Argon2id parameter limits to prevent CPU/memory denial-of-service
export const KDF_BOUNDS = Object.freeze({
  minOpslimit: 2,
  maxOpslimit: 10,
  minMemlimit: 16 * 1024 * 1024,   // 16 MiB
  maxMemlimit: 256 * 1024 * 1024,  // 256 MiB
});

// Default interactive parameters for browser key derivation (64 MiB, 3 iterations)
export const DEFAULT_KDF_PARAMS = Object.freeze({
  opslimit: 3,
  memlimit: 64 * 1024 * 1024,
});

/**
 * Validate KDF configuration and bounds before executing Argon2id.
 * @param {object} config
 */
export function validateKdfConfig(config) {
  if (!config || typeof config !== "object") {
    throw new Error("Missing KDF configuration.");
  }

  const { kdf_algorithm, kdf_version, kdf_params } = config;

  if (kdf_algorithm !== KDF_ALGORITHM_ARGON2ID13) {
    throw new Error(`Unsupported KDF algorithm: ${String(kdf_algorithm)}`);
  }

  if (kdf_version !== CURRENT_KDF_VERSION) {
    throw new Error(`Unsupported KDF version: ${String(kdf_version)}`);
  }

  if (!kdf_params || typeof kdf_params !== "object") {
    throw new Error("Missing KDF parameters.");
  }

  const { opslimit, memlimit } = kdf_params;

  if (
    !Number.isInteger(opslimit) ||
    opslimit < KDF_BOUNDS.minOpslimit ||
    opslimit > KDF_BOUNDS.maxOpslimit
  ) {
    throw new Error(
      `KDF opslimit (${opslimit}) is outside safe bounds [${KDF_BOUNDS.minOpslimit}, ${KDF_BOUNDS.maxOpslimit}].`
    );
  }

  if (
    !Number.isInteger(memlimit) ||
    memlimit < KDF_BOUNDS.minMemlimit ||
    memlimit > KDF_BOUNDS.maxMemlimit
  ) {
    throw new Error(
      `KDF memlimit (${memlimit}) is outside safe bounds [${KDF_BOUNDS.minMemlimit}, ${KDF_BOUNDS.maxMemlimit}].`
    );
  }
}

/**
 * Generate a fresh 16-byte random salt encoded as Base64.
 * @returns {Promise<string>}
 */
export async function generateKdfSalt() {
  const saltBytes = await randomBytes(SALT_BYTES);
  return toBase64(saltBytes);
}

/**
 * Derive a 256-bit wrapping key from a Vault Master Password and KDF configuration.
 * @param {string} masterPassword
 * @param {object} kdfConfig
 * @returns {Promise<Uint8Array>} 32-byte derived wrapping key
 */
export async function deriveWrappingKey(masterPassword, kdfConfig) {
  if (typeof masterPassword !== "string" || masterPassword.length === 0) {
    throw new Error("Vault master password must be a non-empty string.");
  }

  validateKdfConfig(kdfConfig);

  const sodium = await getSodium();
  const saltBytes = await fromBase64(kdfConfig.kdf_salt);

  if (saltBytes.length !== sodium.crypto_pwhash_SALTBYTES) {
    throw new Error(
      `Invalid KDF salt length: expected ${sodium.crypto_pwhash_SALTBYTES} bytes.`
    );
  }

  const { opslimit, memlimit } = kdfConfig.kdf_params;

  const derived = sodium.crypto_pwhash(
    WRAPPING_KEY_BYTES,
    masterPassword,
    saltBytes,
    opslimit,
    memlimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13
  );
  return ensureSodiumUint8Array(sodium, derived);
}
