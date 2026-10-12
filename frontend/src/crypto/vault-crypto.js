/**
 * Client-side envelope encryption and authenticated vault item cryptography.
 * Uses XChaCha20-Poly1305 (IETF) via libsodium.js with strict AAD binding.
 */

import {
  CURRENT_KDF_VERSION,
  DEFAULT_KDF_PARAMS,
  KDF_ALGORITHM_ARGON2ID13,
  deriveWrappingKey,
  generateKdfSalt,
  validateKdfConfig,
} from "./key-derivation.js";
import {
  ensureSodiumUint8Array,
  fromBase64,
  getSodium,
  randomBytes,
  toBase64,
  zeroBuffers,
} from "./sodium.js";

export const CURRENT_ENCRYPTION_VERSION = 1;
export const VEK_BYTES = 32;
export const XCHACHA20_NONCE_BYTES = 24;
export const POLY1305_TAG_BYTES = 16;

/**
 * Construct canonical Authenticated Additional Data (AAD) for VEK wrapping.
 * Binds the wrapped VEK to the owner's user_id and format versions.
 */
function buildVekWrapAad(sodium, { userId, encryptionVersion, kdfVersion }) {
  if (typeof userId !== "string" || !userId.trim()) {
    throw new Error("userId is required for VEK AAD binding.");
  }
  const canonical = JSON.stringify({
    purpose: "aegisvault-vek-wrap",
    u: userId,
    v: encryptionVersion,
    kv: kdfVersion,
  });
  return ensureSodiumUint8Array(sodium, sodium.from_string(canonical));
}

/**
 * Construct canonical Authenticated Additional Data (AAD) for a vault item.
 * Binds each encrypted item to its user, item identifier, and encryption version
 * so ciphertext cannot be moved between records or users.
 */
export async function buildItemAad({ userId, itemId, encryptionVersion }) {
  if (typeof userId !== "string" || !userId.trim()) {
    throw new Error("userId is required for item AAD binding.");
  }
  if (typeof itemId !== "string" || !itemId.trim()) {
    throw new Error("itemId is required for item AAD binding.");
  }
  if (encryptionVersion !== CURRENT_ENCRYPTION_VERSION) {
    throw new Error(`Unsupported encryption version: ${String(encryptionVersion)}`);
  }
  const sodium = await getSodium();
  const canonical = JSON.stringify({
    purpose: "aegisvault-item",
    u: userId,
    i: itemId,
    v: encryptionVersion,
  });
  return ensureSodiumUint8Array(sodium, sodium.from_string(canonical));
}

/**
 * Generate a fresh 256-bit Vault Encryption Key (VEK).
 * @returns {Promise<Uint8Array>}
 */
export async function generateVaultEncryptionKey() {
  const sodium = await getSodium();
  return ensureSodiumUint8Array(
    sodium,
    sodium.crypto_aead_xchacha20poly1305_ietf_keygen()
  );
}

/**
 * Wrap a 256-bit VEK using a master password and fresh random salt & nonce.
 * @param {object} options
 * @param {string} options.masterPassword
 * @param {string} options.userId
 * @param {Uint8Array} [options.existingVek]
 * @param {object} [options.kdfParams]
 * @returns {Promise<{vek: Uint8Array, envelope: object}>}
 */
export async function createWrappedVaultEnvelope({
  masterPassword,
  userId,
  existingVek = null,
  kdfParams = DEFAULT_KDF_PARAMS,
}) {
  const sodium = await getSodium();
  const vek =
    existingVek && ArrayBuffer.isView(existingVek)
      ? ensureSodiumUint8Array(sodium, new Uint8Array(existingVek))
      : await generateVaultEncryptionKey();

  if (vek.length !== VEK_BYTES) {
    throw new Error("VEK must be exactly 32 bytes (256 bits).");
  }

  const kdfSalt = await generateKdfSalt();
  const kdfConfig = {
    kdf_algorithm: KDF_ALGORITHM_ARGON2ID13,
    kdf_version: CURRENT_KDF_VERSION,
    kdf_salt: kdfSalt,
    kdf_params: {
      opslimit: kdfParams.opslimit,
      memlimit: kdfParams.memlimit,
    },
  };

  let wrappingKey = null;
  try {
    wrappingKey = await deriveWrappingKey(masterPassword, kdfConfig);
    const vekNonceBytes = await randomBytes(XCHACHA20_NONCE_BYTES);
    const aadBytes = buildVekWrapAad(sodium, {
      userId,
      encryptionVersion: CURRENT_ENCRYPTION_VERSION,
      kdfVersion: CURRENT_KDF_VERSION,
    });

    const encryptedVekBytes =
      sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        vek,
        aadBytes,
        null,
        vekNonceBytes,
        wrappingKey
      );

    return {
      vek,
      envelope: {
        ...kdfConfig,
        encrypted_vek: await toBase64(encryptedVekBytes),
        vek_nonce: await toBase64(vekNonceBytes),
        encryption_version: CURRENT_ENCRYPTION_VERSION,
      },
    };
  } finally {
    zeroBuffers(wrappingKey);
  }
}

/**
 * Unlock the Vault Encryption Key (VEK) using the user's master password and stored settings.
 * Throws an error if the master password is wrong or if the envelope/AAD was tampered with.
 * @param {object} options
 * @param {string} options.masterPassword
 * @param {object} options.vaultSettings
 * @param {string} options.userId
 * @returns {Promise<Uint8Array>} 32-byte raw VEK
 */
export async function unlockVaultEncryptionKey({
  masterPassword,
  vaultSettings,
  userId,
}) {
  if (!vaultSettings || typeof vaultSettings !== "object") {
    throw new Error("Missing vault settings.");
  }
  if (vaultSettings.encryption_version !== CURRENT_ENCRYPTION_VERSION) {
    throw new Error(
      `Unsupported vault encryption version: ${String(vaultSettings.encryption_version)}`
    );
  }

  validateKdfConfig(vaultSettings);

  const sodium = await getSodium();
  const encryptedVekBytes = await fromBase64(vaultSettings.encrypted_vek);
  const vekNonceBytes = await fromBase64(vaultSettings.vek_nonce);

  if (encryptedVekBytes.length !== VEK_BYTES + POLY1305_TAG_BYTES) {
    throw new Error("Invalid encrypted VEK length.");
  }
  if (vekNonceBytes.length !== XCHACHA20_NONCE_BYTES) {
    throw new Error("Invalid VEK nonce length.");
  }

  let wrappingKey = null;
  try {
    wrappingKey = await deriveWrappingKey(masterPassword, vaultSettings);
    const aadBytes = buildVekWrapAad(sodium, {
      userId,
      encryptionVersion: vaultSettings.encryption_version,
      kdfVersion: vaultSettings.kdf_version,
    });

    const vek = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      encryptedVekBytes,
      aadBytes,
      vekNonceBytes,
      wrappingKey
    );

    if (vek.length !== VEK_BYTES) {
      throw new Error("Unwrapped VEK has invalid length.");
    }
    return vek;
  } catch {
    throw new Error("Invalid master password or corrupted vault key envelope.");
  } finally {
    zeroBuffers(wrappingKey);
  }
}

/**
 * Re-wrap the existing VEK with a new master password, fresh salt, and fresh nonce.
 * Verifies the current master password first and never modifies item ciphertexts.
 */
export async function rewrapVekWithNewMasterPassword({
  currentMasterPassword,
  newMasterPassword,
  vaultSettings,
  userId,
  kdfParams = DEFAULT_KDF_PARAMS,
}) {
  if (typeof newMasterPassword !== "string" || newMasterPassword.length < 10) {
    throw new Error("New master password must be at least 10 characters.");
  }

  const unwrappedVek = await unlockVaultEncryptionKey({
    masterPassword: currentMasterPassword,
    vaultSettings,
    userId,
  });

  try {
    const { vek, envelope } = await createWrappedVaultEnvelope({
      masterPassword: newMasterPassword,
      userId,
      existingVek: unwrappedVek,
      kdfParams,
    });
    return { vek, envelope };
  } finally {
    zeroBuffers(unwrappedVek);
  }
}

/**
 * Normalize and validate a plaintext credential record before encryption.
 */
export function normalizePlaintextItem(entry) {
  if (!entry || typeof entry !== "object") {
    throw new Error("Credential entry must be an object.");
  }
  const title = String(entry.title ?? "").trim();
  if (!title) {
    throw new Error("Credential title is required.");
  }

  const rawTags = Array.isArray(entry.tags)
    ? entry.tags
    : typeof entry.tags === "string"
      ? entry.tags.split(",")
      : [];

  const normalizedTags = rawTags
    .map((t) => String(t).trim())
    .filter((t) => t.length > 0);

  return {
    title,
    username: String(entry.username ?? "").trim(),
    password: String(entry.password ?? ""),
    url: String(entry.url ?? "").trim(),
    notes: String(entry.notes ?? "").trim(),
    category: String(entry.category ?? "General").trim() || "General",
    tags: normalizedTags,
    favorite: Boolean(entry.favorite),
  };
}

/**
 * Encrypt a vault credential object into a single authenticated ciphertext payload.
 * @param {object} options
 * @param {Uint8Array} options.vek 32-byte unlocked VEK
 * @param {string} options.userId Owner user UUID
 * @param {string} options.itemId Record UUID
 * @param {object} options.plaintextEntry Credential fields
 */
export async function encryptVaultItem({
  vek,
  userId,
  itemId,
  plaintextEntry,
}) {
  if (!vek || !ArrayBuffer.isView(vek) || vek.byteLength !== VEK_BYTES) {
    throw new Error("Vault is locked or VEK is invalid.");
  }

  const normalized = normalizePlaintextItem(plaintextEntry);
  const sodium = await getSodium();
  const sodiumVek = ensureSodiumUint8Array(sodium, vek);
  const nonceBytes = await randomBytes(XCHACHA20_NONCE_BYTES);
  const aadBytes = await buildItemAad({
    userId,
    itemId,
    encryptionVersion: CURRENT_ENCRYPTION_VERSION,
  });

  const plaintextBytes = ensureSodiumUint8Array(
    sodium,
    sodium.from_string(JSON.stringify(normalized))
  );
  try {
    const ciphertextBytes =
      sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintextBytes,
        aadBytes,
        null,
        nonceBytes,
        sodiumVek
      );

    return {
      id: itemId,
      ciphertext: await toBase64(ciphertextBytes),
      nonce: await toBase64(nonceBytes),
      encryption_version: CURRENT_ENCRYPTION_VERSION,
    };
  } finally {
    zeroBuffers(plaintextBytes);
  }
}

/**
 * Decrypt and verify an encrypted vault item record using the unlocked VEK and AAD.
 * @param {object} options
 * @param {Uint8Array} options.vek 32-byte unlocked VEK
 * @param {string} options.userId Expected owner user UUID
 * @param {object} options.encryptedRecord Record from API ({id, ciphertext, nonce, encryption_version})
 */
export async function decryptVaultItem({ vek, userId, encryptedRecord }) {
  if (!vek || !ArrayBuffer.isView(vek) || vek.byteLength !== VEK_BYTES) {
    throw new Error("Vault is locked or VEK is invalid.");
  }
  if (!encryptedRecord || typeof encryptedRecord !== "object") {
    throw new Error("Missing encrypted vault item record.");
  }

  const { id, ciphertext, nonce, encryption_version } = encryptedRecord;
  if (encryption_version !== CURRENT_ENCRYPTION_VERSION) {
    throw new Error(
      `Unsupported item encryption version: ${String(encryption_version)}`
    );
  }

  const sodium = await getSodium();
  const sodiumVek = ensureSodiumUint8Array(sodium, vek);
  const ciphertextBytes = await fromBase64(ciphertext);
  const nonceBytes = await fromBase64(nonce);

  if (nonceBytes.length !== XCHACHA20_NONCE_BYTES) {
    throw new Error("Invalid item nonce length.");
  }
  if (ciphertextBytes.length <= POLY1305_TAG_BYTES) {
    throw new Error("Invalid item ciphertext length.");
  }

  const aadBytes = await buildItemAad({
    userId,
    itemId: id,
    encryptionVersion: encryption_version,
  });

  let decryptedBytes = null;
  try {
    decryptedBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      ciphertextBytes,
      aadBytes,
      nonceBytes,
      sodiumVek
    );
    const jsonString = sodium.to_string(decryptedBytes);
    const parsed = JSON.parse(jsonString);
    return {
      id,
      ...normalizePlaintextItem(parsed),
      encryption_version,
      created_at: encryptedRecord.created_at || null,
      updated_at: encryptedRecord.updated_at || null,
    };
  } catch {
    throw new Error(
      `Failed to authenticate or decrypt vault item ${String(id)}. Ciphertext or AAD may have been tampered with.`
    );
  } finally {
    zeroBuffers(decryptedBytes);
  }
}
