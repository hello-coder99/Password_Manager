/**
 * Client-side input validation and backup format verification helpers.
 */

import { validateKdfConfig } from "../crypto/key-derivation.js";
import { CURRENT_ENCRYPTION_VERSION } from "../crypto/vault-crypto.js";

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Validate registration or login form inputs before network dispatch.
 */
export function validateAuthCredentials({ email, loginPassword, isRegistration = false }) {
  const normalizedEmail = String(email ?? "").trim().toLowerCase();
  if (!normalizedEmail || normalizedEmail.length < 5 || !EMAIL_REGEX.test(normalizedEmail)) {
    throw new Error("Enter a valid email address.");
  }

  if (typeof loginPassword !== "string" || loginPassword.length === 0) {
    throw new Error("Enter your account login password.");
  }

  if (isRegistration) {
    if (loginPassword.length < 10) {
      throw new Error("Account login password must be at least 10 characters.");
    }
    if (loginPassword.length > 256) {
      throw new Error("Account login password must not exceed 256 characters.");
    }
    if (loginPassword.trim().toLowerCase() === normalizedEmail) {
      throw new Error("Account login password must not match your email address.");
    }
  }

  return { email: normalizedEmail, loginPassword };
}

/**
 * Validate vault master password creation or change inputs.
 * Ensures the user does not accidentally reuse their account login password as their master password.
 */
export function validateMasterPasswordSetup({
  masterPassword,
  confirmMasterPassword,
  loginPassword = null,
}) {
  if (typeof masterPassword !== "string" || masterPassword.length < 10) {
    throw new Error("Vault master password must be at least 10 characters.");
  }
  if (masterPassword.length > 256) {
    throw new Error("Vault master password must not exceed 256 characters.");
  }
  if (masterPassword !== confirmMasterPassword) {
    throw new Error("Vault master password confirmation does not match.");
  }
  if (loginPassword && masterPassword === loginPassword) {
    throw new Error(
      "Vault master password must be different from your account login password."
    );
  }
  return true;
}

/**
 * Validate an encrypted backup JSON object before attempting decryption or import.
 */
export function validateEncryptedBackupArchive(archive) {
  if (!archive || typeof archive !== "object" || Array.isArray(archive)) {
    throw new Error("Backup file must contain a valid JSON object.");
  }

  if (archive.backup_format !== "aegisvault-encrypted-backup") {
    throw new Error(
      "Unrecognized backup format. Expected 'aegisvault-encrypted-backup'."
    );
  }

  if (archive.backup_version !== 1) {
    throw new Error(
      `Unsupported backup version: ${String(archive.backup_version)}.`
    );
  }

  const settings = archive.vault_settings;
  if (!settings || typeof settings !== "object") {
    throw new Error("Backup archive is missing 'vault_settings'.");
  }

  validateKdfConfig(settings);

  if (
    typeof settings.encrypted_vek !== "string" ||
    settings.encrypted_vek.length < 40
  ) {
    throw new Error("Backup archive contains an invalid 'encrypted_vek'.");
  }
  if (typeof settings.vek_nonce !== "string" || settings.vek_nonce.length < 20) {
    throw new Error("Backup archive contains an invalid 'vek_nonce'.");
  }
  if (settings.encryption_version !== CURRENT_ENCRYPTION_VERSION) {
    throw new Error("Unsupported vault settings encryption version in backup.");
  }

  if (!Array.isArray(archive.items)) {
    throw new Error("Backup archive 'items' must be an array.");
  }

  if (archive.items.length > 2000) {
    throw new Error("Backup archive exceeds maximum supported item count (2000).");
  }

  for (const item of archive.items) {
    if (!item || typeof item !== "object") {
      throw new Error("Backup contains a malformed item entry.");
    }
    if (typeof item.id !== "string" || !UUID_REGEX.test(item.id)) {
      throw new Error("Backup item has an invalid UUID identifier.");
    }
    if (typeof item.ciphertext !== "string" || item.ciphertext.length < 24) {
      throw new Error(`Backup item ${item.id} has invalid ciphertext.`);
    }
    if (typeof item.nonce !== "string" || item.nonce.length < 24) {
      throw new Error(`Backup item ${item.id} has invalid nonce.`);
    }
    if (item.encryption_version !== CURRENT_ENCRYPTION_VERSION) {
      throw new Error(
        `Backup item ${item.id} uses unsupported encryption version.`
      );
    }
  }

  return true;
}
