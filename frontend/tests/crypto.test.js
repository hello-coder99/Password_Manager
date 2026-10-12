import { describe, expect, it } from "vitest";
import {
  KDF_ALGORITHM_ARGON2ID13,
  deriveWrappingKey,
  generateKdfSalt,
  validateKdfConfig,
} from "../src/crypto/key-derivation.js";
import { fromBase64, toBase64 } from "../src/crypto/sodium.js";
import {
  CURRENT_ENCRYPTION_VERSION,
  createWrappedVaultEnvelope,
  decryptVaultItem,
  encryptVaultItem,
  rewrapVekWithNewMasterPassword,
  unlockVaultEncryptionKey,
} from "../src/crypto/vault-crypto.js";
import {
  estimatePasswordStrength,
  generatePassword,
} from "../src/generator/password-generator.js";
import { validateEncryptedBackupArchive } from "../src/utils/validation.js";
import { VaultStateManager } from "../src/vault/vault-state.js";

// Use minimum bounded Argon2id parameters (16 MiB, opslimit 2) in unit tests for fast execution
const TEST_KDF_PARAMS = Object.freeze({
  opslimit: 2,
  memlimit: 16 * 1024 * 1024,
});

describe("Client-Side Cryptography & Key Management", () => {
  it("performs full VEK wrapping, unlocking, and item encryption/decryption round trip", async () => {
    const userId = "2c9d8420-8b2a-4c31-9a14-09911a2b3c4d";
    const itemId = "7f112233-4455-4666-8777-8899aabbccdd";
    const masterPassword = "MasterVaultSecret#2026!ZeroKnowledge";

    const { vek, envelope } = await createWrappedVaultEnvelope({
      masterPassword,
      userId,
      kdfParams: TEST_KDF_PARAMS,
    });

    expect(vek).toBeInstanceOf(Uint8Array);
    expect(vek.length).toBe(32);

    const unlockedVek = await unlockVaultEncryptionKey({
      masterPassword,
      vaultSettings: envelope,
      userId,
    });
    expect(unlockedVek).toEqual(vek);

    const plaintextEntry = {
      title: "Production Bastion SSH",
      username: "secops-admin",
      password: "bastionKey#9988!Xz",
      url: "https://bastion.internal.example.edu",
      notes: "Use hardware token for second factor.",
      category: "Infrastructure",
      tags: ["ssh", "production"],
      favorite: true,
    };

    const encryptedRecord = await encryptVaultItem({
      vek: unlockedVek,
      userId,
      itemId,
      plaintextEntry,
    });

    expect(encryptedRecord.id).toBe(itemId);
    expect(encryptedRecord.ciphertext).not.toContain("Production Bastion SSH");
    expect(encryptedRecord.ciphertext).not.toContain("bastionKey#9988!Xz");

    const decrypted = await decryptVaultItem({
      vek: unlockedVek,
      userId,
      encryptedRecord,
    });

    expect(decrypted.id).toBe(itemId);
    expect(decrypted.title).toBe(plaintextEntry.title);
    expect(decrypted.username).toBe(plaintextEntry.username);
    expect(decrypted.password).toBe(plaintextEntry.password);
    expect(decrypted.url).toBe(plaintextEntry.url);
    expect(decrypted.notes).toBe(plaintextEntry.notes);
    expect(decrypted.category).toBe(plaintextEntry.category);
    expect(decrypted.tags).toEqual(["ssh", "production"]);
    expect(decrypted.favorite).toBe(true);
  });

  it("rejects an incorrect master password when unlocking the VEK", async () => {
    const userId = "2c9d8420-8b2a-4c31-9a14-09911a2b3c4d";
    const { envelope } = await createWrappedVaultEnvelope({
      masterPassword: "CorrectMasterPassword!2026",
      userId,
      kdfParams: TEST_KDF_PARAMS,
    });

    await expect(
      unlockVaultEncryptionKey({
        masterPassword: "WrongMasterPassword!2026",
        vaultSettings: envelope,
        userId,
      })
    ).rejects.toThrow(/Invalid master password/);
  });

  it("detects any modification to item ciphertext or Poly1305 tag", async () => {
    const userId = "2c9d8420-8b2a-4c31-9a14-09911a2b3c4d";
    const itemId = "7f112233-4455-4666-8777-8899aabbccdd";
    const { vek } = await createWrappedVaultEnvelope({
      masterPassword: "MasterPassword#1234",
      userId,
      kdfParams: TEST_KDF_PARAMS,
    });

    const encrypted = await encryptVaultItem({
      vek,
      userId,
      itemId,
      plaintextEntry: {
        title: "Database Root",
        username: "root",
        password: "SuperSecretDBPassword!",
      },
    });

    const rawCiphertext = await fromBase64(encrypted.ciphertext);
    rawCiphertext[0] ^= 0xff; // Flip bits in first byte of ciphertext
    const tamperedRecord = {
      ...encrypted,
      ciphertext: await toBase64(rawCiphertext),
    };

    await expect(
      decryptVaultItem({
        vek,
        userId,
        encryptedRecord: tamperedRecord,
      })
    ).rejects.toThrow(/Failed to authenticate or decrypt/);
  });

  it("generates distinct cryptographically random nonces for separate encryption operations", async () => {
    const userId = "2c9d8420-8b2a-4c31-9a14-09911a2b3c4d";
    const { vek } = await createWrappedVaultEnvelope({
      masterPassword: "MasterPassword#1234",
      userId,
      kdfParams: TEST_KDF_PARAMS,
    });

    const entry = { title: "Identical Entry", username: "u", password: "p" };
    const enc1 = await encryptVaultItem({
      vek,
      userId,
      itemId: "11111111-1111-4111-8111-111111111111",
      plaintextEntry: entry,
    });
    const enc2 = await encryptVaultItem({
      vek,
      userId,
      itemId: "11111111-1111-4111-8111-111111111111",
      plaintextEntry: entry,
    });

    expect(enc1.nonce).not.toBe(enc2.nonce);
    expect(enc1.ciphertext).not.toBe(enc2.ciphertext);
  });

  it("fails decryption when Authenticated Additional Data (AAD) context changes", async () => {
    const userA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const userB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const item1 = "11111111-1111-4111-8111-111111111111";
    const item2 = "22222222-2222-4222-8222-222222222222";

    const { vek } = await createWrappedVaultEnvelope({
      masterPassword: "MasterPassword#1234",
      userId: userA,
      kdfParams: TEST_KDF_PARAMS,
    });

    const encrypted = await encryptVaultItem({
      vek,
      userId: userA,
      itemId: item1,
      plaintextEntry: { title: "Bank Token", username: "alice", password: "secret" },
    });

    // Attempting to decrypt under User B's AAD context must fail
    await expect(
      decryptVaultItem({
        vek,
        userId: userB,
        encryptedRecord: encrypted,
      })
    ).rejects.toThrow(/Failed to authenticate or decrypt/);

    // Attempting to transplant ciphertext to a different itemId must fail
    await expect(
      decryptVaultItem({
        vek,
        userId: userA,
        encryptedRecord: { ...encrypted, id: item2 },
      })
    ).rejects.toThrow(/Failed to authenticate or decrypt/);
  });

  it("enforces strict KDF parameter and version bounds before deriving keys", async () => {
    const validSalt = await generateKdfSalt();

    expect(() =>
      validateKdfConfig({
        kdf_algorithm: "pbkdf2",
        kdf_version: 1,
        kdf_salt: validSalt,
        kdf_params: TEST_KDF_PARAMS,
      })
    ).toThrow(/Unsupported KDF algorithm/);

    expect(() =>
      validateKdfConfig({
        kdf_algorithm: KDF_ALGORITHM_ARGON2ID13,
        kdf_version: 99,
        kdf_salt: validSalt,
        kdf_params: TEST_KDF_PARAMS,
      })
    ).toThrow(/Unsupported KDF version/);

    // Reject dangerously high memlimit (DoS protection)
    await expect(
      deriveWrappingKey("MasterPass!123", {
        kdf_algorithm: KDF_ALGORITHM_ARGON2ID13,
        kdf_version: 1,
        kdf_salt: validSalt,
        kdf_params: {
          opslimit: 3,
          memlimit: 1024 * 1024 * 1024, // 1 GiB
        },
      })
    ).rejects.toThrow(/outside safe bounds/);
  });

  it("changes master password by re-wrapping the VEK without modifying item ciphertexts", async () => {
    const userId = "2c9d8420-8b2a-4c31-9a14-09911a2b3c4d";
    const itemId = "7f112233-4455-4666-8777-8899aabbccdd";
    const oldMaster = "OldMasterPassword#2025!";
    const newMaster = "NewMasterPassword#2026!";

    const { vek: originalVek, envelope: oldEnvelope } =
      await createWrappedVaultEnvelope({
        masterPassword: oldMaster,
        userId,
        kdfParams: TEST_KDF_PARAMS,
      });

    const encryptedItem = await encryptVaultItem({
      vek: originalVek,
      userId,
      itemId,
      plaintextEntry: {
        title: "Immutable Item",
        username: "admin",
        password: "KeepSameCiphertext!99",
      },
    });
    const originalItemCiphertext = encryptedItem.ciphertext;

    const { envelope: newEnvelope } = await rewrapVekWithNewMasterPassword({
      currentMasterPassword: oldMaster,
      newMasterPassword: newMaster,
      vaultSettings: oldEnvelope,
      userId,
      kdfParams: TEST_KDF_PARAMS,
    });

    expect(newEnvelope.kdf_salt).not.toBe(oldEnvelope.kdf_salt);
    expect(newEnvelope.vek_nonce).not.toBe(oldEnvelope.vek_nonce);
    expect(newEnvelope.encrypted_vek).not.toBe(oldEnvelope.encrypted_vek);

    // Old master password can no longer unlock the new envelope
    await expect(
      unlockVaultEncryptionKey({
        masterPassword: oldMaster,
        vaultSettings: newEnvelope,
        userId,
      })
    ).rejects.toThrow(/Invalid master password/);

    // New master password unlocks the VEK, which decrypts the UNCHANGED item ciphertext
    const unlockedNewVek = await unlockVaultEncryptionKey({
      masterPassword: newMaster,
      vaultSettings: newEnvelope,
      userId,
    });
    expect(encryptedItem.ciphertext).toBe(originalItemCiphertext);

    const decryptedAfterRotation = await decryptVaultItem({
      vek: unlockedNewVek,
      userId,
      encryptedRecord: encryptedItem,
    });
    expect(decryptedAfterRotation.password).toBe("KeepSameCiphertext!99");
  });

  it("validates and restores encrypted backup archives end-to-end", async () => {
    const userId = "2c9d8420-8b2a-4c31-9a14-09911a2b3c4d";
    const masterPassword = "BackupMasterPassword!2026";

    const stateA = new VaultStateManager();
    stateA.setUser({ id: userId, email: "backup@example.edu" });
    const settings = await stateA.setupNewVault(masterPassword, 5, TEST_KDF_PARAMS);
    stateA.setVaultSettings(settings);

    const encItem = await stateA.prepareEncryptedItem({
      title: "Restorable VPN Key",
      username: "vpn_user",
      password: "VpnSecretKey!42",
      category: "Security",
    });

    const backupBundle = {
      backup_format: "aegisvault-encrypted-backup",
      backup_version: 1,
      exported_at: new Date().toISOString(),
      user_id: userId,
      vault_settings: settings,
      items: [encItem],
    };

    expect(validateEncryptedBackupArchive(backupBundle)).toBe(true);

    // Lock and clear stateA, then restore into a fresh stateB instance
    stateA.clearAll();
    expect(stateA.isUnlocked()).toBe(false);

    const stateB = new VaultStateManager();
    stateB.setUser({ id: userId, email: "backup@example.edu" });
    stateB.setVaultSettings(backupBundle.vault_settings);
    await stateB.unlock(masterPassword, backupBundle.items);

    expect(stateB.isUnlocked()).toBe(true);
    expect(stateB.decryptedItems.length).toBe(1);
    expect(stateB.decryptedItems[0].title).toBe("Restorable VPN Key");
    expect(stateB.decryptedItems[0].password).toBe("VpnSecretKey!42");

    // Locking stateB zeroes the VEK buffer and removes decrypted items
    const vekRef = stateB.vek;
    stateB.lockVault();
    expect(stateB.isUnlocked()).toBe(false);
    expect(stateB.decryptedItems.length).toBe(0);
    expect(Array.from(vekRef).every((byte) => byte === 0)).toBe(true);
  });

  it("generates passwords meeting character-set requirements and excludes ambiguous characters", () => {
    const pwd = generatePassword({
      length: 32,
      uppercase: true,
      lowercase: true,
      numbers: true,
      symbols: true,
      excludeAmbiguous: true,
    });

    expect(pwd.length).toBe(32);
    expect(/[A-Z]/.test(pwd)).toBe(true);
    expect(/[a-z]/.test(pwd)).toBe(true);
    expect(/[0-9]/.test(pwd)).toBe(true);
    expect(/[^a-zA-Z0-9]/.test(pwd)).toBe(true);
    expect(/[0Oo1lI|`'"]/.test(pwd)).toBe(false);

    const strength = estimatePasswordStrength(pwd);
    expect(strength.score).toBe(4);
    expect(strength.label).toBe("Very Strong");
  });
});
