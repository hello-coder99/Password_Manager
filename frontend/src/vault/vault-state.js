/**
 * In-memory vault state manager.
 * Holds the unlocked 256-bit VEK and decrypted credentials strictly in JavaScript
 * runtime memory. Never writes keys or plaintext entries to localStorage,
 * sessionStorage, IndexedDB, or cookies.
 */

import { zeroBuffers } from "../crypto/sodium.js";
import {
  createWrappedVaultEnvelope,
  decryptVaultItem,
  encryptVaultItem,
  rewrapVekWithNewMasterPassword,
  unlockVaultEncryptionKey,
} from "../crypto/vault-crypto.js";

export class VaultStateManager {
  constructor() {
    this.user = null;
    this.vaultSettings = null;
    /** @type {Uint8Array|null} */
    this.vek = null;
    /** @type {Array<object>} */
    this.encryptedItems = [];
    /** @type {Array<object>} */
    this.decryptedItems = [];
    /** @type {Array<string>} */
    this.corruptedItemIds = [];
  }

  setUser(user) {
    this.user = user;
  }

  setVaultSettings(settings) {
    this.vaultSettings = settings;
  }

  isUnlocked() {
    return this.vek instanceof Uint8Array && this.vek.length === 32;
  }

  /**
   * Initialize a brand-new encrypted vault with a randomly generated 256-bit VEK.
   */
  async setupNewVault(masterPassword, inactivityTimeoutMinutes = 5, kdfParams = undefined) {
    if (!this.user?.id) {
      throw new Error("Authenticated user is required to initialize vault.");
    }
    const { vek, envelope } = await createWrappedVaultEnvelope({
      masterPassword,
      userId: this.user.id,
      kdfParams,
    });
    this.lockVault();
    this.vek = vek;
    return {
      ...envelope,
      inactivity_timeout_minutes: inactivityTimeoutMinutes,
    };
  }

  /**
   * Unlock the existing vault using the master password and decrypt all loaded items.
   */
  async unlock(masterPassword, encryptedRecords = []) {
    if (!this.user?.id) {
      throw new Error("Authenticated user is required to unlock vault.");
    }
    if (!this.vaultSettings) {
      throw new Error("Vault settings are not loaded.");
    }

    const unwrappedVek = await unlockVaultEncryptionKey({
      masterPassword,
      vaultSettings: this.vaultSettings,
      userId: this.user.id,
    });

    this.lockVault();
    this.vek = unwrappedVek;
    await this.setEncryptedItemsAndDecrypt(encryptedRecords);
  }

  /**
   * Store encrypted items from the backend and decrypt them in memory.
   */
  async setEncryptedItemsAndDecrypt(encryptedRecords = []) {
    this.encryptedItems = Array.isArray(encryptedRecords)
      ? [...encryptedRecords]
      : [];
    this.decryptedItems = [];
    this.corruptedItemIds = [];

    if (!this.isUnlocked()) {
      return;
    }

    for (const record of this.encryptedItems) {
      try {
        const decrypted = await decryptVaultItem({
          vek: this.vek,
          userId: this.user.id,
          encryptedRecord: record,
        });
        this.decryptedItems.push(decrypted);
      } catch {
        this.corruptedItemIds.push(record.id);
      }
    }
  }

  /**
   * Encrypt a new or updated credential item in the browser.
   */
  async prepareEncryptedItem(plaintextEntry, existingId = null) {
    if (!this.isUnlocked()) {
      throw new Error("Vault is locked. Unlock your vault first.");
    }
    const itemId = existingId || globalThis.crypto.randomUUID();
    return encryptVaultItem({
      vek: this.vek,
      userId: this.user.id,
      itemId,
      plaintextEntry,
    });
  }

  /**
   * Re-wrap the existing VEK with a new master password without re-encrypting items.
   */
  async prepareMasterPasswordChange({
    currentMasterPassword,
    newMasterPassword,
    inactivityTimeoutMinutes,
    kdfParams = undefined,
  }) {
    if (!this.user?.id || !this.vaultSettings) {
      throw new Error("Vault settings are not initialized.");
    }
    const { vek, envelope } = await rewrapVekWithNewMasterPassword({
      currentMasterPassword,
      newMasterPassword,
      vaultSettings: this.vaultSettings,
      userId: this.user.id,
      kdfParams,
    });

    if (this.vek) {
      zeroBuffers(this.vek);
    }
    this.vek = vek;

    return {
      ...envelope,
      inactivity_timeout_minutes:
        inactivityTimeoutMinutes ??
        this.vaultSettings.inactivity_timeout_minutes ??
        5,
    };
  }

  /**
   * Filter and sort decrypted items in browser memory.
   */
  queryDecryptedItems({
    searchQuery = "",
    category = "all",
    favoritesOnly = false,
  } = {}) {
    if (!this.isUnlocked()) {
      return [];
    }

    const q = String(searchQuery ?? "").trim().toLowerCase();
    const cat = String(category ?? "all").trim();

    return this.decryptedItems
      .filter((item) => {
        if (favoritesOnly && !item.favorite) {
          return false;
        }
        if (cat !== "all" && item.category !== cat) {
          return false;
        }
        if (!q) {
          return true;
        }
        const haystack = [
          item.title,
          item.username,
          item.url,
          item.notes,
          item.category,
          ...(item.tags || []),
        ]
          .join(" ")
          .toLowerCase();
        return haystack.includes(q);
      })
      .sort((a, b) => {
        if (a.favorite !== b.favorite) {
          return a.favorite ? -1 : 1;
        }
        return a.title.localeCompare(b.title);
      });
  }

  /**
   * Lock the vault: zero the VEK Uint8Array buffer and purge decrypted items from memory.
   */
  lockVault() {
    if (this.vek instanceof Uint8Array) {
      zeroBuffers(this.vek);
    }
    this.vek = null;

    for (const item of this.decryptedItems) {
      if (item && typeof item === "object") {
        item.password = "";
        item.username = "";
        item.notes = "";
        item.title = "";
      }
    }
    this.decryptedItems = [];
    this.corruptedItemIds = [];
  }

  /**
   * Full reset on account logout.
   */
  clearAll() {
    this.lockVault();
    this.encryptedItems = [];
    this.vaultSettings = null;
    this.user = null;
  }
}
