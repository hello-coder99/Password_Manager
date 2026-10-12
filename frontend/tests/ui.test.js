// @vitest-environment jsdom
import { describe, expect, it, vi } from "vitest";
import { AutoLockMonitor } from "../src/security/auto-lock.js";
import { VaultStateManager } from "../src/vault/vault-state.js";
import { VaultAppUI, escapeHtml } from "../src/vault/vault-ui.js";

const TEST_KDF_PARAMS = Object.freeze({
  opslimit: 2,
  memlimit: 16 * 1024 * 1024,
});

describe("Frontend UI & Security Controls", () => {
  it("escapes untrusted HTML strings to prevent DOM XSS", () => {
    const malicious = `<img src=x onerror="alert(1)"> & 'quote'`;
    const escaped = escapeHtml(malicious);
    expect(escaped).toBe(
      "&lt;img src=x onerror=&quot;alert(1)&quot;&gt; &amp; &#39;quote&#39;"
    );
    expect(escaped).not.toContain("<img");
  });

  it("renders authentication screen explaining separated account and vault secrets", () => {
    const root = document.createElement("div");
    const state = new VaultStateManager();
    const ui = new VaultAppUI(root, state);

    ui.render();
    expect(root.textContent).toContain("Account Login Password");
    expect(root.textContent).toContain("Vault Master Password");
    expect(root.querySelector("#auth-form")).not.toBeNull();
  });

  it("renders vault setup screen with unrecoverable master password warning", () => {
    const root = document.createElement("div");
    const state = new VaultStateManager();
    state.setUser({
      id: "2c9d8420-8b2a-4c31-9a14-09911a2b3c4d",
      email: "student@university.edu",
      has_vault_setup: false,
    });
    const ui = new VaultAppUI(root, state);

    ui.render();
    expect(root.textContent).toContain("Mandatory Recovery Warning");
    expect(root.textContent).toContain("permanently unrecoverable");
    expect(root.querySelector("#vault-setup-form")).not.toBeNull();
  });

  it("renders unlocked dashboard and filters decrypted credentials in memory", async () => {
    const root = document.createElement("div");
    const state = new VaultStateManager();
    const userId = "2c9d8420-8b2a-4c31-9a14-09911a2b3c4d";
    state.setUser({
      id: userId,
      email: "student@university.edu",
      has_vault_setup: true,
    });

    const settings = await state.setupNewVault(
      "StrongMasterPassword!2026",
      5,
      TEST_KDF_PARAMS
    );
    state.setVaultSettings(settings);

    const enc1 = await state.prepareEncryptedItem({
      title: "MariaDB Production Cluster",
      username: "db_admin",
      password: "DbSecret!99",
      category: "Infrastructure",
      tags: ["sql", "prod"],
      favorite: true,
    });
    const enc2 = await state.prepareEncryptedItem({
      title: "University Portal",
      username: "student123",
      password: "PortalSecret!11",
      category: "Personal",
      tags: ["campus"],
      favorite: false,
    });

    await state.setEncryptedItemsAndDecrypt([enc1, enc2]);

    const ui = new VaultAppUI(root, state);
    ui.render();

    expect(root.textContent).toContain("MariaDB Production Cluster");
    expect(root.textContent).toContain("University Portal");
    // Passwords must be masked by default
    expect(root.textContent).not.toContain("DbSecret!99");

    // Search filtering in browser memory
    ui.searchQuery = "mariadb";
    ui.render();
    expect(root.textContent).toContain("MariaDB Production Cluster");
    expect(root.textContent).not.toContain("University Portal");
  });

  it("triggers auto-lock callback when inactivity deadline expires", () => {
    vi.useFakeTimers();
    try {
      let locked = false;
      const monitor = new AutoLockMonitor({
        timeoutMinutes: 1,
        onLock: () => {
          locked = true;
        },
      });
      monitor.start();
      expect(locked).toBe(false);
      expect(monitor.getRemainingSeconds()).toBe(60);

      vi.advanceTimersByTime(61 * 1000);
      expect(locked).toBe(true);
      expect(monitor.isRunning).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });
});
