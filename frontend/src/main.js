/**
 * AegisVault Frontend Entry Point (Vanilla JS + Vite + libsodium.js).
 */

import "./styles.css";
import { apiRequest } from "./api/client.js";
import { checkCurrentSession } from "./auth/auth.js";
import { getSodium } from "./crypto/sodium.js";
import { VaultStateManager } from "./vault/vault-state.js";
import { VaultAppUI } from "./vault/vault-ui.js";

export async function bootstrapApplication(
  rootElement = document.getElementById("root") || document.getElementById("app")
) {
  if (!rootElement) {
    throw new Error("Application root mount element not found.");
  }

  rootElement.innerHTML = `
    <div style="min-height: 100vh; display: flex; align-items: center; justify-content: center; color: #94a3b8; font-family: sans-serif;">
      Initializing libsodium WebAssembly cryptographic runtime...
    </div>
  `;

  const vaultState = new VaultStateManager();
  const ui = new VaultAppUI(rootElement, vaultState);

  try {
    await getSodium();
    const user = await checkCurrentSession();
    if (user) {
      vaultState.setUser(user);
      if (user.has_vault_setup) {
        try {
          const settingsRes = await apiRequest("/api/vault/settings", {
            method: "GET",
          });
          vaultState.setVaultSettings(settingsRes.vault_settings);
        } catch {
          // Vault settings not yet initialized
        }
      }
    }
  } catch (err) {
    ui.setBanner(
      "error",
      err.message || "Unable to connect to the AegisVault backend API."
    );
  }

  ui.render();
  return { vaultState, ui };
}

if (typeof window !== "undefined" && !window.__AEGISVAULT_TEST_ENV__) {
  bootstrapApplication();
}
