/**
 * Vanilla JavaScript UI controller for AegisVault.
 * Renders authentication, vault initialization, master-password unlock,
 * encrypted credential dashboard, CSPRNG password generator, master-password
 * rotation, and encrypted backup export/import.
 */

import { apiRequest } from "../api/client.js";
import {
  loginAccount,
  logoutAccount,
  registerAccount,
} from "../auth/auth.js";
import { decryptVaultItem, unlockVaultEncryptionKey } from "../crypto/vault-crypto.js";
import {
  estimatePasswordStrength,
  generatePassword,
} from "../generator/password-generator.js";
import { AutoLockMonitor } from "../security/auto-lock.js";
import {
  clearClipboardIfUnchanged,
  copySecretToClipboard,
} from "../security/clipboard.js";
import {
  validateEncryptedBackupArchive,
  validateMasterPasswordSetup,
} from "../utils/validation.js";

const CATEGORIES = [
  "General",
  "Infrastructure",
  "Development",
  "Finance",
  "Security",
  "Personal",
];

/**
 * Strictly escape dynamic strings before HTML interpolation to prevent XSS.
 */
export function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatSecondsMMSS(totalSeconds) {
  const mins = Math.floor(totalSeconds / 60);
  const secs = totalSeconds % 60;
  return `${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
}

function formatShortDate(isoString) {
  if (!isoString) return "Just now";
  const d = new Date(isoString);
  if (Number.isNaN(d.getTime())) return "Recent";
  return d.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

export class VaultAppUI {
  /**
   * @param {HTMLElement} rootElement
   * @param {import('./vault-state.js').VaultStateManager} vaultState
   */
  constructor(rootElement, vaultState) {
    this.root = rootElement;
    this.vaultState = vaultState;

    // UI state
    this.authMode = "login"; // 'login' | 'register'
    this.activeTab = "credentials"; // 'credentials' | 'generator' | 'security' | 'backup'
    this.searchQuery = "";
    this.selectedCategory = "all";
    this.favoritesOnly = false;
    this.revealedPasswords = new Set();

    // Modal state
    this.editingItem = null; // null | object (new or existing item)
    this.isItemModalOpen = false;
    this.deletingItem = null; // null | object

    // Generator state
    this.generatorConfig = {
      length: 24,
      uppercase: true,
      lowercase: true,
      numbers: true,
      symbols: true,
      excludeAmbiguous: false,
    };
    this.generatedPassword = generatePassword(this.generatorConfig);

    // Status banner
    this.banner = null; // { type: 'error'|'success'|'warning', text: string }
    this.isBusy = false;

    // Auto-lock monitor
    this.autoLock = new AutoLockMonitor({
      timeoutMinutes: 5,
      onLock: () => this.handleAutoLockTriggered(),
      onTick: (seconds) => this.updateCountdownDisplay(seconds),
    });
  }

  setBanner(type, text) {
    this.banner = text ? { type, text } : null;
  }

  showToast(message) {
    if (typeof document === "undefined") return;
    let container = document.getElementById("aegis-toast-container");
    if (!container) {
      container = document.createElement("div");
      container.id = "aegis-toast-container";
      container.className = "toast-container";
      container.setAttribute("aria-live", "polite");
      document.body.appendChild(container);
    }
    const toast = document.createElement("div");
    toast.className = "toast-message";
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => {
      toast.remove();
    }, 3200);
  }

  async handleAutoLockTriggered() {
    this.vaultState.lockVault();
    this.revealedPasswords.clear();
    await clearClipboardIfUnchanged();
    this.setBanner(
      "warning",
      "Vault automatically locked due to inactivity. Enter your Vault Master Password to unlock."
    );
    this.render();
  }

  updateCountdownDisplay(remainingSeconds) {
    if (typeof document === "undefined") return;
    const badge = document.getElementById("autolock-countdown");
    if (badge) {
      badge.textContent = `Lock Vault (${formatSecondsMMSS(remainingSeconds)})`;
    }
  }

  render() {
    if (!this.root) return;

    const user = this.vaultState.user;
    if (!user) {
      this.autoLock.stop();
      this.renderAuthScreen();
      return;
    }

    if (!user.has_vault_setup || !this.vaultState.vaultSettings) {
      this.autoLock.stop();
      this.renderVaultSetupScreen();
      return;
    }

    if (!this.vaultState.isUnlocked()) {
      this.autoLock.stop();
      this.renderVaultUnlockScreen();
      return;
    }

    this.renderUnlockedDashboard();
  }

  renderBannerHtml() {
    if (!this.banner) return "";
    return `
      <div class="notice-banner ${escapeHtml(this.banner.type)}" role="alert">
        ${escapeHtml(this.banner.text)}
      </div>
    `;
  }

  renderStrengthMeterHtml(password) {
    const { entropyBits, score, label, guidance } =
      estimatePasswordStrength(password);
    const segments = [1, 2, 3, 4]
      .map(
        (idx) =>
          `<div class="strength-segment ${
            idx <= score ? `active-${score}` : ""
          }"></div>`
      )
      .join("");

    return `
      <div class="strength-meter" aria-live="polite">
        <div class="strength-bars">${segments}</div>
        <div class="strength-meta">
          <span>Strength: <strong>${escapeHtml(label)}</strong> (${escapeHtml(guidance)})</span>
          <span class="tabular-nums">${entropyBits} bits</span>
        </div>
      </div>
    `;
  }

  /* ========================================================================
     1. Authentication Screen (Login & Registration)
     ======================================================================== */
  renderAuthScreen() {
    const isReg = this.authMode === "register";

    this.root.innerHTML = `
      <header class="topbar">
        <a href="/" class="topbar-brand">AegisVault</a>
        <nav class="topbar-nav" aria-label="Authentication navigation">
          <button type="button" class="topbar-nav-link ${!isReg ? "active" : ""}" data-action="switch-auth" data-mode="login">Sign In</button>
          <button type="button" class="topbar-nav-link ${isReg ? "active" : ""}" data-action="switch-auth" data-mode="register">Create Account</button>
        </nav>
        <div class="topbar-actions">
          <button type="button" class="btn btn-secondary" data-action="switch-auth" data-mode="${isReg ? "login" : "register"}">
            ${isReg ? "Existing Account" : "Register Vault"}
          </button>
        </div>
      </header>

      <main class="auth-viewport">
        <section class="auth-editorial">
          <span class="auth-kicker">ZERO-KNOWLEDGE ENVELOPE ARCHITECTURE</span>
          <h1 class="auth-headline">Client-side encrypted credential management with separated secrets.</h1>
          <p class="auth-lead">
            AegisVault enforces a strict cryptographic boundary between backend session authentication and browser-only vault decryption.
          </p>

          <div class="architecture-list">
            <div class="architecture-item">
              <h3>01. Account Login Password (Server Authentication)</h3>
              <p>Authenticates your session with the Flask API and is stored exclusively as a salted Argon2id hash in MariaDB. It cannot decrypt your vault.</p>
            </div>
            <div class="architecture-item">
              <h3>02. Vault Master Password (Browser-Only Key Derivation)</h3>
              <p>Used strictly inside WebAssembly (libsodium.js) to derive a 256-bit Argon2id wrapping key that unlocks your random Vault Encryption Key (VEK). Never transmitted to the server.</p>
            </div>
            <div class="architecture-item">
              <h3>03. Authenticated XChaCha20-Poly1305 Payloads</h3>
              <p>Every credential record—including title, username, password, URL, tags, and notes—is encrypted in browser memory with per-record AAD binding before upload.</p>
            </div>
          </div>
        </section>

        <section class="auth-panel" aria-labelledby="auth-form-title">
          <div class="segmented-control" role="tablist">
            <button type="button" role="tab" aria-selected="${!isReg}" class="segmented-btn ${!isReg ? "active" : ""}" data-action="switch-auth" data-mode="login">
              Sign In to Account
            </button>
            <button type="button" role="tab" aria-selected="${isReg}" class="segmented-btn ${isReg ? "active" : ""}" data-action="switch-auth" data-mode="register">
              Create New Account
            </button>
          </div>

          <div class="form-stack">
            <h2 id="auth-form-title">${isReg ? "Register Account" : "Account Sign In"}</h2>
            <p class="field-hint">
              ${
                isReg
                  ? "Step 1 of 2: Create your server login account. You will initialize your separate Vault Master Password on the next screen."
                  : "Enter your account email and login password to establish an authenticated session."
              }
            </p>

            ${this.renderBannerHtml()}

            <form id="auth-form" class="form-stack" novalidate>
              <div class="field-group">
                <label class="field-label" for="auth-email">Email Address</label>
                <input
                  id="auth-email"
                  name="email"
                  type="email"
                  class="form-input"
                  autocomplete="username"
                  placeholder="analyst@university.edu"
                  required
                />
              </div>

              <div class="field-group">
                <div class="field-label-row">
                  <label class="field-label" for="auth-password">Account Login Password</label>
                  <span class="field-hint">${isReg ? "Minimum 10 characters" : "Server auth secret"}</span>
                </div>
                <div class="input-wrapper">
                  <input
                    id="auth-password"
                    name="login_password"
                    type="password"
                    class="form-input mono-input"
                    autocomplete="${isReg ? "new-password" : "current-password"}"
                    placeholder="Enter account login password"
                    required
                  />
                  <button type="button" class="input-inline-btn" data-toggle-input="auth-password">Show</button>
                </div>
                <div id="auth-strength-slot"></div>
              </div>

              <button type="submit" class="btn btn-primary" ${this.isBusy ? "disabled" : ""}>
                ${
                  this.isBusy
                    ? "Authenticating..."
                    : isReg
                      ? "Create Account & Continue"
                      : "Sign In"
                }
              </button>
            </form>
          </div>
        </section>
      </main>
    `;

    this.bindCommonToggleEvents();

    this.root.querySelectorAll("[data-action='switch-auth']").forEach((btn) => {
      btn.addEventListener("click", () => {
        this.authMode = btn.getAttribute("data-mode") || "login";
        this.setBanner(null, "");
        this.render();
      });
    });

    const pwdInput = document.getElementById("auth-password");
    const strengthSlot = document.getElementById("auth-strength-slot");
    if (isReg && pwdInput && strengthSlot) {
      pwdInput.addEventListener("input", () => {
        strengthSlot.innerHTML = this.renderStrengthMeterHtml(pwdInput.value);
      });
    }

    const form = document.getElementById("auth-form");
    form?.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (this.isBusy) return;

      const email = document.getElementById("auth-email")?.value || "";
      const loginPassword = document.getElementById("auth-password")?.value || "";

      this.isBusy = true;
      this.setBanner(null, "");
      this.render();

      try {
        const user = isReg
          ? await registerAccount({ email, loginPassword })
          : await loginAccount({ email, loginPassword });

        this.vaultState.setUser(user);
        if (user.has_vault_setup) {
          const settingsRes = await apiRequest("/api/vault/settings", {
            method: "GET",
          });
          this.vaultState.setVaultSettings(settingsRes.vault_settings);
        }
        this.setBanner(null, "");
      } catch (err) {
        this.setBanner("error", err.message || "Authentication failed.");
      } finally {
        this.isBusy = false;
        this.render();
      }
    });
  }

  /* ========================================================================
     2. Vault Setup Screen (Browser VEK Creation & Wrapping)
     ======================================================================== */
  renderVaultSetupScreen() {
    const user = this.vaultState.user;

    this.root.innerHTML = `
      <header class="topbar">
        <a href="/" class="topbar-brand">AegisVault</a>
        <nav class="topbar-nav" aria-label="Setup navigation">
          <span class="topbar-nav-link active">Initialize Encrypted Vault</span>
        </nav>
        <div class="topbar-actions">
          <button type="button" class="btn btn-secondary" id="setup-logout-btn">Log Out</button>
        </div>
      </header>

      <main class="auth-viewport">
        <section class="auth-editorial">
          <span class="auth-kicker">STEP 2 OF 2 · CLIENT-SIDE KEY CEREMONY</span>
          <h1 class="auth-headline">Create your Vault Master Password.</h1>
          <p class="auth-lead">
            Signed in as <strong>${escapeHtml(user.email)}</strong>. Your browser will now generate a cryptographically random 256-bit Vault Encryption Key (VEK) and wrap it with Argon2id + XChaCha20-Poly1305.
          </p>

          <div class="notice-banner warning">
            <strong>Mandatory Recovery Warning:</strong> Your Vault Master Password is never sent to the server and cannot be recovered from your Account Login Password. If you forget your Vault Master Password and do not have it recorded, your encrypted credentials will be permanently unrecoverable.
          </div>

          <div class="architecture-list">
            <div class="architecture-item">
              <h3>Envelope Key Derivation Parameters</h3>
              <p class="mono">Algorithm: argon2id13 · Salt: 128-bit CSPRNG · Memory: 64 MiB · Passes: 3 · Cipher: XChaCha20-Poly1305-IETF</p>
            </div>
          </div>
        </section>

        <section class="auth-panel" aria-labelledby="setup-title">
          <form id="vault-setup-form" class="form-stack" novalidate>
            <h2 id="setup-title">Initialize Vault Encryption Key</h2>
            <p class="field-hint">Choose a strong Vault Master Password distinct from your Account Login Password.</p>

            ${this.renderBannerHtml()}

            <div class="field-group">
              <label class="field-label" for="setup-master-password">Vault Master Password</label>
              <div class="input-wrapper">
                <input
                  id="setup-master-password"
                  type="password"
                  class="form-input mono-input"
                  autocomplete="new-password"
                  placeholder="Minimum 10 characters"
                  required
                />
                <button type="button" class="input-inline-btn" data-toggle-input="setup-master-password">Show</button>
              </div>
              <div id="setup-strength-slot"></div>
            </div>

            <div class="field-group">
              <label class="field-label" for="setup-confirm-password">Confirm Vault Master Password</label>
              <div class="input-wrapper">
                <input
                  id="setup-confirm-password"
                  type="password"
                  class="form-input mono-input"
                  autocomplete="new-password"
                  placeholder="Re-enter master password"
                  required
                />
                <button type="button" class="input-inline-btn" data-toggle-input="setup-confirm-password">Show</button>
              </div>
            </div>

            <div class="field-group">
              <label class="field-label" for="setup-timeout">Inactivity Auto-Lock Timeout</label>
              <select id="setup-timeout" class="form-select tabular-nums">
                <option value="1">1 minute</option>
                <option value="5" selected>5 minutes (Recommended Default)</option>
                <option value="10">10 minutes</option>
                <option value="15">15 minutes</option>
                <option value="30">30 minutes</option>
              </select>
            </div>

            <button type="submit" class="btn btn-primary" ${this.isBusy ? "disabled" : ""}>
              ${this.isBusy ? "Deriving Argon2id Key & Wrapping VEK..." : "Generate VEK & Initialize Vault"}
            </button>
          </form>
        </section>
      </main>
    `;

    this.bindCommonToggleEvents();

    document
      .getElementById("setup-logout-btn")
      ?.addEventListener("click", () => this.handleLogout());

    const mpInput = document.getElementById("setup-master-password");
    const strengthSlot = document.getElementById("setup-strength-slot");
    mpInput?.addEventListener("input", () => {
      if (strengthSlot) {
        strengthSlot.innerHTML = this.renderStrengthMeterHtml(mpInput.value);
      }
    });

    const form = document.getElementById("vault-setup-form");
    form?.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (this.isBusy) return;

      const masterPassword =
        document.getElementById("setup-master-password")?.value || "";
      const confirmMasterPassword =
        document.getElementById("setup-confirm-password")?.value || "";
      const timeoutMinutes = Number(
        document.getElementById("setup-timeout")?.value || 5
      );

      try {
        validateMasterPasswordSetup({
          masterPassword,
          confirmMasterPassword,
        });
      } catch (validationErr) {
        this.setBanner("error", validationErr.message);
        this.render();
        return;
      }

      this.isBusy = true;
      this.setBanner(null, "");
      this.render();

      try {
        const envelopePayload = await this.vaultState.setupNewVault(
          masterPassword,
          timeoutMinutes
        );
        const res = await apiRequest("/api/vault/setup", {
          method: "POST",
          body: envelopePayload,
        });

        this.vaultState.setVaultSettings(res.vault_settings);
        this.vaultState.user.has_vault_setup = true;
        await this.vaultState.setEncryptedItemsAndDecrypt([]);
        this.autoLock.setTimeoutMinutes(
          res.vault_settings.inactivity_timeout_minutes
        );
        this.autoLock.start();
        this.showToast("Encrypted vault initialized in browser memory.");
      } catch (err) {
        this.vaultState.lockVault();
        this.setBanner("error", err.message || "Failed to initialize vault.");
      } finally {
        this.isBusy = false;
        this.render();
      }
    });
  }

  /* ========================================================================
     3. Vault Unlock Screen (Derives Wrapping Key & Unwraps VEK)
     ======================================================================== */
  renderVaultUnlockScreen() {
    const user = this.vaultState.user;
    const settings = this.vaultState.vaultSettings;
    const memMiB = settings?.kdf_params?.memlimit
      ? Math.round(settings.kdf_params.memlimit / (1024 * 1024))
      : 64;
    const ops = settings?.kdf_params?.opslimit ?? 3;

    this.root.innerHTML = `
      <header class="topbar">
        <a href="/" class="topbar-brand">AegisVault</a>
        <nav class="topbar-nav" aria-label="Vault locked status">
          <span class="topbar-nav-link active">Vault Locked</span>
        </nav>
        <div class="topbar-actions">
          <button type="button" class="btn btn-secondary" id="unlock-logout-btn">Log Out</button>
        </div>
      </header>

      <main class="auth-viewport">
        <section class="auth-editorial">
          <span class="auth-kicker">CLIENT-SIDE DECRYPTION REQUIRED</span>
          <h1 class="auth-headline">Unlock your encrypted vault.</h1>
          <p class="auth-lead">
            Authenticated as <strong>${escapeHtml(user.email)}</strong>. Your encrypted VEK envelope is loaded. Enter your Vault Master Password to derive the wrapping key in browser memory.
          </p>

          <div class="architecture-list">
            <div class="architecture-item">
              <h3>Loaded KDF & Envelope Metadata</h3>
              <p class="mono tabular-nums">
                KDF: ${escapeHtml(settings.kdf_algorithm)} v${escapeHtml(settings.kdf_version)} · Memory: ${memMiB} MiB · Iterations: ${ops} · Auto-Lock: ${escapeHtml(settings.inactivity_timeout_minutes)}m
              </p>
            </div>
            <div class="architecture-item">
              <h3>Process Memory Hygiene Disclosure</h3>
              <p>
                Decrypted credentials reside solely in JavaScript runtime memory and are never written to localStorage, sessionStorage, IndexedDB, or cookies. Locking zeroes Uint8Array key buffers via <code class="mono">sodium.memzero</code>, though JavaScript engines cannot guarantee hardware-level erasure of garbage-collected strings.
              </p>
            </div>
          </div>
        </section>

        <section class="auth-panel" aria-labelledby="unlock-title">
          <form id="vault-unlock-form" class="form-stack" novalidate>
            <h2 id="unlock-title">Enter Vault Master Password</h2>
            <p class="field-hint">This password is processed locally by libsodium WebAssembly and is never sent to the backend.</p>

            ${this.renderBannerHtml()}

            <div class="field-group">
              <label class="field-label" for="unlock-master-password">Vault Master Password</label>
              <div class="input-wrapper">
                <input
                  id="unlock-master-password"
                  type="password"
                  class="form-input mono-input"
                  autocomplete="current-password"
                  placeholder="Enter vault master password"
                  required
                />
                <button type="button" class="input-inline-btn" data-toggle-input="unlock-master-password">Show</button>
              </div>
            </div>

            <button type="submit" class="btn btn-primary" ${this.isBusy ? "disabled" : ""}>
              ${this.isBusy ? "Deriving Key & Decrypting Vault..." : "Unlock Vault"}
            </button>
          </form>
        </section>
      </main>
    `;

    this.bindCommonToggleEvents();
    document.getElementById("unlock-master-password")?.focus();

    document
      .getElementById("unlock-logout-btn")
      ?.addEventListener("click", () => this.handleLogout());

    const form = document.getElementById("vault-unlock-form");
    form?.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (this.isBusy) return;

      const masterPassword =
        document.getElementById("unlock-master-password")?.value || "";
      if (!masterPassword) {
        this.setBanner("error", "Enter your Vault Master Password.");
        this.render();
        return;
      }

      this.isBusy = true;
      this.setBanner(null, "");
      this.render();

      try {
        const itemsRes = await apiRequest("/api/vault/items", { method: "GET" });
        await this.vaultState.unlock(masterPassword, itemsRes.items || []);

        this.autoLock.setTimeoutMinutes(
          this.vaultState.vaultSettings.inactivity_timeout_minutes || 5
        );
        this.autoLock.start();
        this.setBanner(null, "");
      } catch (err) {
        this.vaultState.lockVault();
        this.setBanner(
          "error",
          err.message || "Invalid Vault Master Password."
        );
      } finally {
        this.isBusy = false;
        this.render();
      }
    });
  }

  /* ========================================================================
     4. Unlocked Vault Dashboard (Top Bar Contract + Sidebar + Main View)
     ======================================================================== */
  renderUnlockedDashboard() {
    const user = this.vaultState.user;
    const totalCount = this.vaultState.decryptedItems.length;
    const favCount = this.vaultState.decryptedItems.filter(
      (i) => i.favorite
    ).length;
    const remainingSec =
      this.autoLock.getRemainingSeconds() ||
      (this.vaultState.vaultSettings?.inactivity_timeout_minutes || 5) * 60;

    this.root.innerHTML = `
      <!-- Top Bar Contract: Zone 1 (Brand) — Zone 2 (4 single-line nav links) — Zone 3 (1 primary action) -->
      <header class="topbar">
        <a href="/" class="topbar-brand">AegisVault</a>

        <nav class="topbar-nav" aria-label="Workspace navigation">
          <button type="button" class="topbar-nav-link ${this.activeTab === "credentials" ? "active" : ""}" data-tab="credentials">
            Credentials (${totalCount})
          </button>
          <button type="button" class="topbar-nav-link ${this.activeTab === "generator" ? "active" : ""}" data-tab="generator">
            Password Generator
          </button>
          <button type="button" class="topbar-nav-link ${this.activeTab === "security" ? "active" : ""}" data-tab="security">
            Master Key &amp; Security
          </button>
          <button type="button" class="topbar-nav-link ${this.activeTab === "backup" ? "active" : ""}" data-tab="backup">
            Encrypted Backup
          </button>
        </nav>

        <div class="topbar-actions">
          <button type="button" class="btn btn-secondary tabular-nums" id="autolock-countdown" title="Click to lock vault immediately">
            Lock Vault (${formatSecondsMMSS(remainingSec)})
          </button>
        </div>
      </header>

      <div class="workspace-shell">
        <aside class="workspace-sidebar" aria-label="Vault filters and account">
          <div class="form-stack">
            <div class="sidebar-section">
              <div class="sidebar-heading">Vault Views</div>
              <button type="button" class="sidebar-filter-btn ${this.activeTab === "credentials" && !this.favoritesOnly && this.selectedCategory === "all" ? "active" : ""}" data-filter-cat="all" data-filter-fav="false">
                <span>All Credentials</span>
                <span class="tabular-nums">${totalCount}</span>
              </button>
              <button type="button" class="sidebar-filter-btn ${this.activeTab === "credentials" && this.favoritesOnly ? "active" : ""}" data-filter-cat="all" data-filter-fav="true">
                <span>Favorites</span>
                <span class="tabular-nums">${favCount}</span>
              </button>
            </div>

            <div class="sidebar-section">
              <div class="sidebar-heading">Categories</div>
              ${CATEGORIES.map((cat) => {
                const count = this.vaultState.decryptedItems.filter(
                  (i) => i.category === cat
                ).length;
                const isActive =
                  this.activeTab === "credentials" &&
                  !this.favoritesOnly &&
                  this.selectedCategory === cat;
                return `
                  <button type="button" class="sidebar-filter-btn ${isActive ? "active" : ""}" data-filter-cat="${escapeHtml(cat)}" data-filter-fav="false">
                    <span>${escapeHtml(cat)}</span>
                    <span class="tabular-nums">${count}</span>
                  </button>
                `;
              }).join("")}
            </div>
          </div>

          <div class="sidebar-section">
            <div class="sidebar-heading">Authenticated Account</div>
            <div style="padding: 0.35rem 0.65rem; font-size: 0.825rem; color: var(--text-secondary); word-break: break-all;">
              ${escapeHtml(user.email)}
            </div>
            <button type="button" class="btn btn-secondary" id="dashboard-logout-btn" style="margin-top: 0.5rem; width: 100%;">
              Log Out &amp; Wipe Memory
            </button>
          </div>
        </aside>

        <main class="workspace-main">
          ${this.renderBannerHtml()}
          ${
            this.vaultState.corruptedItemIds.length > 0
              ? `<div class="notice-banner error" role="alert">
                   Integrity Warning: ${this.vaultState.corruptedItemIds.length} record(s) failed XChaCha20-Poly1305 / AAD authentication and were quarantined.
                 </div>`
              : ""
          }
          ${this.renderActiveWorkspaceTab()}
        </main>
      </div>

      ${this.isItemModalOpen ? this.renderItemModalHtml() : ""}
      ${this.deletingItem ? this.renderDeleteConfirmModalHtml() : ""}
    `;

    this.bindDashboardEvents();
  }

  renderActiveWorkspaceTab() {
    switch (this.activeTab) {
      case "generator":
        return this.renderGeneratorTabHtml();
      case "security":
        return this.renderSecurityTabHtml();
      case "backup":
        return this.renderBackupTabHtml();
      case "credentials":
      default:
        return this.renderCredentialsTabHtml();
    }
  }

  /* ========================================================================
     Tab 1: Credentials Table & Search
     ======================================================================== */
  renderCredentialsTabHtml() {
    const filteredItems = this.vaultState.queryDecryptedItems({
      searchQuery: this.searchQuery,
      category: this.selectedCategory,
      favoritesOnly: this.favoritesOnly,
    });

    const rowsHtml =
      filteredItems.length === 0
        ? `
          <div class="empty-state">
            <h3>${
              this.vaultState.decryptedItems.length === 0
                ? "Your encrypted vault is empty"
                : "No matching credentials found"
            }</h3>
            <p>
              ${
                this.vaultState.decryptedItems.length === 0
                  ? "Create your first credential entry. Every field is encrypted in your browser with your 256-bit VEK before leaving this device."
                  : "Adjust your search query or category filter to view matching entries."
              }
            </p>
            ${
              this.vaultState.decryptedItems.length === 0
                ? `<button type="button" class="btn btn-primary" id="empty-new-item-btn">Create First Credential</button>`
                : `<button type="button" class="btn btn-secondary" id="clear-filters-btn">Reset Filters</button>`
            }
          </div>
        `
        : `
          <table class="vault-table" aria-label="Decrypted vault credentials">
            <thead>
              <tr>
                <th>Service / Metadata</th>
                <th>Username / Identity</th>
                <th>Secret / Password</th>
                <th style="text-align: right;">Actions</th>
              </tr>
            </thead>
            <tbody>
              ${filteredItems
                .map((item) => {
                  const isRevealed = this.revealedPasswords.has(item.id);
                  const tagsText =
                    item.tags && item.tags.length > 0
                      ? item.tags.map(escapeHtml).join(", ")
                      : null;

                  return `
                    <tr>
                      <td>
                        <div class="credential-title-cell">
                          <div class="credential-title-row">
                            <button
                              type="button"
                              class="favorite-btn ${item.favorite ? "is-fav" : ""}"
                              data-action="toggle-favorite"
                              data-id="${escapeHtml(item.id)}"
                              aria-label="${item.favorite ? "Remove from favorites" : "Mark as favorite"}"
                              title="${item.favorite ? "Favorite" : "Mark as favorite"}"
                            >
                              ${item.favorite ? "★" : "☆"}
                            </button>
                            <span>${escapeHtml(item.title)}</span>
                          </div>
                          <div class="credential-meta-inline">
                            <span>${escapeHtml(item.category)}</span>
                            ${
                              tagsText
                                ? `<span aria-hidden="true">·</span><span>${tagsText}</span>`
                                : ""
                            }
                            ${
                              item.url
                                ? `<span aria-hidden="true">·</span><span class="mono">${escapeHtml(item.url)}</span>`
                                : ""
                            }
                            <span aria-hidden="true">·</span>
                            <span class="tabular-nums">Updated ${escapeHtml(formatShortDate(item.updated_at))}</span>
                          </div>
                        </div>
                      </td>

                      <td>
                        <div class="secret-cell">
                          <span>${escapeHtml(item.username || "—")}</span>
                          ${
                            item.username
                              ? `<button type="button" class="btn btn-ghost" data-action="copy-username" data-id="${escapeHtml(item.id)}">Copy</button>`
                              : ""
                          }
                        </div>
                      </td>

                      <td>
                        <div class="secret-cell">
                          <span>${
                            isRevealed
                              ? escapeHtml(item.password)
                              : "••••••••••••"
                          }</span>
                          <button type="button" class="btn btn-ghost" data-action="toggle-reveal" data-id="${escapeHtml(item.id)}">
                            ${isRevealed ? "Hide" : "Reveal"}
                          </button>
                          <button type="button" class="btn btn-ghost" data-action="copy-password" data-id="${escapeHtml(item.id)}">
                            Copy
                          </button>
                        </div>
                      </td>

                      <td>
                        <div class="row-actions">
                          <button type="button" class="btn btn-secondary" data-action="edit-item" data-id="${escapeHtml(item.id)}">
                            Edit
                          </button>
                          <button type="button" class="btn btn-danger" data-action="delete-item" data-id="${escapeHtml(item.id)}">
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  `;
                })
                .join("")}
            </tbody>
          </table>
        `;

    return `
      <div class="workspace-toolbar">
        <div class="search-box">
          <input
            id="vault-search-input"
            type="search"
            class="form-input"
            placeholder="Search decrypted titles, usernames, URLs, tags, or notes..."
            value="${escapeHtml(this.searchQuery)}"
            aria-label="Search decrypted credentials"
          />
        </div>
        <div style="display: flex; align-items: center; gap: 0.75rem;">
          <button type="button" class="btn btn-secondary" id="open-generator-tab-btn">
            Password Generator
          </button>
          <button type="button" class="btn btn-primary" id="new-credential-btn">
            + New Credential
          </button>
        </div>
      </div>

      <div class="vault-table-container">
        ${rowsHtml}
      </div>
    `;
  }

  /* ========================================================================
     Tab 2: CSPRNG Password Generator
     ======================================================================== */
  renderGeneratorTabHtml() {
    const cfg = this.generatorConfig;
    return `
      <div class="auth-panel" style="max-width: 680px;">
        <div class="form-stack">
          <div>
            <h2>Cryptographic Password Generator</h2>
            <p class="field-hint">
              Passwords are generated locally in your browser using Web Crypto CSPRNG with unbiased rejection sampling. Generated values are never transmitted or logged.
            </p>
          </div>

          <div class="generator-display">
            <span id="gen-password-output">${escapeHtml(this.generatedPassword)}</span>
            <div style="display: flex; gap: 0.5rem; flex-shrink: 0;">
              <button type="button" class="btn btn-secondary" id="gen-regenerate-btn">Regenerate</button>
              <button type="button" class="btn btn-primary" id="gen-copy-btn">Copy</button>
            </div>
          </div>

          ${this.renderStrengthMeterHtml(this.generatedPassword)}

          <div class="field-group">
            <div class="field-label-row">
              <label class="field-label" for="gen-length-range">Password Length</label>
              <span class="mono tabular-nums" id="gen-length-label">${cfg.length} characters</span>
            </div>
            <input
              id="gen-length-range"
              type="range"
              min="8"
              max="64"
              value="${cfg.length}"
              style="width: 100%; accent-color: var(--accent-primary);"
            />
          </div>

          <div class="form-grid-2">
            <label class="checkbox-row">
              <input type="checkbox" id="gen-upper" ${cfg.uppercase ? "checked" : ""} />
              <span>Uppercase Letters (A–Z)</span>
            </label>
            <label class="checkbox-row">
              <input type="checkbox" id="gen-lower" ${cfg.lowercase ? "checked" : ""} />
              <span>Lowercase Letters (a–z)</span>
            </label>
            <label class="checkbox-row">
              <input type="checkbox" id="gen-numbers" ${cfg.numbers ? "checked" : ""} />
              <span>Numbers (0–9)</span>
            </label>
            <label class="checkbox-row">
              <input type="checkbox" id="gen-symbols" ${cfg.symbols ? "checked" : ""} />
              <span>Symbols (!@#$%^&amp;*...)</span>
            </label>
          </div>

          <label class="checkbox-row">
            <input type="checkbox" id="gen-ambiguous" ${cfg.excludeAmbiguous ? "checked" : ""} />
            <span>Exclude Ambiguous Characters (0, O, o, 1, l, I, |, \`, ', ")</span>
          </label>

          <div class="modal-footer">
            <button type="button" class="btn btn-primary" id="gen-use-in-new-item-btn">
              Use Password in New Credential
            </button>
          </div>
        </div>
      </div>
    `;
  }

  /* ========================================================================
     Tab 3: Master Key Rotation & Security Settings
     ======================================================================== */
  renderSecurityTabHtml() {
    const s = this.vaultState.vaultSettings;
    const currentTimeout = s?.inactivity_timeout_minutes || 5;

    return `
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 1.5rem; align-items: start;">
        <section class="auth-panel">
          <form id="change-master-password-form" class="form-stack" novalidate>
            <div>
              <h2>Rotate Vault Master Password</h2>
              <p class="field-hint">
                Re-derives your Argon2id wrapping key with a fresh 16-byte salt and re-wraps your 256-bit VEK with a fresh 24-byte nonce. Existing vault item ciphertexts do not need to be re-encrypted.
              </p>
            </div>

            <div class="field-group">
              <label class="field-label" for="mp-current">Current Vault Master Password</label>
              <div class="input-wrapper">
                <input id="mp-current" type="password" class="form-input mono-input" autocomplete="current-password" required />
                <button type="button" class="input-inline-btn" data-toggle-input="mp-current">Show</button>
              </div>
            </div>

            <div class="field-group">
              <label class="field-label" for="mp-new">New Vault Master Password</label>
              <div class="input-wrapper">
                <input id="mp-new" type="password" class="form-input mono-input" autocomplete="new-password" placeholder="Minimum 10 characters" required />
                <button type="button" class="input-inline-btn" data-toggle-input="mp-new">Show</button>
              </div>
              <div id="mp-new-strength-slot"></div>
            </div>

            <div class="field-group">
              <label class="field-label" for="mp-confirm">Confirm New Vault Master Password</label>
              <div class="input-wrapper">
                <input id="mp-confirm" type="password" class="form-input mono-input" autocomplete="new-password" required />
                <button type="button" class="input-inline-btn" data-toggle-input="mp-confirm">Show</button>
              </div>
            </div>

            <div class="field-group">
              <label class="field-label" for="mp-timeout">Inactivity Auto-Lock Timeout</label>
              <select id="mp-timeout" class="form-select tabular-nums">
                ${[1, 5, 10, 15, 30, 60]
                  .map(
                    (m) =>
                      `<option value="${m}" ${
                        m === currentTimeout ? "selected" : ""
                      }>${m} ${m === 1 ? "minute" : "minutes"}</option>`
                  )
                  .join("")}
              </select>
            </div>

            <button type="submit" class="btn btn-primary" ${this.isBusy ? "disabled" : ""}>
              ${this.isBusy ? "Re-wrapping VEK in Browser..." : "Update Master Password & Re-wrap VEK"}
            </button>
          </form>
        </section>

        <section class="auth-panel">
          <div class="form-stack">
            <h2>Active Cryptographic Envelope</h2>
            <p class="field-hint">
              Public envelope parameters stored on the server. Neither your Master Password nor your raw 256-bit VEK is ever stored on disk or transmitted.
            </p>

            <div class="architecture-list">
              <div class="architecture-item">
                <h3>Key Derivation Function</h3>
                <p class="mono tabular-nums">${escapeHtml(s.kdf_algorithm)} (v${escapeHtml(s.kdf_version)}) · opslimit=${escapeHtml(s.kdf_params.opslimit)} · memlimit=${escapeHtml(s.kdf_params.memlimit)} bytes</p>
              </div>
              <div class="architecture-item">
                <h3>KDF Salt (16 bytes Base64)</h3>
                <p class="mono" style="word-break: break-all;">${escapeHtml(s.kdf_salt)}</p>
              </div>
              <div class="architecture-item">
                <h3>VEK Wrapping Nonce (24 bytes Base64)</h3>
                <p class="mono" style="word-break: break-all;">${escapeHtml(s.vek_nonce)}</p>
              </div>
              <div class="architecture-item">
                <h3>Wrapped VEK Ciphertext (48 bytes Base64)</h3>
                <p class="mono" style="word-break: break-all;">${escapeHtml(s.encrypted_vek)}</p>
              </div>
            </div>
          </div>
        </section>
      </div>
    `;
  }

  /* ========================================================================
     Tab 4: Encrypted Backup Export & Import
     ======================================================================== */
  renderBackupTabHtml() {
    return `
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 1.5rem; align-items: start;">
        <section class="auth-panel">
          <div class="form-stack">
            <h2>Export Encrypted Vault Backup</h2>
            <p class="field-hint">
              Downloads a versioned JSON archive containing your KDF salt, bounded parameters, wrapped VEK, and XChaCha20-Poly1305 encrypted items.
            </p>
            <div class="notice-banner">
              <strong>Security Policy:</strong> Plaintext CSV export is intentionally disabled to prevent accidental credential leakage onto unencrypted disks or cloud sync folders.
            </div>
            <button type="button" class="btn btn-primary" id="export-backup-btn" ${this.isBusy ? "disabled" : ""}>
              Download Encrypted Backup (.json)
            </button>
          </div>
        </section>

        <section class="auth-panel">
          <form id="import-backup-form" class="form-stack" novalidate>
            <div>
              <h2>Restore Encrypted Vault Backup</h2>
              <p class="field-hint">
                Select an AegisVault encrypted backup file and provide the backup's Vault Master Password to verify authenticity before atomic restoration.
              </p>
            </div>

            <div class="field-group">
              <label class="field-label" for="import-file-input">Encrypted Backup File (.json)</label>
              <input id="import-file-input" type="file" accept=".json,application/json" class="form-input" required />
            </div>

            <div class="field-group">
              <label class="field-label" for="import-master-password">Backup Vault Master Password</label>
              <div class="input-wrapper">
                <input
                  id="import-master-password"
                  type="password"
                  class="form-input mono-input"
                  placeholder="Enter master password for this backup"
                  required
                />
                <button type="button" class="input-inline-btn" data-toggle-input="import-master-password">Show</button>
              </div>
            </div>

            <button type="submit" class="btn btn-secondary" ${this.isBusy ? "disabled" : ""}>
              ${this.isBusy ? "Verifying & Restoring Backup..." : "Verify & Restore Encrypted Backup"}
            </button>
          </form>
        </section>
      </div>
    `;
  }

  /* ========================================================================
     Modals: Create/Edit Credential & Delete Confirmation
     ======================================================================== */
  renderItemModalHtml() {
    const item = this.editingItem || {
      id: null,
      title: "",
      username: "",
      password: "",
      url: "",
      category: "General",
      tags: [],
      notes: "",
      favorite: false,
    };
    const isEdit = Boolean(item.id);
    const tagsStr = Array.isArray(item.tags) ? item.tags.join(", ") : "";

    return `
      <div class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="item-modal-title">
        <div class="modal-card">
          <div class="modal-header">
            <h2 id="item-modal-title">${isEdit ? "Edit Encrypted Credential" : "New Encrypted Credential"}</h2>
            <button type="button" class="btn btn-ghost" id="close-item-modal-btn">Close</button>
          </div>

          <form id="credential-item-form" class="form-stack" novalidate>
            <div class="form-grid-2">
              <div class="field-group">
                <label class="field-label" for="item-title">Service or Title *</label>
                <input id="item-title" type="text" class="form-input" value="${escapeHtml(item.title)}" placeholder="e.g., Production Bastion SSH" required />
              </div>

              <div class="field-group">
                <label class="field-label" for="item-category">Category</label>
                <select id="item-category" class="form-select">
                  ${CATEGORIES.map(
                    (c) =>
                      `<option value="${escapeHtml(c)}" ${
                        c === item.category ? "selected" : ""
                      }>${escapeHtml(c)}</option>`
                  ).join("")}
                </select>
              </div>
            </div>

            <div class="form-grid-2">
              <div class="field-group">
                <label class="field-label" for="item-username">Username or Email</label>
                <input id="item-username" type="text" class="form-input" value="${escapeHtml(item.username)}" placeholder="secops-admin" />
              </div>

              <div class="field-group">
                <label class="field-label" for="item-url">Website or Host URL</label>
                <input id="item-url" type="url" class="form-input" value="${escapeHtml(item.url)}" placeholder="https://internal.example.edu" />
              </div>
            </div>

            <div class="field-group">
              <div class="field-label-row">
                <label class="field-label" for="item-password">Password or Secret</label>
                <button type="button" class="btn btn-ghost" id="modal-generate-pwd-btn">Generate Strong Password</button>
              </div>
              <div class="input-wrapper">
                <input id="item-password" type="password" class="form-input mono-input" value="${escapeHtml(item.password)}" placeholder="Enter or generate secret" />
                <button type="button" class="input-inline-btn" data-toggle-input="item-password">Show</button>
              </div>
              <div id="modal-pwd-strength-slot">
                ${this.renderStrengthMeterHtml(item.password)}
              </div>
            </div>

            <div class="field-group">
              <label class="field-label" for="item-tags">Tags (comma-separated, encrypted with record)</label>
              <input id="item-tags" type="text" class="form-input" value="${escapeHtml(tagsStr)}" placeholder="ssh, production, 2fa" />
            </div>

            <div class="field-group">
              <label class="field-label" for="item-notes">Encrypted Notes</label>
              <textarea id="item-notes" class="form-textarea" placeholder="Recovery codes, port numbers, or rotation instructions...">${escapeHtml(item.notes)}</textarea>
            </div>

            <label class="checkbox-row">
              <input type="checkbox" id="item-favorite" ${item.favorite ? "checked" : ""} />
              <span>Pin to Favorites</span>
            </label>

            <div class="modal-footer">
              <button type="button" class="btn btn-secondary" id="cancel-item-modal-btn">Cancel</button>
              <button type="submit" class="btn btn-primary" ${this.isBusy ? "disabled" : ""}>
                ${this.isBusy ? "Encrypting & Saving..." : isEdit ? "Encrypt & Update" : "Encrypt & Save"}
              </button>
            </div>
          </form>
        </div>
      </div>
    `;
  }

  renderDeleteConfirmModalHtml() {
    const item = this.deletingItem;
    if (!item) return "";
    return `
      <div class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="delete-modal-title">
        <div class="modal-card" style="max-width: 460px;">
          <div class="modal-header">
            <h2 id="delete-modal-title">Confirm Credential Deletion</h2>
          </div>
          <p style="color: var(--text-secondary);">
            Are you sure you want to permanently delete <strong>${escapeHtml(item.title)}</strong>? This encrypted record will be removed from the database and cannot be recovered unless you have an encrypted backup.
          </p>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" id="cancel-delete-btn">Cancel</button>
            <button type="button" class="btn btn-danger" id="confirm-delete-btn" ${this.isBusy ? "disabled" : ""}>
              ${this.isBusy ? "Deleting..." : "Permanently Delete"}
            </button>
          </div>
        </div>
      </div>
    `;
  }

  /* ========================================================================
     Event Binding & Handlers
     ======================================================================== */
  bindCommonToggleEvents() {
    this.root.querySelectorAll("[data-toggle-input]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const inputId = btn.getAttribute("data-toggle-input");
        const input = document.getElementById(inputId);
        if (!input) return;
        const isPassword = input.type === "password";
        input.type = isPassword ? "text" : "password";
        btn.textContent = isPassword ? "Hide" : "Show";
      });
    });
  }

  bindDashboardEvents() {
    this.bindCommonToggleEvents();

    // Topbar tab switching
    this.root.querySelectorAll("[data-tab]").forEach((btn) => {
      btn.addEventListener("click", () => {
        this.activeTab = btn.getAttribute("data-tab") || "credentials";
        this.setBanner(null, "");
        this.render();
      });
    });

    // Lock Vault button
    document
      .getElementById("autolock-countdown")
      ?.addEventListener("click", async () => {
        this.autoLock.stop();
        this.vaultState.lockVault();
        this.revealedPasswords.clear();
        await clearClipboardIfUnchanged();
        this.showToast("Vault locked and VEK zeroed in memory.");
        this.render();
      });

    // Logout button
    document
      .getElementById("dashboard-logout-btn")
      ?.addEventListener("click", () => this.handleLogout());

    // Sidebar category & favorite filters
    this.root.querySelectorAll("[data-filter-cat]").forEach((btn) => {
      btn.addEventListener("click", () => {
        this.activeTab = "credentials";
        this.selectedCategory = btn.getAttribute("data-filter-cat") || "all";
        this.favoritesOnly = btn.getAttribute("data-filter-fav") === "true";
        this.render();
      });
    });

    // Search box
    const searchInput = document.getElementById("vault-search-input");
    searchInput?.addEventListener("input", () => {
      const cursorPos = searchInput.selectionStart;
      this.searchQuery = searchInput.value;
      this.render();
      const refreshed = document.getElementById("vault-search-input");
      if (refreshed) {
        refreshed.focus();
        refreshed.setSelectionRange(cursorPos, cursorPos);
      }
    });

    // Toolbar buttons
    document
      .getElementById("new-credential-btn")
      ?.addEventListener("click", () => {
        this.editingItem = null;
        this.isItemModalOpen = true;
        this.render();
      });

    document
      .getElementById("empty-new-item-btn")
      ?.addEventListener("click", () => {
        this.editingItem = null;
        this.isItemModalOpen = true;
        this.render();
      });

    document
      .getElementById("clear-filters-btn")
      ?.addEventListener("click", () => {
        this.searchQuery = "";
        this.selectedCategory = "all";
        this.favoritesOnly = false;
        this.render();
      });

    document
      .getElementById("open-generator-tab-btn")
      ?.addEventListener("click", () => {
        this.activeTab = "generator";
        this.render();
      });

    // Table row actions
    this.root.querySelectorAll("[data-action]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const action = btn.getAttribute("data-action");
        const id = btn.getAttribute("data-id");
        const item = this.vaultState.decryptedItems.find((i) => i.id === id);
        if (!item) return;

        if (action === "toggle-reveal") {
          if (this.revealedPasswords.has(id)) {
            this.revealedPasswords.delete(id);
          } else {
            this.revealedPasswords.add(id);
          }
          this.render();
        } else if (action === "copy-username") {
          const ok = await copySecretToClipboard(item.username, {
            clearAfterMs: 25000,
          });
          if (ok) this.showToast(`Copied username for "${item.title}".`);
        } else if (action === "copy-password") {
          const ok = await copySecretToClipboard(item.password, {
            clearAfterMs: 25000,
            onCleared: () => this.showToast("Clipboard automatically cleared."),
          });
          if (ok)
            this.showToast(
              `Copied password for "${item.title}" (auto-clears in 25s).`
            );
        } else if (action === "edit-item") {
          this.editingItem = { ...item, tags: [...(item.tags || [])] };
          this.isItemModalOpen = true;
          this.render();
        } else if (action === "delete-item") {
          this.deletingItem = item;
          this.render();
        } else if (action === "toggle-favorite") {
          await this.handleToggleFavorite(item);
        }
      });
    });

    this.bindItemModalEvents();
    this.bindDeleteModalEvents();
    this.bindGeneratorTabEvents();
    this.bindSecurityTabEvents();
    this.bindBackupTabEvents();
  }

  bindItemModalEvents() {
    if (!this.isItemModalOpen) return;

    const closeModal = () => {
      this.isItemModalOpen = false;
      this.editingItem = null;
      this.render();
    };

    document
      .getElementById("close-item-modal-btn")
      ?.addEventListener("click", closeModal);
    document
      .getElementById("cancel-item-modal-btn")
      ?.addEventListener("click", closeModal);

    const pwdInput = document.getElementById("item-password");
    const strengthSlot = document.getElementById("modal-pwd-strength-slot");
    pwdInput?.addEventListener("input", () => {
      if (strengthSlot) {
        strengthSlot.innerHTML = this.renderStrengthMeterHtml(pwdInput.value);
      }
    });

    document
      .getElementById("modal-generate-pwd-btn")
      ?.addEventListener("click", () => {
        const fresh = generatePassword(this.generatorConfig);
        if (pwdInput) {
          pwdInput.value = fresh;
          pwdInput.type = "text";
        }
        if (strengthSlot) {
          strengthSlot.innerHTML = this.renderStrengthMeterHtml(fresh);
        }
      });

    const form = document.getElementById("credential-item-form");
    form?.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (this.isBusy) return;

      const entry = {
        title: document.getElementById("item-title")?.value || "",
        category: document.getElementById("item-category")?.value || "General",
        username: document.getElementById("item-username")?.value || "",
        url: document.getElementById("item-url")?.value || "",
        password: document.getElementById("item-password")?.value || "",
        tags: document.getElementById("item-tags")?.value || "",
        notes: document.getElementById("item-notes")?.value || "",
        favorite: Boolean(document.getElementById("item-favorite")?.checked),
      };

      const existingId = this.editingItem?.id || null;
      this.isBusy = true;
      this.render();

      try {
        const encryptedPayload = await this.vaultState.prepareEncryptedItem(
          entry,
          existingId
        );

        if (existingId) {
          await apiRequest(`/api/vault/items/${existingId}`, {
            method: "PUT",
            body: {
              ciphertext: encryptedPayload.ciphertext,
              nonce: encryptedPayload.nonce,
              encryption_version: encryptedPayload.encryption_version,
            },
          });
        } else {
          await apiRequest("/api/vault/items", {
            method: "POST",
            body: encryptedPayload,
          });
        }

        await this.refreshEncryptedItems();
        this.isItemModalOpen = false;
        this.editingItem = null;
        this.showToast(
          existingId
            ? "Encrypted credential updated."
            : "Encrypted credential saved."
        );
      } catch (err) {
        this.setBanner("error", err.message || "Failed to save credential.");
      } finally {
        this.isBusy = false;
        this.render();
      }
    });
  }

  bindDeleteModalEvents() {
    if (!this.deletingItem) return;

    document
      .getElementById("cancel-delete-btn")
      ?.addEventListener("click", () => {
        this.deletingItem = null;
        this.render();
      });

    document
      .getElementById("confirm-delete-btn")
      ?.addEventListener("click", async () => {
        if (this.isBusy || !this.deletingItem) return;
        const targetId = this.deletingItem.id;
        this.isBusy = true;
        this.render();

        try {
          await apiRequest(`/api/vault/items/${targetId}`, {
            method: "DELETE",
          });
          this.revealedPasswords.delete(targetId);
          this.deletingItem = null;
          await this.refreshEncryptedItems();
          this.showToast("Credential deleted.");
        } catch (err) {
          this.setBanner("error", err.message || "Failed to delete item.");
        } finally {
          this.isBusy = false;
          this.render();
        }
      });
  }

  async handleToggleFavorite(item) {
    try {
      const updatedEntry = { ...item, favorite: !item.favorite };
      const encryptedPayload = await this.vaultState.prepareEncryptedItem(
        updatedEntry,
        item.id
      );
      await apiRequest(`/api/vault/items/${item.id}`, {
        method: "PUT",
        body: {
          ciphertext: encryptedPayload.ciphertext,
          nonce: encryptedPayload.nonce,
          encryption_version: encryptedPayload.encryption_version,
        },
      });
      await this.refreshEncryptedItems();
      this.render();
    } catch (err) {
      this.setBanner("error", err.message || "Failed to update favorite.");
      this.render();
    }
  }

  bindGeneratorTabEvents() {
    if (this.activeTab !== "generator") return;

    const regenerate = () => {
      try {
        this.generatedPassword = generatePassword(this.generatorConfig);
        this.setBanner(null, "");
      } catch (err) {
        this.setBanner("error", err.message);
      }
      this.render();
    };

    document
      .getElementById("gen-regenerate-btn")
      ?.addEventListener("click", regenerate);

    document
      .getElementById("gen-copy-btn")
      ?.addEventListener("click", async () => {
        const ok = await copySecretToClipboard(this.generatedPassword, {
          clearAfterMs: 25000,
        });
        if (ok)
          this.showToast("Generated password copied (auto-clears in 25s).");
      });

    document
      .getElementById("gen-length-range")
      ?.addEventListener("input", (e) => {
        this.generatorConfig.length = Number(e.target.value);
        regenerate();
      });

    const checkboxMap = [
      ["gen-upper", "uppercase"],
      ["gen-lower", "lowercase"],
      ["gen-numbers", "numbers"],
      ["gen-symbols", "symbols"],
      ["gen-ambiguous", "excludeAmbiguous"],
    ];

    for (const [id, key] of checkboxMap) {
      document.getElementById(id)?.addEventListener("change", (e) => {
        this.generatorConfig[key] = Boolean(e.target.checked);
        regenerate();
      });
    }

    document
      .getElementById("gen-use-in-new-item-btn")
      ?.addEventListener("click", () => {
        this.editingItem = {
          id: null,
          title: "",
          username: "",
          password: this.generatedPassword,
          url: "",
          category: "General",
          tags: [],
          notes: "",
          favorite: false,
        };
        this.activeTab = "credentials";
        this.isItemModalOpen = true;
        this.render();
      });
  }

  bindSecurityTabEvents() {
    if (this.activeTab !== "security") return;

    const newMpInput = document.getElementById("mp-new");
    const strengthSlot = document.getElementById("mp-new-strength-slot");
    newMpInput?.addEventListener("input", () => {
      if (strengthSlot) {
        strengthSlot.innerHTML = this.renderStrengthMeterHtml(newMpInput.value);
      }
    });

    const form = document.getElementById("change-master-password-form");
    form?.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (this.isBusy) return;

      const currentMasterPassword =
        document.getElementById("mp-current")?.value || "";
      const newMasterPassword = document.getElementById("mp-new")?.value || "";
      const confirmNewMasterPassword =
        document.getElementById("mp-confirm")?.value || "";
      const inactivityTimeoutMinutes = Number(
        document.getElementById("mp-timeout")?.value || 5
      );

      try {
        validateMasterPasswordSetup({
          masterPassword: newMasterPassword,
          confirmMasterPassword: confirmNewMasterPassword,
        });
      } catch (err) {
        this.setBanner("error", err.message);
        this.render();
        return;
      }

      this.isBusy = true;
      this.setBanner(null, "");
      this.render();

      try {
        const updatedEnvelope =
          await this.vaultState.prepareMasterPasswordChange({
            currentMasterPassword,
            newMasterPassword,
            inactivityTimeoutMinutes,
          });

        const res = await apiRequest("/api/vault/settings/master-password", {
          method: "PUT",
          body: updatedEnvelope,
        });

        this.vaultState.setVaultSettings(res.vault_settings);
        this.autoLock.setTimeoutMinutes(
          res.vault_settings.inactivity_timeout_minutes
        );
        this.setBanner(
          "success",
          "Vault Master Password rotated and VEK re-wrapped with a new salt and nonce."
        );
      } catch (err) {
        this.setBanner(
          "error",
          err.message || "Failed to update Vault Master Password."
        );
      } finally {
        this.isBusy = false;
        this.render();
      }
    });
  }

  bindBackupTabEvents() {
    if (this.activeTab !== "backup") return;

    document
      .getElementById("export-backup-btn")
      ?.addEventListener("click", async () => {
        if (this.isBusy) return;
        this.isBusy = true;
        this.setBanner(null, "");
        this.render();

        try {
          const bundle = await apiRequest("/api/vault/export", {
            method: "GET",
          });
          const jsonStr = JSON.stringify(bundle, null, 2);
          const blob = new Blob([jsonStr], { type: "application/json" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          const dateTag = new Date().toISOString().slice(0, 10);
          a.href = url;
          a.download = `aegisvault-encrypted-backup-${dateTag}.json`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
          this.showToast("Encrypted backup downloaded.");
        } catch (err) {
          this.setBanner("error", err.message || "Failed to export backup.");
        } finally {
          this.isBusy = false;
          this.render();
        }
      });

    const importForm = document.getElementById("import-backup-form");
    importForm?.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (this.isBusy) return;

      const fileInput = document.getElementById("import-file-input");
      const masterPassword =
        document.getElementById("import-master-password")?.value || "";
      const file = fileInput?.files?.[0];

      if (!file) {
        this.setBanner("error", "Select an encrypted backup JSON file.");
        this.render();
        return;
      }
      if (!masterPassword) {
        this.setBanner(
          "error",
          "Enter the Vault Master Password for the backup archive."
        );
        this.render();
        return;
      }

      this.isBusy = true;
      this.setBanner(null, "");
      this.render();

      try {
        const rawText = await file.text();
        let parsedArchive;
        try {
          parsedArchive = JSON.parse(rawText);
        } catch {
          throw new Error("Selected file is not valid JSON.");
        }

        validateEncryptedBackupArchive(parsedArchive);

        const archiveOwnerId =
          parsedArchive.user_id || this.vaultState.user.id;

        // Verify the master password unlocks the backup's VEK before importing
        const backupVek = await unlockVaultEncryptionKey({
          masterPassword,
          vaultSettings: parsedArchive.vault_settings,
          userId: archiveOwnerId,
        });

        // Verify every item in the backup authenticates cleanly under its AAD
        const verifiedPlaintextItems = [];
        for (const item of parsedArchive.items) {
          const dec = await decryptVaultItem({
            vek: backupVek,
            userId: archiveOwnerId,
            encryptedRecord: item,
          });
          verifiedPlaintextItems.push(dec);
        }

        let importPayload;
        if (archiveOwnerId === this.vaultState.user.id) {
          importPayload = {
            backup_format: parsedArchive.backup_format,
            backup_version: parsedArchive.backup_version,
            exported_at: parsedArchive.exported_at || null,
            vault_settings: parsedArchive.vault_settings,
            items: parsedArchive.items,
          };
          this.vaultState.lockVault();
          this.vaultState.vek = backupVek;
        } else {
          // Re-bind AAD to the current user's account ID when restoring across accounts
          const newEnvelope = await this.vaultState.setupNewVault(
            masterPassword,
            parsedArchive.vault_settings.inactivity_timeout_minutes || 5,
            parsedArchive.vault_settings.kdf_params
          );
          const reencryptedItems = [];
          for (const dec of verifiedPlaintextItems) {
            const reenc = await this.vaultState.prepareEncryptedItem(dec);
            reencryptedItems.push(reenc);
          }
          importPayload = {
            backup_format: "aegisvault-encrypted-backup",
            backup_version: 1,
            exported_at: parsedArchive.exported_at || null,
            vault_settings: newEnvelope,
            items: reencryptedItems,
          };
        }

        const res = await apiRequest("/api/vault/import", {
          method: "POST",
          body: importPayload,
        });

        this.vaultState.setVaultSettings(res.vault_settings);
        await this.refreshEncryptedItems();
        this.setBanner(
          "success",
          `Successfully verified and restored ${res.imported_count} encrypted credential(s).`
        );
      } catch (err) {
        this.setBanner("error", err.message || "Backup restoration failed.");
      } finally {
        this.isBusy = false;
        this.render();
      }
    });
  }

  async refreshEncryptedItems() {
    const res = await apiRequest("/api/vault/items", { method: "GET" });
    await this.vaultState.setEncryptedItemsAndDecrypt(res.items || []);
  }

  async handleLogout() {
    this.autoLock.stop();
    this.vaultState.clearAll();
    this.revealedPasswords.clear();
    await clearClipboardIfUnchanged();
    try {
      await logoutAccount();
    } catch {
      // Session already cleared locally
    }
    this.setBanner(null, "");
    this.render();
  }
}
