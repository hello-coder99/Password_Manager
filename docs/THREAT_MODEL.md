# AegisVault Threat Model

## 1. Security Assumptions & Trust Boundaries

1. **Transport Security:** Production deployments must run behind HTTPS (TLS 1.2/1.3) terminated at Nginx or an upstream TLS load balancer. Local HTTP (`http://localhost:8080`) is strictly for local development over the loopback interface and is not safe for transmitting account login passwords over untrusted networks.
2. **Endpoint Integrity:** Client-side encryption protects vault confidentiality against server, network, and database compromise, assuming the user's browser environment and the static JavaScript/WebAssembly bundle served to the browser have not been subverted at the time the user unlocks their vault.
3. **Unrecoverable Master Password:** Because the server never receives the Vault Master Password or raw 256-bit VEK, there is no server-side "forgot master password" backdoor. Losing the Vault Master Password renders the encrypted vault permanently unrecoverable.

---

## 2. Database & Redis Compromise Analysis

A primary goal of AegisVault's envelope encryption is minimizing the blast radius of a backend data store breach.

| Compromised Component | What an Attacker Can Observe | What Remains Cryptographically Protected |
| :--- | :--- | :--- |
| **MariaDB Read Compromise (SQLi / Backup Leak)** | - User email addresses (`users.email`)<br>- Salted Argon2id hashes of Account Login Passwords (`users.login_password_hash`)<br>- KDF parameters, 16-byte salts, 24-byte nonces, and 48-byte wrapped VEKs (`vault_settings`)<br>- Item count, timestamps, UUIDs, 24-byte nonces, and XChaCha20-Poly1305 ciphertexts (`vault_items`) | - **Vault Master Passwords** (never stored)<br>- **Raw 256-bit VEK** (encrypted under Argon2id-derived key with 64 MiB memory cost)<br>- **All Credential Fields:** service titles, usernames, passwords, URLs, tags, categories, and notes are encrypted together in `vault_items.ciphertext` |
| **MariaDB Write / Tampering Compromise** | Attacker could attempt to swap ciphertexts between User A and User B, or swap two item ciphertexts belonging to User A | **Detected & Rejected:** Every item ciphertext and wrapped VEK is bound via Poly1305 AAD to `(user_id, item_id, encryption_version)`. Swapped or altered records fail decryption immediately |
| **Redis Compromise** | - Active server-side session identifiers and user UUID mappings<br>- Rate-limiter IP counters | - No vault keys, master passwords, decrypted credentials, or generated passwords are ever stored in Redis |

---

## 3. Threat Catalog & Implemented Mitigations

### 3.1 Credential Stuffing, Brute Force, and User Enumeration
- **Mitigations:**
  - Server-side `Flask-Limiter` enforces strict rate limits on `/api/auth/login` (`10/minute`) and `/api/auth/register` (`10/minute`).
  - `verify_login_password()` in `app/security/password_hashing.py` verifies against a precomputed dummy Argon2id hash when an email does not exist, equalizing response timing.
  - Authentication endpoints return uniform error messages (`"Invalid email or account password."`).

### 3.2 Cross-Site Request Forgery (CSRF)
- **Mitigations:**
  - Session cookies enforce `HttpOnly` and `SameSite=Lax` (`Secure` in production).
  - Every state-changing request (`POST`, `PUT`, `DELETE`) requires a valid signed `X-CSRF-Token` header verified by `Flask-WTF` (`CSRFProtect`).

### 3.3 Cross-Site Scripting (XSS) & Malicious Ciphertext Payloads
- **Mitigations:**
  - All dynamic values rendered in `frontend/src/vault/vault-ui.js` pass through `escapeHtml()` before DOM insertion.
  - Nginx and Flask enforce a strict `Content-Security-Policy` (`default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; base-uri 'self'; form-action 'self';`). Note that `'wasm-unsafe-eval'` is the minimal W3C CSP directive required to compile WebAssembly (`libsodium.js`) without permitting JavaScript `'unsafe-eval'` or inline scripts.

### 3.4 Insecure Direct Object References (IDOR)
- **Mitigations:**
  - Every `/api/vault/*` endpoint requires `@login_required` and scopes SQLAlchemy queries to `g.current_user.id`.
  - `get_owned_vault_item()` verifies ownership via `verify_resource_ownership(item.user_id, user.id)` and returns `404 Not Found` on cross-user access attempts so attackers cannot probe UUID existence.
  - `/api/vault/import` rejects any backup containing an item UUID owned by another user (`CROSS_USER_ITEM_CONFLICT`).

### 3.5 Key Derivation Denial-of-Service (KDF Parameter Tampering)
- **Threat:** A compromised server or tampered backup file could supply `memlimit = 4 GiB` or `opslimit = 1000` to crash the user's browser tab during Argon2id derivation.
- **Mitigation:** Both `app/schemas/vault.py` (server-side) and `frontend/src/crypto/key-derivation.js` (`validateKdfConfig`) enforce strict upper and lower bounds (`opslimit` in `[2, 10]`, `memlimit` in `[16 MiB, 256 MiB]`) before invoking `sodium.crypto_pwhash`.

### 3.6 Redis Outage / Cache Unavailability
- **Threat:** If Redis becomes unreachable, an improperly configured app might bypass rate limits, crash with stack traces, or fall back to insecure session handling.
- **Mitigation:** `FailClosedSessionWrapper` in `app/__init__.py` catches `RedisError` and fails closed with HTTP `503 Service Unavailable` (`REDIS_UNAVAILABLE`) on all session-dependent routes while reporting degraded health on `/api/health`.

---

## 4. Known Limitations & Residual Risks

1. **JavaScript Process Memory Residency:** When the vault is locked or times out, AegisVault zeroes the `Uint8Array` VEK buffer via `zeroBuffers()` and clears decrypted item references. However, JavaScript engines manage strings as immutable garbage-collected values and do not guarantee immediate physical RAM erasure prior to GC compaction.
2. **Malicious Server Code Delivery:** As with any web-based password manager, if an attacker compromises the Nginx/Flask host and modifies the static JavaScript bundle served to the browser, the modified script could capture the Vault Master Password the next time the user unlocks their vault.
3. **Client-Side Malware / Browser Extensions:** Privileged browser extensions with DOM access or OS-level keyloggers/clipboard monitors on the client device can read revealed credentials. AegisVault mitigates casual clipboard exposure by automatically clearing copied secrets after 25 seconds.
