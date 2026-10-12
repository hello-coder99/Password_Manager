# AegisVault Security Verification Checklist

## 1. Cryptographic & Key Management Controls

- [x] **Two-Secret Separation:** Account Login Password authenticates to Flask; Vault Master Password never leaves the browser (`BaseStrictSchema` rejects any payload containing `master_password`).
- [x] **Client-Side Envelope Encryption:** Browser generates a 256-bit random `VEK` via `crypto_aead_xchacha20poly1305_ietf_keygen()`.
- [x] **Argon2id Wrapping Key Derivation:** Browser derives a 256-bit wrapping key using `crypto_pwhash` (`ALG_ARGON2ID13`, 16-byte random salt, bounded `opslimit` and `memlimit`).
- [x] **Authenticated Encryption (AEAD):** Uses `XChaCha20-Poly1305-IETF` with fresh 24-byte CSPRNG nonces for every encryption operation.
- [x] **Per-Item & Envelope AAD Binding:** Canonical JSON AAD binds every ciphertext to `(user_id, item_id, encryption_version)` so ciphertexts cannot be moved across records or users.
- [x] **Bounded KDF Validation:** Both backend (`app/schemas/vault.py`) and frontend (`validateKdfConfig`) enforce `opslimit ∈ [2, 10]` and `memlimit ∈ [16 MiB, 256 MiB]` to prevent CPU/RAM DoS.
- [x] **Master Password Rotation:** Re-wraps the existing 256-bit VEK with a new salt and nonce without re-encrypting item ciphertexts.
- [x] **No Persistent Client Storage of Secrets:** Decrypted entries and unlocked VEK live only in JS memory (`VaultStateManager`); never written to `localStorage`, `sessionStorage`, `IndexedDB`, or cookies.
- [x] **Unbiased CSPRNG Password Generator:** Uses Web Crypto `getRandomValues()` with rejection sampling (`uniformRandomIndex`) to eliminate modulo bias.

## 2. Backend & Infrastructure Security Controls

- [x] **Argon2id Server Password Hashing:** Account login passwords hashed via `argon2-cffi` (`time_cost=3`, `memory_cost=64 MiB`, `parallelism=2`).
- [x] **Anti-Enumeration Login Verification:** Verifies against a precomputed dummy Argon2id hash when an account email does not exist.
- [x] **Redis Server-Side Sessions:** Session state stored in Redis with rotation on login (`establish_authenticated_session`) and full invalidation on logout (`terminate_session`).
- [x] **Fail-Closed Redis Outage Handling:** `FailClosedSessionWrapper` returns HTTP `503 REDIS_UNAVAILABLE` if Redis becomes unreachable.
- [x] **CSRF Protection:** `Flask-WTF` `CSRFProtect` enforced on all state-changing endpoints via `X-CSRF-Token`.
- [x] **Rate Limiting:** `Flask-Limiter` enforces strict per-IP rate limits on login, registration, and vault mutation routes.
- [x] **Strict Ownership Authorization (Anti-IDOR):** All vault queries filter by `user_id` and return `404` on cross-user access attempts.
- [x] **Zero Plaintext Credential Columns in Database:** `vault_items` stores only `id`, `user_id`, `ciphertext`, `nonce`, `encryption_version`, `created_at`, and `updated_at`.
- [x] **Sensitive Log Redaction:** `SensitiveDataLogFilter` redacts passwords, ciphertexts, salts, nonces, cookies, and CSRF tokens from logs.
- [x] **Docker Network Isolation & Non-Root Execution:** `mariadb` and `redis` reside on `internal: true` `backend_net` with no host port bindings; `api` and `nginx` run as unprivileged users.

## 3. Documented Architectural Limitations

- **Unrecoverable Vault Master Password:** If a user forgets their Vault Master Password and lacks a record of it, the encrypted vault cannot be recovered by the server.
- **JavaScript Memory Erasure Constraints:** `zeroBuffers()` overwrites `Uint8Array` key material on lock, but JS engines do not guarantee immediate physical erasure of immutable string primitives prior to garbage collection.
- **Endpoint & Static Asset Integrity:** Client-side encryption cannot protect a user who unlocks their vault on a device infected with keylogging malware or against a compromised server actively serving modified JavaScript.
