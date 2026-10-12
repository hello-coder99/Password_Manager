# AegisVault System & Cryptographic Architecture

## 1. High-Level System Architecture

AegisVault is a self-hosted, zero-knowledge password manager designed around two strict architectural boundaries:

1. **Network & Infrastructure Boundary:** Public traffic terminates at an unprivileged Nginx container. The Python Flask/Gunicorn API, MariaDB relational database, and Redis store reside on isolated internal Docker networks (`frontend_net` and `backend_net`) and are never exposed directly to the host network interface.
2. **Cryptographic Trust Boundary:** All vault key generation, Argon2id key derivation for vault unlocking, XChaCha20-Poly1305 encryption/decryption, password generation, and search/filtering occur exclusively in the user's browser via `libsodium.js` (WebAssembly). The Flask backend and MariaDB database store only authenticated ciphertext envelopes.

```mermaid
flowchart TB
    subgraph Browser["User Browser (Client Trust Zone)"]
        UI["Vanilla JS UI Controller"]
        WASM["libsodium.js (WASM)\nArgon2id + XChaCha20-Poly1305"]
        MEM["Volatile JS Memory\n(Unlocked 256-bit VEK & Decrypted Items)"]
        GEN["Web Crypto CSPRNG\nPassword Generator"]
        UI <--> WASM
        WASM <--> MEM
        UI <--> GEN
    end

    subgraph DockerHost["Docker Compose / Ubuntu VPS"]
        subgraph FrontNet["frontend_net (Internal Bridge)"]
            NGINX["Nginx Reverse Proxy\nStatic Assets + CSP + Rate/Size Limits"]
            API["Flask + Gunicorn WSGI\nBlueprints + Marshmallow + CSRFProtect"]
        end

        subgraph BackNet["backend_net (Internal Isolated Network)"]
            DB[("MariaDB 11.4\nusers | vault_settings | vault_items")]
            REDIS[("Redis 7.4\nFlask-Session & Flask-Limiter")]
        end

        NGINX -->|"/api/* (HTTP/1.1 + Proxy Headers)"| API
        API -->|"PyMySQL + SQLAlchemy"| DB
        API -->|"Server Sessions & Rate Counters"| REDIS
    end

    Browser -->|"HTTPS (Prod) / HTTP (Localhost)\nCookie: aegisvault_sid + Header: X-CSRF-Token"| NGINX
```

---

## 2. Separation of Authentication and Encryption Secrets

AegisVault requires two distinct user secrets with non-overlapping roles:

| Secret | Where It Is Processed | Cryptographic Purpose | Server Visibility |
| :--- | :--- | :--- | :--- |
| **Account Login Password** | Sent over TLS to `/api/auth/register` or `/api/auth/login` | Authenticates the user to the Flask backend using server-side `argon2-cffi` (`Argon2id`, `t=3`, `m=64 MiB`, `p=2`) | Server receives during auth and stores only the salted Argon2id hash (`users.login_password_hash`) |
| **Vault Master Password** | Processed exclusively in the browser via `libsodium-wrappers-sumo` | Derives a 256-bit `Wrapping Key` via Argon2id to encrypt/decrypt the random 256-bit `Vault Encryption Key (VEK)` | **Never transmitted, logged, or stored on the server** (`RegisterSchema` and `BaseStrictSchema` actively reject any payload containing `master_password`) |

---

## 3. Envelope Encryption & Key Hierarchy

```mermaid
flowchart LR
    MP["Vault Master Password\n(Browser Input Only)"]
    SALT["128-bit Random Salt\n(crypto_pwhash_SALTBYTES = 16B)"]
    KDF["Argon2id v1.3\n(opslimit=3, memlimit=64MiB)"]
    WK["256-bit Wrapping Key\n(Zeroed Immediately After Use)"]
    VEK["256-bit Random VEK\n(crypto_aead_xchacha20poly1305_ietf_keygen)"]
    WVEK["Encrypted VEK (48B)\n+ 24B Nonce + VEK AAD"]
    ITEM_PT["Plaintext Credential JSON\n{title, username, password, url, notes, category, tags, favorite}"]
    ITEM_CT["Encrypted Vault Item\nCiphertext + 24B Nonce + Item AAD"]

    MP --> KDF
    SALT --> KDF
    KDF --> WK
    WK -->|"XChaCha20-Poly1305 Wrap/Unwrap"| WVEK
    VEK -->|"Wrapped by WK"| WVEK
    VEK -->|"XChaCha20-Poly1305 Encrypt/Decrypt"| ITEM_CT
    ITEM_PT --> ITEM_CT
```

### 3.1 Authenticated Additional Data (AAD) Binding

To prevent an attacker with database write access from moving ciphertexts between users or swapping records within a user's vault, every XChaCha20-Poly1305 encryption operation binds canonical JSON Authenticated Additional Data (AAD):

- **VEK Envelope AAD:**
  ```json
  {"purpose":"aegisvault-vek-wrap","u":"<user_uuid>","v":1,"kv":1}
  ```
- **Vault Item AAD:**
  ```json
  {"purpose":"aegisvault-item","u":"<user_uuid>","i":"<item_uuid>","v":1}
  ```

During decryption, the browser reconstructs the AAD from the authenticated user ID, the item's UUID, and `encryption_version`. Any modification to `user_id`, `item_id`, `encryption_version`, `nonce`, or `ciphertext` causes Poly1305 tag verification to fail deterministically.

### 3.2 Master-Password Rotation Without Re-Encrypting Items

When a user rotates their Vault Master Password:
1. The browser verifies the current Master Password by unwrapping the 256-bit `VEK`.
2. The browser generates a new 16-byte `kdf_salt` and a new 24-byte `vek_nonce`.
3. A new 256-bit wrapping key is derived via Argon2id from the new Master Password and new salt.
4. The existing 256-bit `VEK` is encrypted under the new wrapping key and sent to `PUT /api/vault/settings/master-password`.
5. Temporary buffers (`wrappingKey`, old `unwrappedVek`) are zeroed via `zeroBuffers`.
6. Because the underlying `VEK` has not changed, existing `vault_items` ciphertexts remain valid without expensive bulk re-encryption.
