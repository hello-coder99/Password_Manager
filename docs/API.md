# AegisVault REST API Reference

All API routes are prefixed with `/api`, accept and return `application/json`, and include `Cache-Control: no-store`.

## Authentication & CSRF Conventions

- **Session Cookie:** `aegisvault_sid` (`HttpOnly`, `SameSite=Lax`, `Secure` in production).
- **CSRF Protection:** All state-changing methods (`POST`, `PUT`, `DELETE`) require the `X-CSRF-Token` request header containing a valid token obtained from `GET /api/csrf-token` (or rotated in `/api/auth/*` responses).
- **Maximum Request Size:** `524,288` bytes (512 KB) default; oversized requests return `413 PAYLOAD_TOO_LARGE`.

---

## 1. System & Security Bootstrap

### `GET /api/health`
Health check endpoint for Docker Compose and monitoring probes.
- **Authentication:** None
- **Rate Limit:** Exempt
- **Responses:**
  - `200 OK`:
    ```json
    {
      "status": "healthy",
      "database": "connected",
      "redis": "connected"
    }
    ```
  - `503 Service Unavailable`: Returned when MariaDB or Redis is unreachable.

### `GET /api/csrf-token`
Issues a signed CSRF token bound to the caller's server-side session.
- **Authentication:** None
- **Rate Limit:** `60 per minute`
- **Response (`200 OK`):**
  ```json
  {
    "csrf_token": "ImI1Z..."
  }
  ```

---

## 2. Authentication Endpoints

### `POST /api/auth/register`
Registers a new user account with a server-side Argon2id hash of `login_password` and establishes an authenticated session.
- **Authentication:** None
- **CSRF Header Required:** Yes (`X-CSRF-Token`)
- **Rate Limit:** `10 per minute`
- **Request Payload:**
  ```json
  {
    "email": "analyst@university.edu",
    "login_password": "AccountLoginPassword#2026!"
  }
  ```
- **Responses:**
  - `201 Created`:
    ```json
    {
      "message": "Account registered successfully.",
      "user": {
        "id": "d064461f-ad54-42b3-a3ea-ea7da7299dbf",
        "email": "analyst@university.edu",
        "is_active": true,
        "has_vault_setup": false,
        "created_at": "2026-10-11T22:50:00+00:00"
      },
      "csrf_token": "ImNewRotatedToken..."
    }
    ```
  - `409 Conflict` (`ACCOUNT_CONFLICT`): Email cannot be registered.
  - `422 Unprocessable Entity` (`VALIDATION_ERROR`): Invalid email or password length (`<10` or `>256` chars).

### `POST /api/auth/login`
Authenticates an existing user and rotates the server-side session and CSRF token.
- **Authentication:** None
- **CSRF Header Required:** Yes (`X-CSRF-Token`)
- **Rate Limit:** `10 per minute`
- **Request Payload:**
  ```json
  {
    "email": "analyst@university.edu",
    "login_password": "AccountLoginPassword#2026!"
  }
  ```
- **Responses:**
  - `200 OK`: Returns `{ "message": "Authenticated successfully.", "user": {...}, "csrf_token": "..." }`.
  - `401 Unauthorized` (`INVALID_CREDENTIALS`): Generic error for unknown email, wrong password, or disabled account.
  - `429 Too Many Requests` (`RATE_LIMITED`): Exceeded 10 attempts per minute.

### `POST /api/auth/logout`
Invalidates the current Redis-backed server session.
- **Authentication:** Required (`@login_required`)
- **CSRF Header Required:** Yes (`X-CSRF-Token`)
- **Rate Limit:** `30 per minute`
- **Request Payload:** `{}`
- **Response (`200 OK`):**
  ```json
  {
    "message": "Logged out successfully.",
    "csrf_token": "ImFreshAnonymousToken..."
  }
  ```

### `GET /api/auth/me`
Returns the currently authenticated user's profile and whether their encrypted vault has been initialized.
- **Authentication:** Required (`@login_required`)
- **Rate Limit:** `60 per minute`
- **Response (`200 OK`):**
  ```json
  {
    "user": {
      "id": "d064461f-ad54-42b3-a3ea-ea7da7299dbf",
      "email": "analyst@university.edu",
      "is_active": true,
      "has_vault_setup": true,
      "created_at": "2026-10-11T22:50:00+00:00"
    }
  }
  ```

---

## 3. Encrypted Vault Endpoints

### `GET /api/vault/settings`
Returns the authenticated user's KDF parameters and wrapped Vault Encryption Key (`encrypted_vek`).
- **Authentication:** Required
- **Rate Limit:** `60 per minute`
- **Responses:**
  - `200 OK`:
    ```json
    {
      "vault_settings": {
        "user_id": "d064461f-ad54-42b3-a3ea-ea7da7299dbf",
        "kdf_algorithm": "argon2id13",
        "kdf_version": 1,
        "kdf_salt": "<16-byte-base64>",
        "kdf_params": {
          "opslimit": 3,
          "memlimit": 67108864
        },
        "encrypted_vek": "<48-byte-base64>",
        "vek_nonce": "<24-byte-base64>",
        "encryption_version": 1,
        "inactivity_timeout_minutes": 5,
        "updated_at": "2026-10-11T22:55:00+00:00"
      }
    }
    ```
  - `404 Not Found` (`VAULT_NOT_INITIALIZED`): Vault has not been initialized yet.

### `POST /api/vault/setup`
Initializes the user's encrypted vault settings with a browser-generated wrapped VEK.
- **Authentication:** Required
- **CSRF Header Required:** Yes
- **Rate Limit:** `15 per minute`
- **Request Payload:**
  ```json
  {
    "kdf_algorithm": "argon2id13",
    "kdf_version": 1,
    "kdf_salt": "<16-byte-base64>",
    "kdf_params": {
      "opslimit": 3,
      "memlimit": 67108864
    },
    "encrypted_vek": "<48-byte-base64>",
    "vek_nonce": "<24-byte-base64>",
    "encryption_version": 1,
    "inactivity_timeout_minutes": 5
  }
  ```
- **Responses:**
  - `201 Created`: Returns `{ "message": "Encrypted vault initialized.", "vault_settings": {...} }`.
  - `409 Conflict` (`VAULT_ALREADY_INITIALIZED`): Vault already initialized.
  - `422 Unprocessable Entity`: Invalid byte lengths or out-of-bounds KDF parameters.

### `PUT /api/vault/settings/master-password`
Updates the wrapped VEK, KDF salt, and wrapping nonce after the browser re-wraps the VEK under a new Master Password.
- **Authentication:** Required
- **CSRF Header Required:** Yes
- **Rate Limit:** `10 per minute`
- **Request Payload:** Same schema as `POST /api/vault/setup`.
- **Response (`200 OK`):** Returns `{ "message": "Master password envelope updated.", "vault_settings": {...} }`.

### `GET /api/vault/items`
Lists all encrypted vault items owned by the authenticated user.
- **Authentication:** Required
- **Rate Limit:** `60 per minute`
- **Response (`200 OK`):**
  ```json
  {
    "count": 1,
    "items": [
      {
        "id": "7f112233-4455-4666-8777-8899aabbccdd",
        "user_id": "d064461f-ad54-42b3-a3ea-ea7da7299dbf",
        "ciphertext": "<base64-xchacha20poly1305-payload>",
        "nonce": "<24-byte-base64>",
        "encryption_version": 1,
        "created_at": "2026-10-11T22:56:00+00:00",
        "updated_at": "2026-10-11T22:56:00+00:00"
      }
    ]
  }
  ```

### `POST /api/vault/items`
Stores a new client-side encrypted vault item.
- **Authentication:** Required
- **CSRF Header Required:** Yes
- **Rate Limit:** `60 per minute`
- **Request Payload:**
  ```json
  {
    "id": "7f112233-4455-4666-8777-8899aabbccdd",
    "ciphertext": "<base64-xchacha20poly1305-payload>",
    "nonce": "<24-byte-base64>",
    "encryption_version": 1
  }
  ```
- **Response (`201 Created`):** Returns `{ "message": "Encrypted item stored.", "item": {...} }`.

### `PUT /api/vault/items/<item_id>`
Updates the ciphertext and nonce of an existing vault item owned by the authenticated user.
- **Authentication:** Required (strictly enforces item ownership)
- **CSRF Header Required:** Yes
- **Rate Limit:** `60 per minute`
- **Request Payload:**
  ```json
  {
    "ciphertext": "<base64-xchacha20poly1305-payload>",
    "nonce": "<24-byte-base64>",
    "encryption_version": 1
  }
  ```
- **Responses:**
  - `200 OK`: Returns `{ "message": "Encrypted item updated.", "item": {...} }`.
  - `404 Not Found` (`ITEM_NOT_FOUND`): Item does not exist or belongs to another user.

### `DELETE /api/vault/items/<item_id>`
Permanently deletes an encrypted vault item owned by the authenticated user.
- **Authentication:** Required (strictly enforces item ownership)
- **CSRF Header Required:** Yes
- **Rate Limit:** `60 per minute`
- **Responses:**
  - `200 OK`: `{ "message": "Encrypted item deleted.", "deleted_id": "<uuid>" }`
  - `404 Not Found` (`ITEM_NOT_FOUND`): Item does not exist or belongs to another user.

### `GET /api/vault/export`
Exports a complete encrypted backup archive containing the user's `vault_settings` and encrypted `items`.
- **Authentication:** Required
- **Rate Limit:** `15 per minute`
- **Response (`200 OK`):**
  ```json
  {
    "backup_format": "aegisvault-encrypted-backup",
    "backup_version": 1,
    "exported_at": "2026-10-11T23:00:00+00:00",
    "user_id": "d064461f-ad54-42b3-a3ea-ea7da7299dbf",
    "vault_settings": { "...": "..." },
    "items": [ { "...": "..." } ]
  }
  ```

### `POST /api/vault/import`
Validates and atomically restores an encrypted backup archive into the user's vault.
- **Authentication:** Required
- **CSRF Header Required:** Yes
- **Rate Limit:** `10 per minute`
- **Request Payload:** The JSON object produced by `GET /api/vault/export`.
- **Responses:**
  - `200 OK`: `{ "message": "Encrypted backup restored successfully.", "imported_count": 1, "vault_settings": {...} }`
  - `409 Conflict` (`CROSS_USER_ITEM_CONFLICT`): Item UUID collides with another user's record.
  - `422 Unprocessable Entity`: Invalid backup format, version, or cryptographic byte lengths.
