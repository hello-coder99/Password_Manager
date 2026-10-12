"""Security test suite verifying CSRF, rate limiting, IDOR/cross-user isolation, Redis outage fail-closed behavior, payload validation, and log sanitization."""

import base64
import logging
import os
from redis.exceptions import ConnectionError as RedisConnectionError

from app.security.headers import SensitiveDataLogFilter
from tests.conftest import (
    fetch_csrf_token,
    make_sample_encrypted_item_payload,
    make_sample_vault_setup_payload,
)


def test_csrf_protection_rejects_missing_or_invalid_tokens(client):
    """Ensure all state-changing endpoints reject requests without a valid CSRF token."""
    # Attempt registration without X-CSRF-Token header
    res_missing = client.post(
        "/api/auth/register",
        json={
            "email": "attacker@example.edu",
            "login_password": "ValidPasswordLength!123",
        },
    )
    assert res_missing.status_code == 400
    assert res_missing.get_json()["code"] == "CSRF_ERROR"

    # Attempt registration with forged X-CSRF-Token header
    res_forged = client.post(
        "/api/auth/register",
        json={
            "email": "attacker@example.edu",
            "login_password": "ValidPasswordLength!123",
        },
        headers={"X-CSRF-Token": "forged-invalid-csrf-token"},
    )
    assert res_forged.status_code == 400
    assert res_forged.get_json()["code"] == "CSRF_ERROR"


def test_cross_user_isolation_and_idor_prevention(app):
    """Ensure User B cannot read, update, delete, or import-overwrite User A's vault items."""
    client_a = app.test_client()
    client_b = app.test_client()

    # Register & setup User A
    csrf_a = fetch_csrf_token(client_a)
    reg_a = client_a.post(
        "/api/auth/register",
        json={
            "email": "user_a@example.edu",
            "login_password": "UserALoginPassword!123",
        },
        headers={"X-CSRF-Token": csrf_a},
    ).get_json()
    csrf_a = reg_a["csrf_token"]
    client_a.post(
        "/api/vault/setup",
        json=make_sample_vault_setup_payload(),
        headers={"X-CSRF-Token": csrf_a},
    )
    item_a = make_sample_encrypted_item_payload()
    client_a.post(
        "/api/vault/items",
        json=item_a,
        headers={"X-CSRF-Token": csrf_a},
    )

    # Register & setup User B
    csrf_b = fetch_csrf_token(client_b)
    reg_b = client_b.post(
        "/api/auth/register",
        json={
            "email": "user_b@example.edu",
            "login_password": "UserBLoginPassword!123",
        },
        headers={"X-CSRF-Token": csrf_b},
    ).get_json()
    csrf_b = reg_b["csrf_token"]
    client_b.post(
        "/api/vault/setup",
        json=make_sample_vault_setup_payload(),
        headers={"X-CSRF-Token": csrf_b},
    )

    # User B listing items must see 0 items
    list_b = client_b.get("/api/vault/items").get_json()
    assert list_b["count"] == 0

    # User B attempting to PUT User A's item ID must receive 404
    put_b = client_b.put(
        f"/api/vault/items/{item_a['id']}",
        json={
            "ciphertext": base64.b64encode(os.urandom(64)).decode("ascii"),
            "nonce": base64.b64encode(os.urandom(24)).decode("ascii"),
            "encryption_version": 1,
        },
        headers={"X-CSRF-Token": csrf_b},
    )
    assert put_b.status_code == 404

    # User B attempting to DELETE User A's item ID must receive 404
    del_b = client_b.delete(
        f"/api/vault/items/{item_a['id']}",
        headers={"X-CSRF-Token": csrf_b},
    )
    assert del_b.status_code == 404

    # User B attempting to import a backup containing User A's item UUID must be rejected
    import_b = client_b.post(
        "/api/vault/import",
        json={
            "backup_format": "aegisvault-encrypted-backup",
            "backup_version": 1,
            "vault_settings": make_sample_vault_setup_payload(),
            "items": [item_a],
        },
        headers={"X-CSRF-Token": csrf_b},
    )
    assert import_b.status_code == 409
    assert import_b.get_json()["code"] == "CROSS_USER_ITEM_CONFLICT"

    # Verify User A's item remains intact
    items_a = client_a.get("/api/vault/items").get_json()["items"]
    assert len(items_a) == 1
    assert items_a[0]["ciphertext"] == item_a["ciphertext"]


def test_rate_limiting_blocks_brute_force_login_attempts(client):
    """Verify login endpoint enforces Redis/Limiter rate limit (10 per minute)."""
    csrf_token = fetch_csrf_token(client)
    last_status = 200
    for _ in range(12):
        res = client.post(
            "/api/auth/login",
            json={
                "email": "victim@example.edu",
                "login_password": "WrongPasswordAttempt!1",
            },
            headers={"X-CSRF-Token": csrf_token},
        )
        last_status = res.status_code
        if last_status == 429:
            break

    assert last_status == 429
    assert res.get_json()["code"] == "RATE_LIMITED"


def test_strict_payload_validation_and_size_limits(client):
    """Ensure server rejects forbidden plaintext secrets, unbounded KDF params, and oversized bodies."""
    csrf_token = fetch_csrf_token(client)
    reg = client.post(
        "/api/auth/register",
        json={
            "email": "validator@example.edu",
            "login_password": "ValidatorStrongPassword!123",
        },
        headers={"X-CSRF-Token": csrf_token},
    ).get_json()
    csrf_token = reg["csrf_token"]

    # 1. Sending master_password to the server must be rejected
    bad_secret_payload = make_sample_vault_setup_payload()
    bad_secret_payload["master_password"] = "ShouldNeverBeSentToServer!"
    res_secret = client.post(
        "/api/vault/setup",
        json=bad_secret_payload,
        headers={"X-CSRF-Token": csrf_token},
    )
    assert res_secret.status_code == 422

    # 2. Excessive KDF memlimit (DoS attempt) must be rejected
    bad_kdf_payload = make_sample_vault_setup_payload()
    bad_kdf_payload["kdf_params"]["memlimit"] = 2 * 1024 * 1024 * 1024  # 2 GiB
    res_kdf = client.post(
        "/api/vault/setup",
        json=bad_kdf_payload,
        headers={"X-CSRF-Token": csrf_token},
    )
    assert res_kdf.status_code == 422

    # 3. Oversized payload (>32 KB test limit) must be rejected with 413
    oversized_body = "x" * (40 * 1024)
    res_large = client.post(
        "/api/vault/items",
        data=oversized_body,
        content_type="application/json",
        headers={"X-CSRF-Token": csrf_token},
    )
    assert res_large.status_code == 413
    assert res_large.get_json()["code"] == "PAYLOAD_TOO_LARGE"


def test_application_fails_closed_when_redis_is_unavailable(app):
    """Verify that if Redis raises ConnectionError, the app fails closed with 503 JSON."""

    class BrokenRedisClient:
        def get(self, *args, **kwargs):
            raise RedisConnectionError("Simulated Redis connection refusal")

        def setex(self, *args, **kwargs):
            raise RedisConnectionError("Simulated Redis connection refusal")

        def set(self, *args, **kwargs):
            raise RedisConnectionError("Simulated Redis connection refusal")

        def delete(self, *args, **kwargs):
            raise RedisConnectionError("Simulated Redis connection refusal")

        def ping(self, *args, **kwargs):
            raise RedisConnectionError("Simulated Redis connection refusal")

    broken_redis = BrokenRedisClient()
    app.config["SESSION_REDIS"] = broken_redis
    app.session_interface._inner.client = broken_redis

    broken_client = app.test_client()

    # Health endpoint reports 503 degraded without crashing
    health_res = broken_client.get("/api/health")
    assert health_res.status_code == 503
    assert health_res.get_json()["redis"] == "unavailable"

    # Protected/session endpoints fail closed with 503 REDIS_UNAVAILABLE
    me_res = broken_client.get("/api/auth/me")
    assert me_res.status_code == 503
    assert me_res.get_json()["code"] == "REDIS_UNAVAILABLE"


def test_sensitive_data_log_filter_redacts_secrets():
    """Verify SensitiveDataLogFilter scrubs passwords, tokens, and ciphertexts from logs."""
    log_filter = SensitiveDataLogFilter()
    record = logging.LogRecord(
        name="app",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg='Payload {"login_password": "MySecretPassword123", "ciphertext": "abc123xyz"} Header X-CSRF-Token: secret-csrf-999',
        args=(),
        exc_info=None,
    )
    log_filter.filter(record)
    assert "MySecretPassword123" not in record.msg
    assert "abc123xyz" not in record.msg
    assert "secret-csrf-999" not in record.msg
    assert "[REDACTED]" in record.msg
