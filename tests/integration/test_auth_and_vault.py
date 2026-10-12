"""Integration tests for authentication, vault setup, CRUD, master-password rotation, and backups."""

import base64
import os

from tests.conftest import (
    fetch_csrf_token,
    make_sample_encrypted_item_payload,
    make_sample_vault_setup_payload,
)


def test_health_and_csrf_endpoints(client):
    """Verify /api/health and /api/csrf-token return expected status and security headers."""
    health_res = client.get("/api/health")
    assert health_res.status_code == 200
    health_json = health_res.get_json()
    assert health_json["status"] == "healthy"
    assert health_json["database"] == "connected"
    assert health_json["redis"] == "connected"
    assert "Content-Security-Policy" in health_res.headers
    assert "'wasm-unsafe-eval'" in health_res.headers["Content-Security-Policy"]
    assert health_res.headers.get("X-Content-Type-Options") == "nosniff"
    assert (
        health_res.headers.get("Referrer-Policy")
        == "strict-origin-when-cross-origin"
    )

    csrf_token = fetch_csrf_token(client)
    assert isinstance(csrf_token, str) and len(csrf_token) > 20


def test_user_registration_login_me_and_logout_lifecycle(client):
    """Test complete user registration, session validation, logout, and re-login."""
    csrf_token = fetch_csrf_token(client)

    reg_res = client.post(
        "/api/auth/register",
        json={
            "email": "  Student.Analyst@University.edu ",
            "login_password": "AccountLoginPassword#2026!",
        },
        headers={"X-CSRF-Token": csrf_token},
    )
    assert reg_res.status_code == 201
    reg_data = reg_res.get_json()
    assert reg_data["user"]["email"] == "student.analyst@university.edu"
    assert reg_data["user"]["has_vault_setup"] is False
    assert "login_password_hash" not in reg_data["user"]
    csrf_token = reg_data["csrf_token"]

    # Check Set-Cookie attributes
    set_cookie = reg_res.headers.get("Set-Cookie", "")
    assert "HttpOnly" in set_cookie
    assert "SameSite=Lax" in set_cookie

    # Verify /api/auth/me works with active session
    me_res = client.get("/api/auth/me")
    assert me_res.status_code == 200
    assert me_res.get_json()["user"]["email"] == "student.analyst@university.edu"

    # Duplicate registration must be rejected
    dup_res = client.post(
        "/api/auth/register",
        json={
            "email": "student.analyst@university.edu",
            "login_password": "AnotherPassword#2026!",
        },
        headers={"X-CSRF-Token": csrf_token},
    )
    assert dup_res.status_code == 409

    # Logout invalidates session
    logout_res = client.post(
        "/api/auth/logout",
        json={},
        headers={"X-CSRF-Token": csrf_token},
    )
    assert logout_res.status_code == 200
    assert client.get("/api/auth/me").status_code == 401

    # Re-login succeeds
    fresh_csrf = fetch_csrf_token(client)
    login_res = client.post(
        "/api/auth/login",
        json={
            "email": "STUDENT.ANALYST@university.edu",
            "login_password": "AccountLoginPassword#2026!",
        },
        headers={"X-CSRF-Token": fresh_csrf},
    )
    assert login_res.status_code == 200
    assert client.get("/api/auth/me").status_code == 200


def test_vault_setup_crud_master_password_rotation_and_backup_restore(client):
    """Test full encrypted vault workflow including setup, CRUD, VEK re-wrap, and backup import."""
    csrf_token = fetch_csrf_token(client)
    reg_res = client.post(
        "/api/auth/register",
        json={
            "email": "vaultuser@example.edu",
            "login_password": "StrongAccountPassword!2026",
        },
        headers={"X-CSRF-Token": csrf_token},
    )
    csrf_token = reg_res.get_json()["csrf_token"]

    # Vault settings should return 404 before setup
    assert client.get("/api/vault/settings").status_code == 404

    # Initialize vault settings
    setup_payload = make_sample_vault_setup_payload()
    setup_res = client.post(
        "/api/vault/setup",
        json=setup_payload,
        headers={"X-CSRF-Token": csrf_token},
    )
    assert setup_res.status_code == 201
    assert setup_res.get_json()["vault_settings"]["encrypted_vek"] == setup_payload["encrypted_vek"]

    # Duplicate setup must return 409
    dup_setup = client.post(
        "/api/vault/setup",
        json=setup_payload,
        headers={"X-CSRF-Token": csrf_token},
    )
    assert dup_setup.status_code == 409

    # Create two encrypted vault items
    item1_payload = make_sample_encrypted_item_payload()
    item2_payload = make_sample_encrypted_item_payload()

    create1 = client.post(
        "/api/vault/items",
        json=item1_payload,
        headers={"X-CSRF-Token": csrf_token},
    )
    assert create1.status_code == 201
    created_item1 = create1.get_json()["item"]
    assert created_item1["id"] == item1_payload["id"]
    assert created_item1["ciphertext"] == item1_payload["ciphertext"]

    create2 = client.post(
        "/api/vault/items",
        json=item2_payload,
        headers={"X-CSRF-Token": csrf_token},
    )
    assert create2.status_code == 201

    # List items
    list_res = client.get("/api/vault/items")
    assert list_res.status_code == 200
    assert list_res.get_json()["count"] == 2

    # Update item 1 ciphertext & nonce
    updated_ciphertext = base64.b64encode(os.urandom(160)).decode("ascii")
    updated_nonce = base64.b64encode(os.urandom(24)).decode("ascii")
    update_res = client.put(
        f"/api/vault/items/{item1_payload['id']}",
        json={
            "ciphertext": updated_ciphertext,
            "nonce": updated_nonce,
            "encryption_version": 1,
        },
        headers={"X-CSRF-Token": csrf_token},
    )
    assert update_res.status_code == 200
    assert update_res.get_json()["item"]["ciphertext"] == updated_ciphertext

    # Rotate master password (updates wrapped VEK and salt/nonce without changing item ciphertexts)
    new_envelope = make_sample_vault_setup_payload()
    mp_res = client.put(
        "/api/vault/settings/master-password",
        json=new_envelope,
        headers={"X-CSRF-Token": csrf_token},
    )
    assert mp_res.status_code == 200
    assert (
        mp_res.get_json()["vault_settings"]["encrypted_vek"]
        == new_envelope["encrypted_vek"]
    )

    # Verify item 1 ciphertext was NOT altered by master password change
    items_after_mp = client.get("/api/vault/items").get_json()["items"]
    item1_after = next(i for i in items_after_mp if i["id"] == item1_payload["id"])
    assert item1_after["ciphertext"] == updated_ciphertext

    # Export encrypted backup before deleting item 2
    export_res = client.get("/api/vault/export")
    assert export_res.status_code == 200
    backup_bundle = export_res.get_json()
    assert backup_bundle["backup_format"] == "aegisvault-encrypted-backup"
    assert backup_bundle["backup_version"] == 1
    assert len(backup_bundle["items"]) == 2

    # Delete item 2
    del_res = client.delete(
        f"/api/vault/items/{item2_payload['id']}",
        headers={"X-CSRF-Token": csrf_token},
    )
    assert del_res.status_code == 200
    assert client.get("/api/vault/items").get_json()["count"] == 1

    # Restore backup via /api/vault/import
    import_payload = {
        "backup_format": backup_bundle["backup_format"],
        "backup_version": backup_bundle["backup_version"],
        "exported_at": backup_bundle["exported_at"],
        "vault_settings": backup_bundle["vault_settings"],
        "items": backup_bundle["items"],
    }
    import_res = client.post(
        "/api/vault/import",
        json=import_payload,
        headers={"X-CSRF-Token": csrf_token},
    )
    assert import_res.status_code == 200
    assert import_res.get_json()["imported_count"] == 2
    assert client.get("/api/vault/items").get_json()["count"] == 2
