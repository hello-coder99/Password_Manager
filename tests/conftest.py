"""Pytest fixtures for backend unit, integration, and security test suites."""

import base64
import os
import uuid
import pytest
import fakeredis

from app import create_app
from app.extensions import db as _db


@pytest.fixture()
def app():
    """Create an isolated Flask application configured for testing."""
    fake_redis = fakeredis.FakeStrictRedis()
    test_app = create_app(
        "testing",
        config_overrides={
            "SESSION_REDIS": fake_redis,
            "WTF_CSRF_ENABLED": True,
            "RATELIMIT_ENABLED": True,
            "MAX_CONTENT_LENGTH": 32 * 1024,  # 32 KB limit for fast payload limit tests
        },
    )
    with test_app.app_context():
        try:
            from app.extensions import limiter
            limiter.reset()
        except Exception:
            pass
        _db.create_all()

    yield test_app

    with test_app.app_context():
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def client(app):
    """Create a Flask test client with cookie persistence."""
    return app.test_client()


def fetch_csrf_token(client) -> str:
    """Helper to retrieve a valid CSRF token bound to the test client's session."""
    res = client.get("/api/csrf-token")
    assert res.status_code == 200
    data = res.get_json()
    return data["csrf_token"]


def make_sample_vault_setup_payload() -> dict:
    """Construct a valid synthetic encrypted VEK setup payload for backend tests."""
    return {
        "kdf_algorithm": "argon2id13",
        "kdf_version": 1,
        "kdf_salt": base64.b64encode(os.urandom(16)).decode("ascii"),
        "kdf_params": {
            "opslimit": 3,
            "memlimit": 67108864,  # 64 MiB
        },
        "encrypted_vek": base64.b64encode(os.urandom(48)).decode("ascii"),
        "vek_nonce": base64.b64encode(os.urandom(24)).decode("ascii"),
        "encryption_version": 1,
        "inactivity_timeout_minutes": 5,
    }


def make_sample_encrypted_item_payload(item_id: str | None = None) -> dict:
    """Construct a valid synthetic encrypted vault item payload."""
    payload = {
        "ciphertext": base64.b64encode(os.urandom(128)).decode("ascii"),
        "nonce": base64.b64encode(os.urandom(24)).decode("ascii"),
        "encryption_version": 1,
    }
    if item_id:
        payload["id"] = item_id
    else:
        payload["id"] = str(uuid.uuid4())
    return payload
