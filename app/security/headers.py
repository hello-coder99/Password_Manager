"""HTTP security headers and log sanitization filters."""

import logging
import re
from flask import Flask, Response, request

# Patterns that must never appear in application logs
_SENSITIVE_KEY_PATTERN = re.compile(
    r'("(?:password|login_password|master_password|ciphertext|encrypted_vek|'
    r'vek_nonce|nonce|kdf_salt|csrf_token|secret_key|session|cookie)"\s*:\s*")([^"]*)(")',
    re.IGNORECASE,
)
_HEADER_TOKEN_PATTERN = re.compile(
    r"(X-CSRF-Token|Cookie|Set-Cookie|Authorization)\s*[:=]\s*([^\r\n,;]+)",
    re.IGNORECASE,
)


class SensitiveDataLogFilter(logging.Filter):
    """Redacts passwords, tokens, cookies, and encrypted payloads from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self._scrub(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: self._scrub(str(v)) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    self._scrub(str(a)) if isinstance(a, str) else a
                    for a in record.args
                )
        return True

    @staticmethod
    def _scrub(value: str) -> str:
        scrubbed = _SENSITIVE_KEY_PATTERN.sub(r"\1[REDACTED]\3", value)
        scrubbed = _HEADER_TOKEN_PATTERN.sub(r"\1: [REDACTED]", scrubbed)
        return scrubbed


def configure_security_headers(app: Flask) -> None:
    """Register response hooks that attach strict HTTP security headers."""
    log_filter = SensitiveDataLogFilter()
    app.logger.addFilter(log_filter)
    logging.getLogger("werkzeug").addFilter(log_filter)

    @app.after_request
    def apply_security_headers(response: Response) -> Response:
        frame_ancestors = app.config.get("CSP_FRAME_ANCESTORS", "'none'")
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'wasm-unsafe-eval'; "
            "style-src 'self' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            f"frame-ancestors {frame_ancestors};"
        )
        response.headers.setdefault("Content-Security-Policy", csp)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault(
            "Referrer-Policy", "strict-origin-when-cross-origin"
        )
        if frame_ancestors == "'none'":
            response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=()",
        )

        # Prevent caching of API responses containing session or vault metadata
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = (
                "no-store, no-cache, must-revalidate, max-age=0"
            )
            response.headers["Pragma"] = "no-cache"

        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )

        return response
