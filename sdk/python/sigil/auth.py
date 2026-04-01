"""Authentication utilities: JWT tokens, enrollment tokens, and challenges."""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Any

import jwt


@dataclass
class TokenPayload:
    agent_id: str
    user_id: str
    fingerprint: str


def issue_token(
    secret: str,
    payload: TokenPayload,
    ttl_seconds: int = 3600,
) -> str:
    """Create a signed JWT with the given payload and TTL."""
    claims: dict[str, Any] = {
        "agent_id": payload.agent_id,
        "user_id": payload.user_id,
        "fingerprint": payload.fingerprint,
        "exp": int(time.time()) + ttl_seconds,
        "iat": int(time.time()),
    }
    return jwt.encode(claims, secret, algorithm="HS256")


def verify_token(secret: str, token: str) -> dict[str, Any]:
    """Verify and decode a JWT. Raises jwt.InvalidTokenError on failure."""
    return jwt.decode(token, secret, algorithms=["HS256"])


def generate_token() -> str:
    """Generate a random 32-byte hex enrollment token."""
    return secrets.token_hex(32)


def hash_token(token: str) -> str:
    """Return the SHA-256 hex digest of a token string."""
    return hashlib.sha256(token.encode()).hexdigest()


def generate_challenge() -> str:
    """Generate a random 32-byte challenge, base64 encoded."""
    return base64.b64encode(secrets.token_bytes(32)).decode()
