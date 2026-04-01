"""Main Sigil server class for agent identity management."""

from __future__ import annotations

import base64
import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sigil.auth import (
    TokenPayload,
    generate_challenge,
    generate_token,
    hash_token,
    issue_token,
    verify_token,
)
from sigil.builder import Builder, create_builder
from sigil.types import Agent, Challenge, EnrollmentToken, StorageAdapter


class SigilError(Exception):
    """Application-level error with a machine-readable code and HTTP status."""

    def __init__(self, message: str, code: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


@dataclass
class SigilConfig:
    """Configuration for the Sigil server."""

    builder: str
    platforms: list[str]
    jwt_secret: str
    storage: StorageAdapter
    challenge_ttl: int = 300  # seconds
    session_ttl: int = 3600  # seconds
    enrollment_ttl: int = 600  # seconds
    max_key_age: str | None = None


@dataclass
class CreateAgentResult:
    agent_id: str
    enrollment_token: str


@dataclass
class EnrollResult:
    token: str


@dataclass
class ChallengeResult:
    challenge: str


@dataclass
class VerifyResult:
    token: str


class Sigil:
    """Core Sigil server for managing agent identities.

    Provides methods for agent lifecycle management: creation, enrollment,
    challenge-response authentication, key rotation, and revocation.
    """

    def __init__(self, config: SigilConfig) -> None:
        self.config = config
        self.storage = config.storage
        self.builder: Builder = create_builder(config.builder)

    async def create_agent(
        self,
        name: str,
        external_user_id: str,
    ) -> CreateAgentResult:
        """Create a new agent and return its ID with an enrollment token.

        The agent starts in 'pending_enrollment' status. The returned
        enrollment token must be used to complete enrollment within
        the configured enrollment_ttl.
        """
        agent_id = str(uuid.uuid4())

        agent = Agent(
            id=agent_id,
            name=name,
            external_user_id=external_user_id,
        )
        await self.storage.create_agent(agent)

        # Generate enrollment token
        raw_token = generate_token()
        token_hash_value = hash_token(raw_token)

        enrollment_token = EnrollmentToken(
            token_hash=token_hash_value,
            agent_id=agent_id,
            expires_at=datetime.utcnow() + timedelta(seconds=self.config.enrollment_ttl),
        )
        await self.storage.create_enrollment_token(enrollment_token)

        return CreateAgentResult(
            agent_id=agent_id,
            enrollment_token=raw_token,
        )

    async def enroll(
        self,
        token: str,
        public_key: bytes,
        platform: str,
    ) -> EnrollResult:
        """Complete agent enrollment using an enrollment token.

        Validates the token, stores the agent's public key, and transitions
        the agent to 'active' status. Returns a signed JWT session token.
        """
        token_hash_value = hash_token(token)

        enrollment = await self.storage.validate_enrollment_token(token_hash_value)
        if not enrollment:
            raise SigilError(
                "Invalid or expired enrollment token",
                code="INVALID_ENROLLMENT_TOKEN",
                status_code=401,
            )

        if platform not in self.config.platforms:
            raise SigilError(
                f"Unsupported platform: {platform}",
                code="UNSUPPORTED_PLATFORM",
                status_code=400,
            )

        agent = await self.storage.get_agent(enrollment.agent_id)
        if not agent:
            raise SigilError(
                "Agent not found",
                code="AGENT_NOT_FOUND",
                status_code=404,
            )

        if agent.status != "pending_enrollment":
            raise SigilError(
                "Agent is not pending enrollment",
                code="INVALID_AGENT_STATUS",
                status_code=400,
            )

        # Compute key fingerprint
        fingerprint = hashlib.sha256(public_key).hexdigest()

        now = datetime.utcnow()
        key_expires_at = None
        if self.config.max_key_age:
            key_expires_at = now + _parse_duration(self.config.max_key_age)

        await self.storage.update_agent_status(
            enrollment.agent_id,
            "active",
            public_key=public_key,
            key_fingerprint=fingerprint,
            platform=platform,
            enrolled_at=now,
            last_auth_at=now,
            key_expires_at=key_expires_at,
        )

        # Burn the enrollment token so it cannot be reused
        await self.storage.burn_enrollment_token(token_hash_value)

        # Issue JWT
        jwt_token = issue_token(
            self.config.jwt_secret,
            TokenPayload(
                agent_id=enrollment.agent_id,
                user_id=agent.external_user_id,
                fingerprint=fingerprint,
            ),
            ttl_seconds=self.config.session_ttl,
        )

        return EnrollResult(token=jwt_token)

    async def challenge(self, agent_id: str) -> ChallengeResult:
        """Issue an authentication challenge for an active agent.

        The challenge must be signed by the agent's private key and
        returned via the verify() method.
        """
        agent = await self.storage.get_agent(agent_id)
        if not agent:
            raise SigilError(
                "Agent not found",
                code="AGENT_NOT_FOUND",
                status_code=404,
            )

        if agent.status != "active":
            raise SigilError(
                "Agent is not active",
                code="AGENT_NOT_ACTIVE",
                status_code=403,
            )

        challenge_str = generate_challenge()

        ch = Challenge(
            challenge=challenge_str,
            agent_id=agent_id,
            expires_at=datetime.utcnow() + timedelta(seconds=self.config.challenge_ttl),
        )
        await self.storage.create_challenge(ch)

        return ChallengeResult(challenge=challenge_str)

    async def verify(
        self,
        agent_id: str,
        challenge_str: str,
        signature: bytes,
    ) -> VerifyResult:
        """Verify a signed challenge and issue a JWT session token.

        Validates the challenge, verifies the Ed25519 signature against
        the agent's stored public key, and returns a fresh JWT.
        """
        ch = await self.storage.validate_challenge(challenge_str)
        if not ch:
            raise SigilError(
                "Invalid or expired challenge",
                code="INVALID_CHALLENGE",
                status_code=401,
            )

        if ch.agent_id != agent_id:
            raise SigilError(
                "Challenge does not belong to this agent",
                code="CHALLENGE_MISMATCH",
                status_code=401,
            )

        agent = await self.storage.get_agent(agent_id)
        if not agent or agent.status != "active":
            raise SigilError(
                "Agent not found or not active",
                code="AGENT_NOT_ACTIVE",
                status_code=403,
            )

        if not agent.public_key:
            raise SigilError(
                "Agent has no public key",
                code="NO_PUBLIC_KEY",
                status_code=500,
            )

        # Verify Ed25519 signature
        try:
            pub = Ed25519PublicKey.from_public_bytes(agent.public_key)
            pub.verify(signature, challenge_str.encode())
        except (InvalidSignature, ValueError) as e:
            raise SigilError(
                "Invalid signature",
                code="INVALID_SIGNATURE",
                status_code=401,
            ) from e

        # Burn the challenge
        await self.storage.burn_challenge(challenge_str)

        # Update last auth time
        now = datetime.utcnow()
        await self.storage.update_agent_status(
            agent_id,
            "active",
            last_auth_at=now,
        )

        # Issue JWT
        jwt_token = issue_token(
            self.config.jwt_secret,
            TokenPayload(
                agent_id=agent_id,
                user_id=agent.external_user_id,
                fingerprint=agent.key_fingerprint or "",
            ),
            ttl_seconds=self.config.session_ttl,
        )

        return VerifyResult(token=jwt_token)

    async def rotate(
        self,
        agent_id: str,
        new_public_key: bytes,
        challenge_str: str,
        signature: bytes,
    ) -> EnrollResult:
        """Rotate an agent's key pair.

        Requires a valid signed challenge to authorize the rotation.
        The agent's public key is replaced with the new one.
        """
        # First verify the challenge with the current key
        ch = await self.storage.validate_challenge(challenge_str)
        if not ch or ch.agent_id != agent_id:
            raise SigilError(
                "Invalid or expired challenge",
                code="INVALID_CHALLENGE",
                status_code=401,
            )

        agent = await self.storage.get_agent(agent_id)
        if not agent or agent.status != "active":
            raise SigilError(
                "Agent not found or not active",
                code="AGENT_NOT_ACTIVE",
                status_code=403,
            )

        if not agent.public_key:
            raise SigilError(
                "Agent has no public key",
                code="NO_PUBLIC_KEY",
                status_code=500,
            )

        # Verify signature with current key
        try:
            pub = Ed25519PublicKey.from_public_bytes(agent.public_key)
            pub.verify(signature, challenge_str.encode())
        except (InvalidSignature, ValueError) as e:
            raise SigilError(
                "Invalid signature",
                code="INVALID_SIGNATURE",
                status_code=401,
            ) from e

        await self.storage.burn_challenge(challenge_str)

        # Update to new key
        fingerprint = hashlib.sha256(new_public_key).hexdigest()
        now = datetime.utcnow()
        key_expires_at = None
        if self.config.max_key_age:
            key_expires_at = now + _parse_duration(self.config.max_key_age)

        await self.storage.update_agent_status(
            agent_id,
            "active",
            public_key=new_public_key,
            key_fingerprint=fingerprint,
            last_auth_at=now,
            key_expires_at=key_expires_at,
        )

        jwt_token = issue_token(
            self.config.jwt_secret,
            TokenPayload(
                agent_id=agent_id,
                user_id=agent.external_user_id,
                fingerprint=fingerprint,
            ),
            ttl_seconds=self.config.session_ttl,
        )

        return EnrollResult(token=jwt_token)

    async def revoke(self, agent_id: str) -> None:
        """Revoke an agent, making it unable to authenticate."""
        agent = await self.storage.get_agent(agent_id)
        if not agent:
            raise SigilError(
                "Agent not found",
                code="AGENT_NOT_FOUND",
                status_code=404,
            )

        await self.storage.update_agent_status(agent_id, "revoked")

    async def re_enroll(self, agent_id: str) -> CreateAgentResult:
        """Re-enroll a revoked agent by generating a new enrollment token.

        Transitions the agent back to 'pending_enrollment' and returns
        a fresh enrollment token.
        """
        agent = await self.storage.get_agent(agent_id)
        if not agent:
            raise SigilError(
                "Agent not found",
                code="AGENT_NOT_FOUND",
                status_code=404,
            )

        if agent.status != "revoked":
            raise SigilError(
                "Agent must be revoked to re-enroll",
                code="INVALID_AGENT_STATUS",
                status_code=400,
            )

        await self.storage.update_agent_status(
            agent_id,
            "pending_enrollment",
            public_key=None,
            key_fingerprint=None,
        )

        raw_token = generate_token()
        token_hash_value = hash_token(raw_token)

        enrollment_token = EnrollmentToken(
            token_hash=token_hash_value,
            agent_id=agent_id,
            expires_at=datetime.utcnow() + timedelta(seconds=self.config.enrollment_ttl),
        )
        await self.storage.create_enrollment_token(enrollment_token)

        return CreateAgentResult(
            agent_id=agent_id,
            enrollment_token=raw_token,
        )

    async def verify_jwt(self, token: str) -> dict[str, Any]:
        """Verify a JWT session token and return its decoded payload.

        Raises SigilError if the token is invalid or expired.
        """
        try:
            return verify_token(self.config.jwt_secret, token)
        except Exception as e:
            raise SigilError(
                "Invalid or expired token",
                code="INVALID_TOKEN",
                status_code=401,
            ) from e


def _parse_duration(duration: str) -> timedelta:
    """Parse a duration string like '30d', '24h', '90m' to timedelta."""
    if not duration:
        raise ValueError("Empty duration string")

    unit = duration[-1].lower()
    value = int(duration[:-1])

    if unit == "d":
        return timedelta(days=value)
    elif unit == "h":
        return timedelta(hours=value)
    elif unit == "m":
        return timedelta(minutes=value)
    elif unit == "s":
        return timedelta(seconds=value)
    else:
        raise ValueError(f"Unknown duration unit: {unit}")
