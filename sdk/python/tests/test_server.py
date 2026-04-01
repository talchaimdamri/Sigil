"""Tests for the Sigil Python SDK: storage, auth, and server class."""

from __future__ import annotations

import time
from datetime import datetime, timedelta

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sigil.auth import (
    TokenPayload,
    generate_challenge,
    generate_token,
    hash_token,
    issue_token,
    verify_token,
)
from sigil.server import Sigil, SigilConfig, SigilError
from sigil.storage.sqlite import SQLiteStorage
from sigil.types import Agent, Challenge, EnrollmentToken


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def storage():
    """Create an in-memory SQLite storage, cleaned up after the test."""
    s = SQLiteStorage(":memory:")
    # Force table creation by accessing the db
    await s._get_db()
    yield s
    await s.cleanup()


@pytest.fixture
def ed25519_keypair():
    """Generate a fresh Ed25519 key pair for testing."""
    private_key = Ed25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes_raw()
    return private_key, public_key_bytes


@pytest.fixture
async def sigil_server(storage):
    """Create a Sigil instance backed by in-memory SQLite."""
    config = SigilConfig(
        builder="local",
        platforms=["linux-amd64", "darwin-arm64"],
        jwt_secret="test-secret-key-for-signing",
        storage=storage,
        challenge_ttl=300,
        session_ttl=3600,
        enrollment_ttl=600,
    )
    return Sigil(config)


# ===========================================================================
# SQLite Storage Tests
# ===========================================================================


class TestSQLiteStorage:
    """Test the SQLite storage adapter CRUD operations."""

    async def test_create_and_get_agent(self, storage: SQLiteStorage):
        agent = Agent(
            id="agent-1",
            name="Test Agent",
            external_user_id="user-42",
        )
        created = await storage.create_agent(agent)
        assert created.id == "agent-1"
        assert created.name == "Test Agent"
        assert created.status == "pending_enrollment"

        fetched = await storage.get_agent("agent-1")
        assert fetched is not None
        assert fetched.id == "agent-1"
        assert fetched.name == "Test Agent"
        assert fetched.external_user_id == "user-42"
        assert fetched.status == "pending_enrollment"
        assert fetched.public_key is None

    async def test_get_nonexistent_agent(self, storage: SQLiteStorage):
        result = await storage.get_agent("does-not-exist")
        assert result is None

    async def test_update_agent_status(self, storage: SQLiteStorage):
        agent = Agent(id="agent-2", name="Agent Two", external_user_id="user-1")
        await storage.create_agent(agent)

        now = datetime.utcnow()
        await storage.update_agent_status(
            "agent-2",
            "active",
            public_key=b"fake-key-bytes",
            key_fingerprint="abc123",
            enrolled_at=now,
        )

        updated = await storage.get_agent("agent-2")
        assert updated is not None
        assert updated.status == "active"
        assert updated.public_key == b"fake-key-bytes"
        assert updated.key_fingerprint == "abc123"
        assert updated.enrolled_at is not None

    async def test_list_agents_by_user(self, storage: SQLiteStorage):
        for i in range(3):
            await storage.create_agent(
                Agent(id=f"a-{i}", name=f"Agent {i}", external_user_id="user-x")
            )
        # Different user
        await storage.create_agent(
            Agent(id="a-other", name="Other", external_user_id="user-y")
        )

        agents = await storage.list_agents_by_user("user-x")
        assert len(agents) == 3
        assert all(a.external_user_id == "user-x" for a in agents)

    async def test_enrollment_token_lifecycle(self, storage: SQLiteStorage):
        token = EnrollmentToken(
            token_hash="hash-abc",
            agent_id="agent-1",
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        )
        await storage.create_enrollment_token(token)

        # Validate returns the token
        validated = await storage.validate_enrollment_token("hash-abc")
        assert validated is not None
        assert validated.agent_id == "agent-1"
        assert validated.used is False

        # Burn the token
        await storage.burn_enrollment_token("hash-abc")

        # Validate no longer returns it
        burned = await storage.validate_enrollment_token("hash-abc")
        assert burned is None

    async def test_expired_enrollment_token(self, storage: SQLiteStorage):
        token = EnrollmentToken(
            token_hash="hash-expired",
            agent_id="agent-1",
            expires_at=datetime.utcnow() - timedelta(minutes=1),
        )
        await storage.create_enrollment_token(token)

        result = await storage.validate_enrollment_token("hash-expired")
        assert result is None

    async def test_challenge_lifecycle(self, storage: SQLiteStorage):
        ch = Challenge(
            challenge="challenge-xyz",
            agent_id="agent-1",
            expires_at=datetime.utcnow() + timedelta(minutes=5),
        )
        await storage.create_challenge(ch)

        validated = await storage.validate_challenge("challenge-xyz")
        assert validated is not None
        assert validated.agent_id == "agent-1"

        await storage.burn_challenge("challenge-xyz")

        burned = await storage.validate_challenge("challenge-xyz")
        assert burned is None

    async def test_expired_challenge(self, storage: SQLiteStorage):
        ch = Challenge(
            challenge="expired-ch",
            agent_id="agent-1",
            expires_at=datetime.utcnow() - timedelta(minutes=1),
        )
        await storage.create_challenge(ch)

        result = await storage.validate_challenge("expired-ch")
        assert result is None

    async def test_validate_nonexistent_token(self, storage: SQLiteStorage):
        result = await storage.validate_enrollment_token("no-such-hash")
        assert result is None

    async def test_validate_nonexistent_challenge(self, storage: SQLiteStorage):
        result = await storage.validate_challenge("no-such-challenge")
        assert result is None


# ===========================================================================
# Auth Tests
# ===========================================================================


class TestAuth:
    """Test JWT and token utility functions."""

    def test_jwt_round_trip(self):
        secret = "my-test-secret"
        payload = TokenPayload(
            agent_id="agent-1",
            user_id="user-42",
            fingerprint="fp-abc",
        )
        token = issue_token(secret, payload, ttl_seconds=60)
        assert isinstance(token, str)

        decoded = verify_token(secret, token)
        assert decoded["agent_id"] == "agent-1"
        assert decoded["user_id"] == "user-42"
        assert decoded["fingerprint"] == "fp-abc"
        assert "exp" in decoded
        assert "iat" in decoded

    def test_jwt_expired_token(self):
        secret = "my-test-secret"
        payload = TokenPayload(
            agent_id="agent-1",
            user_id="user-42",
            fingerprint="fp-abc",
        )
        # Issue with 0 TTL (already expired)
        token = issue_token(secret, payload, ttl_seconds=-1)

        with pytest.raises(Exception):
            verify_token(secret, token)

    def test_jwt_wrong_secret(self):
        secret = "correct-secret"
        payload = TokenPayload(
            agent_id="agent-1",
            user_id="user-42",
            fingerprint="fp-abc",
        )
        token = issue_token(secret, payload)

        with pytest.raises(Exception):
            verify_token("wrong-secret", token)

    def test_generate_token_uniqueness(self):
        tokens = {generate_token() for _ in range(100)}
        assert len(tokens) == 100

    def test_generate_token_length(self):
        token = generate_token()
        # 32 bytes = 64 hex characters
        assert len(token) == 64

    def test_hash_token_deterministic(self):
        token = "some-test-token"
        h1 = hash_token(token)
        h2 = hash_token(token)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_hash_token_different_inputs(self):
        h1 = hash_token("token-a")
        h2 = hash_token("token-b")
        assert h1 != h2

    def test_generate_challenge_is_base64(self):
        ch = generate_challenge()
        # Should be valid base64
        import base64

        decoded = base64.b64decode(ch)
        assert len(decoded) == 32


# ===========================================================================
# Sigil Server Tests
# ===========================================================================


class TestSigil:
    """Test the main Sigil server class."""

    async def test_create_agent(self, sigil_server: Sigil):
        result = await sigil_server.create_agent(
            name="My Agent",
            external_user_id="user-1",
        )
        assert result.agent_id is not None
        assert len(result.agent_id) == 36  # UUID length
        assert result.enrollment_token is not None
        assert len(result.enrollment_token) == 64  # 32-byte hex

        # Verify agent was stored
        agent = await sigil_server.storage.get_agent(result.agent_id)
        assert agent is not None
        assert agent.name == "My Agent"
        assert agent.status == "pending_enrollment"

    async def test_challenge_active_agent(
        self, sigil_server: Sigil, ed25519_keypair
    ):
        _, public_key_bytes = ed25519_keypair

        # Create and manually activate agent
        result = await sigil_server.create_agent(
            name="Active Agent",
            external_user_id="user-2",
        )
        await sigil_server.storage.update_agent_status(
            result.agent_id,
            "active",
            public_key=public_key_bytes,
            key_fingerprint="test-fp",
            enrolled_at=datetime.utcnow(),
        )

        challenge_result = await sigil_server.challenge(result.agent_id)
        assert challenge_result.challenge is not None
        assert len(challenge_result.challenge) > 0

    async def test_challenge_unknown_agent(self, sigil_server: Sigil):
        with pytest.raises(SigilError) as exc_info:
            await sigil_server.challenge("nonexistent-id")
        assert exc_info.value.code == "AGENT_NOT_FOUND"
        assert exc_info.value.status_code == 404

    async def test_challenge_pending_agent(self, sigil_server: Sigil):
        result = await sigil_server.create_agent(
            name="Pending Agent",
            external_user_id="user-3",
        )
        with pytest.raises(SigilError) as exc_info:
            await sigil_server.challenge(result.agent_id)
        assert exc_info.value.code == "AGENT_NOT_ACTIVE"

    async def test_full_enrollment_flow(
        self, sigil_server: Sigil, ed25519_keypair
    ):
        _, public_key_bytes = ed25519_keypair

        # Create agent
        create_result = await sigil_server.create_agent(
            name="Enroll Me",
            external_user_id="user-4",
        )

        # Enroll with public key
        enroll_result = await sigil_server.enroll(
            token=create_result.enrollment_token,
            public_key=public_key_bytes,
            platform="linux-amd64",
        )
        assert enroll_result.token is not None

        # Verify the JWT
        decoded = await sigil_server.verify_jwt(enroll_result.token)
        assert decoded["agent_id"] == create_result.agent_id
        assert decoded["user_id"] == "user-4"

        # Agent should now be active
        agent = await sigil_server.storage.get_agent(create_result.agent_id)
        assert agent is not None
        assert agent.status == "active"
        assert agent.public_key == public_key_bytes

    async def test_enroll_invalid_token(self, sigil_server: Sigil):
        with pytest.raises(SigilError) as exc_info:
            await sigil_server.enroll(
                token="invalid-token",
                public_key=b"fake-key",
                platform="linux-amd64",
            )
        assert exc_info.value.code == "INVALID_ENROLLMENT_TOKEN"

    async def test_enroll_unsupported_platform(
        self, sigil_server: Sigil, ed25519_keypair
    ):
        _, public_key_bytes = ed25519_keypair

        create_result = await sigil_server.create_agent(
            name="Platform Test",
            external_user_id="user-5",
        )

        with pytest.raises(SigilError) as exc_info:
            await sigil_server.enroll(
                token=create_result.enrollment_token,
                public_key=public_key_bytes,
                platform="windows-x86",
            )
        assert exc_info.value.code == "UNSUPPORTED_PLATFORM"

    async def test_full_challenge_verify_flow(
        self, sigil_server: Sigil, ed25519_keypair
    ):
        private_key, public_key_bytes = ed25519_keypair

        # Create and enroll
        create_result = await sigil_server.create_agent(
            name="Verify Me",
            external_user_id="user-6",
        )
        await sigil_server.enroll(
            token=create_result.enrollment_token,
            public_key=public_key_bytes,
            platform="linux-amd64",
        )

        # Challenge
        challenge_result = await sigil_server.challenge(create_result.agent_id)

        # Sign the challenge
        signature = private_key.sign(challenge_result.challenge.encode())

        # Verify
        verify_result = await sigil_server.verify(
            agent_id=create_result.agent_id,
            challenge_str=challenge_result.challenge,
            signature=signature,
        )
        assert verify_result.token is not None

        # JWT should be valid
        decoded = await sigil_server.verify_jwt(verify_result.token)
        assert decoded["agent_id"] == create_result.agent_id

    async def test_verify_invalid_signature(
        self, sigil_server: Sigil, ed25519_keypair
    ):
        _, public_key_bytes = ed25519_keypair

        # Create and enroll
        create_result = await sigil_server.create_agent(
            name="Bad Sig Agent",
            external_user_id="user-7",
        )
        await sigil_server.enroll(
            token=create_result.enrollment_token,
            public_key=public_key_bytes,
            platform="linux-amd64",
        )

        # Challenge
        challenge_result = await sigil_server.challenge(create_result.agent_id)

        # Use wrong signature (random bytes)
        with pytest.raises(SigilError) as exc_info:
            await sigil_server.verify(
                agent_id=create_result.agent_id,
                challenge_str=challenge_result.challenge,
                signature=b"wrong-signature-bytes" * 4,
            )
        assert exc_info.value.code == "INVALID_SIGNATURE"

    async def test_revoke_agent(self, sigil_server: Sigil, ed25519_keypair):
        _, public_key_bytes = ed25519_keypair

        create_result = await sigil_server.create_agent(
            name="Revoke Me",
            external_user_id="user-8",
        )
        await sigil_server.enroll(
            token=create_result.enrollment_token,
            public_key=public_key_bytes,
            platform="linux-amd64",
        )

        await sigil_server.revoke(create_result.agent_id)

        agent = await sigil_server.storage.get_agent(create_result.agent_id)
        assert agent is not None
        assert agent.status == "revoked"

        # Challenge should fail for revoked agent
        with pytest.raises(SigilError) as exc_info:
            await sigil_server.challenge(create_result.agent_id)
        assert exc_info.value.code == "AGENT_NOT_ACTIVE"

    async def test_revoke_nonexistent_agent(self, sigil_server: Sigil):
        with pytest.raises(SigilError) as exc_info:
            await sigil_server.revoke("no-such-agent")
        assert exc_info.value.code == "AGENT_NOT_FOUND"

    async def test_re_enroll_revoked_agent(
        self, sigil_server: Sigil, ed25519_keypair
    ):
        _, public_key_bytes = ed25519_keypair

        # Create, enroll, revoke
        create_result = await sigil_server.create_agent(
            name="Re-enroll Me",
            external_user_id="user-9",
        )
        await sigil_server.enroll(
            token=create_result.enrollment_token,
            public_key=public_key_bytes,
            platform="linux-amd64",
        )
        await sigil_server.revoke(create_result.agent_id)

        # Re-enroll
        re_result = await sigil_server.re_enroll(create_result.agent_id)
        assert re_result.agent_id == create_result.agent_id
        assert re_result.enrollment_token is not None

        agent = await sigil_server.storage.get_agent(create_result.agent_id)
        assert agent is not None
        assert agent.status == "pending_enrollment"

    async def test_re_enroll_active_agent_fails(
        self, sigil_server: Sigil, ed25519_keypair
    ):
        _, public_key_bytes = ed25519_keypair

        create_result = await sigil_server.create_agent(
            name="Active Agent",
            external_user_id="user-10",
        )
        await sigil_server.enroll(
            token=create_result.enrollment_token,
            public_key=public_key_bytes,
            platform="linux-amd64",
        )

        with pytest.raises(SigilError) as exc_info:
            await sigil_server.re_enroll(create_result.agent_id)
        assert exc_info.value.code == "INVALID_AGENT_STATUS"

    async def test_verify_jwt_invalid(self, sigil_server: Sigil):
        with pytest.raises(SigilError) as exc_info:
            await sigil_server.verify_jwt("not-a-valid-jwt")
        assert exc_info.value.code == "INVALID_TOKEN"

    async def test_key_rotation(
        self, sigil_server: Sigil, ed25519_keypair
    ):
        private_key, public_key_bytes = ed25519_keypair

        # Create and enroll
        create_result = await sigil_server.create_agent(
            name="Rotate Me",
            external_user_id="user-11",
        )
        await sigil_server.enroll(
            token=create_result.enrollment_token,
            public_key=public_key_bytes,
            platform="linux-amd64",
        )

        # Challenge for rotation
        challenge_result = await sigil_server.challenge(create_result.agent_id)
        signature = private_key.sign(challenge_result.challenge.encode())

        # Generate new keypair
        new_private_key = Ed25519PrivateKey.generate()
        new_public_key_bytes = new_private_key.public_key().public_bytes_raw()

        # Rotate
        rotate_result = await sigil_server.rotate(
            agent_id=create_result.agent_id,
            new_public_key=new_public_key_bytes,
            challenge_str=challenge_result.challenge,
            signature=signature,
        )
        assert rotate_result.token is not None

        # Verify agent has new key
        agent = await sigil_server.storage.get_agent(create_result.agent_id)
        assert agent is not None
        assert agent.public_key == new_public_key_bytes
        assert agent.status == "active"

        # Verify new key works for auth
        challenge_result2 = await sigil_server.challenge(create_result.agent_id)
        signature2 = new_private_key.sign(challenge_result2.challenge.encode())
        verify_result = await sigil_server.verify(
            agent_id=create_result.agent_id,
            challenge_str=challenge_result2.challenge,
            signature=signature2,
        )
        assert verify_result.token is not None
