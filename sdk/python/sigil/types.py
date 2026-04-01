from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol


@dataclass
class Agent:
    id: str
    name: str
    external_user_id: str
    public_key: bytes | None = None
    key_fingerprint: str | None = None
    platform: str | None = None
    status: str = "pending_enrollment"
    enrolled_at: datetime | None = None
    last_auth_at: datetime | None = None
    key_expires_at: datetime | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class EnrollmentToken:
    token_hash: str
    agent_id: str
    expires_at: datetime
    used: bool = False


@dataclass
class Challenge:
    challenge: str
    agent_id: str
    expires_at: datetime
    used: bool = False


class StorageAdapter(Protocol):
    async def create_agent(self, agent: Agent) -> Agent: ...
    async def get_agent(self, agent_id: str) -> Agent | None: ...
    async def update_agent_status(self, agent_id: str, status: str, **fields) -> None: ...
    async def list_agents_by_user(self, user_id: str) -> list[Agent]: ...

    async def create_enrollment_token(self, token: EnrollmentToken) -> None: ...
    async def validate_enrollment_token(self, token_hash: str) -> EnrollmentToken | None: ...
    async def burn_enrollment_token(self, token_hash: str) -> None: ...

    async def create_challenge(self, challenge: Challenge) -> None: ...
    async def validate_challenge(self, challenge: str) -> Challenge | None: ...
    async def burn_challenge(self, challenge: str) -> None: ...

    async def cleanup(self) -> None: ...
