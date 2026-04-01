"""SQLite storage adapter using aiosqlite for async access."""

from __future__ import annotations

from datetime import datetime

import aiosqlite

from sigil.types import Agent, Challenge, EnrollmentToken

_CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS sigil_agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    external_user_id TEXT NOT NULL,
    public_key BLOB,
    key_fingerprint TEXT,
    platform TEXT,
    status TEXT NOT NULL DEFAULT 'pending_enrollment',
    enrolled_at TEXT,
    last_auth_at TEXT,
    key_expires_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sigil_enrollment_tokens (
    token_hash TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sigil_challenges (
    challenge TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
"""


def _dt_to_str(dt: datetime | None) -> str | None:
    """Convert a datetime to ISO format string, or None."""
    return dt.isoformat() if dt else None


def _str_to_dt(s: str | None) -> datetime | None:
    """Parse an ISO format string to datetime, or None."""
    return datetime.fromisoformat(s) if s else None


def _row_to_agent(row: aiosqlite.Row) -> Agent:
    """Convert a database row to an Agent dataclass."""
    return Agent(
        id=row[0],
        name=row[1],
        external_user_id=row[2],
        public_key=row[3],
        key_fingerprint=row[4],
        platform=row[5],
        status=row[6],
        enrolled_at=_str_to_dt(row[7]),
        last_auth_at=_str_to_dt(row[8]),
        key_expires_at=_str_to_dt(row[9]),
        created_at=_str_to_dt(row[10]) or datetime.utcnow(),
    )


class SQLiteStorage:
    """Async SQLite storage adapter implementing the StorageAdapter protocol."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self._db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def _get_db(self) -> aiosqlite.Connection:
        if self._db is None:
            self._db = await aiosqlite.connect(self._db_path)
            await self._db.executescript(_CREATE_TABLES)
        return self._db

    # -- Agents --

    async def create_agent(self, agent: Agent) -> Agent:
        db = await self._get_db()
        await db.execute(
            """
            INSERT INTO sigil_agents
                (id, name, external_user_id, public_key, key_fingerprint,
                 platform, status, enrolled_at, last_auth_at, key_expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                agent.id,
                agent.name,
                agent.external_user_id,
                agent.public_key,
                agent.key_fingerprint,
                agent.platform,
                agent.status,
                _dt_to_str(agent.enrolled_at),
                _dt_to_str(agent.last_auth_at),
                _dt_to_str(agent.key_expires_at),
                _dt_to_str(agent.created_at),
            ),
        )
        await db.commit()
        return agent

    async def get_agent(self, agent_id: str) -> Agent | None:
        db = await self._get_db()
        cursor = await db.execute(
            "SELECT * FROM sigil_agents WHERE id = ?",
            (agent_id,),
        )
        row = await cursor.fetchone()
        return _row_to_agent(row) if row else None

    async def update_agent_status(
        self, agent_id: str, status: str, **fields: object
    ) -> None:
        db = await self._get_db()

        set_clauses = ["status = ?"]
        params: list[object] = [status]

        field_mapping = {
            "public_key": "public_key",
            "key_fingerprint": "key_fingerprint",
            "platform": "platform",
            "enrolled_at": "enrolled_at",
            "last_auth_at": "last_auth_at",
            "key_expires_at": "key_expires_at",
        }

        for field_name, column in field_mapping.items():
            if field_name in fields:
                value = fields[field_name]
                if isinstance(value, datetime):
                    value = _dt_to_str(value)
                set_clauses.append(f"{column} = ?")
                params.append(value)

        params.append(agent_id)
        sql = f"UPDATE sigil_agents SET {', '.join(set_clauses)} WHERE id = ?"
        await db.execute(sql, params)
        await db.commit()

    async def list_agents_by_user(self, user_id: str) -> list[Agent]:
        db = await self._get_db()
        cursor = await db.execute(
            "SELECT * FROM sigil_agents WHERE external_user_id = ?",
            (user_id,),
        )
        rows = await cursor.fetchall()
        return [_row_to_agent(row) for row in rows]

    # -- Enrollment Tokens --

    async def create_enrollment_token(self, token: EnrollmentToken) -> None:
        db = await self._get_db()
        await db.execute(
            """
            INSERT INTO sigil_enrollment_tokens (token_hash, agent_id, expires_at, used)
            VALUES (?, ?, ?, ?)
            """,
            (
                token.token_hash,
                token.agent_id,
                _dt_to_str(token.expires_at),
                1 if token.used else 0,
            ),
        )
        await db.commit()

    async def validate_enrollment_token(
        self, token_hash: str
    ) -> EnrollmentToken | None:
        db = await self._get_db()
        cursor = await db.execute(
            """
            SELECT token_hash, agent_id, expires_at, used
            FROM sigil_enrollment_tokens
            WHERE token_hash = ? AND used = 0
            """,
            (token_hash,),
        )
        row = await cursor.fetchone()
        if not row:
            return None

        token = EnrollmentToken(
            token_hash=row[0],
            agent_id=row[1],
            expires_at=_str_to_dt(row[2]) or datetime.utcnow(),
            used=bool(row[3]),
        )

        # Check expiration
        if token.expires_at < datetime.utcnow():
            return None

        return token

    async def burn_enrollment_token(self, token_hash: str) -> None:
        db = await self._get_db()
        await db.execute(
            "UPDATE sigil_enrollment_tokens SET used = 1 WHERE token_hash = ?",
            (token_hash,),
        )
        await db.commit()

    # -- Challenges --

    async def create_challenge(self, challenge: Challenge) -> None:
        db = await self._get_db()
        await db.execute(
            """
            INSERT INTO sigil_challenges (challenge, agent_id, expires_at, used)
            VALUES (?, ?, ?, ?)
            """,
            (
                challenge.challenge,
                challenge.agent_id,
                _dt_to_str(challenge.expires_at),
                1 if challenge.used else 0,
            ),
        )
        await db.commit()

    async def validate_challenge(self, challenge: str) -> Challenge | None:
        db = await self._get_db()
        cursor = await db.execute(
            """
            SELECT challenge, agent_id, expires_at, used
            FROM sigil_challenges
            WHERE challenge = ? AND used = 0
            """,
            (challenge,),
        )
        row = await cursor.fetchone()
        if not row:
            return None

        ch = Challenge(
            challenge=row[0],
            agent_id=row[1],
            expires_at=_str_to_dt(row[2]) or datetime.utcnow(),
            used=bool(row[3]),
        )

        if ch.expires_at < datetime.utcnow():
            return None

        return ch

    async def burn_challenge(self, challenge: str) -> None:
        db = await self._get_db()
        await db.execute(
            "UPDATE sigil_challenges SET used = 1 WHERE challenge = ?",
            (challenge,),
        )
        await db.commit()

    # -- Lifecycle --

    async def cleanup(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None
