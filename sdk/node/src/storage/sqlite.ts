import Database from 'better-sqlite3';
import type { StorageAdapter, Agent, EnrollmentToken, Challenge } from '../types.js';

export class SQLiteStorageAdapter implements StorageAdapter {
  private db: Database.Database;

  agents: StorageAdapter['agents'];
  enrollmentTokens: StorageAdapter['enrollmentTokens'];
  challenges: StorageAdapter['challenges'];

  constructor(path: string) {
    this.db = new Database(path);
    this.db.pragma('journal_mode = WAL');
    this.initTables();

    this.agents = {
      create: this.createAgent.bind(this),
      get: this.getAgent.bind(this),
      updateStatus: this.updateAgentStatus.bind(this),
      listByUser: this.listAgentsByUser.bind(this),
    };

    this.enrollmentTokens = {
      create: this.createEnrollmentToken.bind(this),
      validate: this.validateEnrollmentToken.bind(this),
      burn: this.burnEnrollmentToken.bind(this),
    };

    this.challenges = {
      create: this.createChallenge.bind(this),
      validate: this.validateChallenge.bind(this),
      burn: this.burnChallenge.bind(this),
    };
  }

  private initTables(): void {
    this.db.exec(`
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
    `);
  }

  // ─── Agents ──────────────────────────────────────────────────────────

  private async createAgent(input: Omit<Agent, 'createdAt'>): Promise<Agent> {
    const createdAt = new Date();
    const stmt = this.db.prepare(`
      INSERT INTO sigil_agents (id, name, external_user_id, public_key, key_fingerprint, platform, status, enrolled_at, last_auth_at, key_expires_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      input.id,
      input.name,
      input.externalUserId,
      input.publicKey ?? null,
      input.keyFingerprint ?? null,
      input.platform ?? null,
      input.status,
      input.enrolledAt ? input.enrolledAt.toISOString() : null,
      input.lastAuthAt ? input.lastAuthAt.toISOString() : null,
      input.keyExpiresAt ? input.keyExpiresAt.toISOString() : null,
      createdAt.toISOString(),
    );
    return { ...input, createdAt };
  }

  private async getAgent(id: string): Promise<Agent | null> {
    const row = this.db.prepare('SELECT * FROM sigil_agents WHERE id = ?').get(id) as
      | Record<string, unknown>
      | undefined;
    if (!row) return null;
    return this.rowToAgent(row);
  }

  private async updateAgentStatus(
    id: string,
    status: Agent['status'],
    fields?: Partial<Agent>,
  ): Promise<void> {
    const sets: string[] = ['status = ?'];
    const values: unknown[] = [status];

    if (fields) {
      if (fields.publicKey !== undefined) {
        sets.push('public_key = ?');
        values.push(fields.publicKey ?? null);
      }
      if (fields.keyFingerprint !== undefined) {
        sets.push('key_fingerprint = ?');
        values.push(fields.keyFingerprint ?? null);
      }
      if (fields.platform !== undefined) {
        sets.push('platform = ?');
        values.push(fields.platform ?? null);
      }
      if (fields.enrolledAt !== undefined) {
        sets.push('enrolled_at = ?');
        values.push(fields.enrolledAt ? fields.enrolledAt.toISOString() : null);
      }
      if (fields.lastAuthAt !== undefined) {
        sets.push('last_auth_at = ?');
        values.push(fields.lastAuthAt ? fields.lastAuthAt.toISOString() : null);
      }
      if (fields.keyExpiresAt !== undefined) {
        sets.push('key_expires_at = ?');
        values.push(fields.keyExpiresAt ? fields.keyExpiresAt.toISOString() : null);
      }
      if (fields.name !== undefined) {
        sets.push('name = ?');
        values.push(fields.name);
      }
    }

    values.push(id);
    this.db.prepare(`UPDATE sigil_agents SET ${sets.join(', ')} WHERE id = ?`).run(...values);
  }

  private async listAgentsByUser(userId: string): Promise<Agent[]> {
    const rows = this.db
      .prepare('SELECT * FROM sigil_agents WHERE external_user_id = ?')
      .all(userId) as Record<string, unknown>[];
    return rows.map((row) => this.rowToAgent(row));
  }

  private rowToAgent(row: Record<string, unknown>): Agent {
    return {
      id: row.id as string,
      name: row.name as string,
      externalUserId: row.external_user_id as string,
      publicKey: row.public_key ? Buffer.from(row.public_key as Buffer) : null,
      keyFingerprint: (row.key_fingerprint as string) ?? null,
      platform: (row.platform as string) ?? null,
      status: row.status as Agent['status'],
      enrolledAt: row.enrolled_at ? new Date(row.enrolled_at as string) : null,
      lastAuthAt: row.last_auth_at ? new Date(row.last_auth_at as string) : null,
      keyExpiresAt: row.key_expires_at ? new Date(row.key_expires_at as string) : null,
      createdAt: new Date(row.created_at as string),
    };
  }

  // ─── Enrollment Tokens ──────────────────────────────────────────────

  private async createEnrollmentToken(token: EnrollmentToken): Promise<void> {
    this.db
      .prepare(
        `INSERT INTO sigil_enrollment_tokens (token_hash, agent_id, expires_at, used)
       VALUES (?, ?, ?, ?)`,
      )
      .run(token.tokenHash, token.agentId, token.expiresAt.toISOString(), token.used ? 1 : 0);
  }

  private async validateEnrollmentToken(tokenHash: string): Promise<EnrollmentToken | null> {
    const row = this.db
      .prepare(
        `SELECT * FROM sigil_enrollment_tokens
       WHERE token_hash = ? AND used = 0 AND expires_at > ?`,
      )
      .get(tokenHash, new Date().toISOString()) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.rowToEnrollmentToken(row);
  }

  private async burnEnrollmentToken(tokenHash: string): Promise<void> {
    this.db
      .prepare('UPDATE sigil_enrollment_tokens SET used = 1 WHERE token_hash = ?')
      .run(tokenHash);
  }

  private rowToEnrollmentToken(row: Record<string, unknown>): EnrollmentToken {
    return {
      tokenHash: row.token_hash as string,
      agentId: row.agent_id as string,
      expiresAt: new Date(row.expires_at as string),
      used: (row.used as number) === 1,
    };
  }

  // ─── Challenges ─────────────────────────────────────────────────────

  private async createChallenge(challenge: Challenge): Promise<void> {
    this.db
      .prepare(
        `INSERT INTO sigil_challenges (challenge, agent_id, expires_at, used)
       VALUES (?, ?, ?, ?)`,
      )
      .run(
        challenge.challenge,
        challenge.agentId,
        challenge.expiresAt.toISOString(),
        challenge.used ? 1 : 0,
      );
  }

  private async validateChallenge(challenge: string): Promise<Challenge | null> {
    const row = this.db
      .prepare(
        `SELECT * FROM sigil_challenges
       WHERE challenge = ? AND used = 0 AND expires_at > ?`,
      )
      .get(challenge, new Date().toISOString()) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.rowToChallenge(row);
  }

  private async burnChallenge(challenge: string): Promise<void> {
    this.db
      .prepare('UPDATE sigil_challenges SET used = 1 WHERE challenge = ?')
      .run(challenge);
  }

  private rowToChallenge(row: Record<string, unknown>): Challenge {
    return {
      challenge: row.challenge as string,
      agentId: row.agent_id as string,
      expiresAt: new Date(row.expires_at as string),
      used: (row.used as number) === 1,
    };
  }

  // ─── Cleanup ────────────────────────────────────────────────────────

  async cleanup(): Promise<void> {
    const now = new Date().toISOString();
    this.db.prepare('DELETE FROM sigil_challenges WHERE expires_at <= ? OR used = 1').run(now);
    this.db
      .prepare('DELETE FROM sigil_enrollment_tokens WHERE expires_at <= ? OR used = 1')
      .run(now);
  }

  /** Close the database connection. */
  close(): void {
    this.db.close();
  }
}
