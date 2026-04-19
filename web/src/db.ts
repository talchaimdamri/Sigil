import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { dbPath } from './sigil.js';

export const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS agent_meta (
    agent_id     TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL,
    codeword     TEXT NOT NULL,
    last_seen_at INTEGER
  );

  CREATE INDEX IF NOT EXISTS idx_agent_meta_user_id ON agent_meta(user_id);
`);

export interface User {
  id: string;
  name: string;
  createdAt: number;
}

export interface AgentMeta {
  agentId: string;
  userId: string;
  codeword: string;
  lastSeenAt: number | null;
}

export function upsertUser(name: string): User {
  const existing = db.prepare('SELECT * FROM users WHERE name = ?').get(name) as
    | { id: string; name: string; created_at: number }
    | undefined;
  if (existing) {
    return { id: existing.id, name: existing.name, createdAt: existing.created_at };
  }
  const id = crypto.randomUUID();
  const createdAt = Date.now();
  db.prepare('INSERT INTO users (id, name, created_at) VALUES (?, ?, ?)').run(id, name, createdAt);
  return { id, name, createdAt };
}

export function getUser(id: string): User | null {
  const row = db.prepare('SELECT * FROM users WHERE id = ?').get(id) as
    | { id: string; name: string; created_at: number }
    | undefined;
  if (!row) return null;
  return { id: row.id, name: row.name, createdAt: row.created_at };
}

export function insertAgentMeta(meta: { agentId: string; userId: string; codeword: string }): void {
  db.prepare(
    'INSERT INTO agent_meta (agent_id, user_id, codeword, last_seen_at) VALUES (?, ?, ?, NULL)',
  ).run(meta.agentId, meta.userId, meta.codeword);
}

export function getAgentMeta(agentId: string): AgentMeta | null {
  const row = db.prepare('SELECT * FROM agent_meta WHERE agent_id = ?').get(agentId) as
    | { agent_id: string; user_id: string; codeword: string; last_seen_at: number | null }
    | undefined;
  if (!row) return null;
  return {
    agentId: row.agent_id,
    userId: row.user_id,
    codeword: row.codeword,
    lastSeenAt: row.last_seen_at,
  };
}

export function deleteAgentMeta(agentId: string): void {
  db.prepare('DELETE FROM agent_meta WHERE agent_id = ?').run(agentId);
}

export function touchAgentMeta(agentId: string): void {
  db.prepare('UPDATE agent_meta SET last_seen_at = ? WHERE agent_id = ?').run(Date.now(), agentId);
}

export interface AgentRow {
  id: string;
  name: string;
  status: string;
  platform: string | null;
  enrolledAt: number | null;
  codeword: string;
  lastSeenAt: number | null;
}

export function listAgentsForUser(userId: string): AgentRow[] {
  const rows = db
    .prepare(
      `SELECT sa.id, sa.name, sa.status, sa.platform, sa.enrolled_at, am.codeword, am.last_seen_at
       FROM agent_meta am
       JOIN sigil_agents sa ON sa.id = am.agent_id
       WHERE am.user_id = ?
       ORDER BY sa.created_at DESC`,
    )
    .all(userId) as Array<{
    id: string;
    name: string;
    status: string;
    platform: string | null;
    enrolled_at: string | null;
    codeword: string;
    last_seen_at: number | null;
  }>;
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    status: r.status,
    platform: r.platform,
    enrolledAt: r.enrolled_at ? new Date(r.enrolled_at).getTime() : null,
    codeword: r.codeword,
    lastSeenAt: r.last_seen_at,
  }));
}
