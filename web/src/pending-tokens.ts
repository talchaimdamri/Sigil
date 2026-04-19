// In-memory cache of freshly-minted enrollment tokens so the detail page
// can render them between creation and first enroll. Tokens are one-shot and
// expire in 30 minutes server-side; this just mirrors the lifetime in memory.
// Lost on restart — user can revoke + re-create if that happens.

interface PendingToken {
  token: string;
  expiresAt: number;
}

const pending = new Map<string, PendingToken>();

export function rememberToken(agentId: string, token: string, expiresAt: Date): void {
  pending.set(agentId, { token, expiresAt: expiresAt.getTime() });
}

export function getPendingToken(agentId: string): string | null {
  const entry = pending.get(agentId);
  if (!entry) return null;
  if (Date.now() >= entry.expiresAt) {
    pending.delete(agentId);
    return null;
  }
  return entry.token;
}

export function forgetToken(agentId: string): void {
  pending.delete(agentId);
}
