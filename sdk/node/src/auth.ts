import { SignJWT, jwtVerify } from 'jose';
import crypto from 'node:crypto';

export async function issueToken(
  secret: string,
  payload: { agentId: string; userId: string; fingerprint: string },
  ttlSeconds: number,
): Promise<string> {
  const key = new TextEncoder().encode(secret);
  return new SignJWT({
    agent_id: payload.agentId,
    user_id: payload.userId,
    fingerprint: payload.fingerprint,
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(`${ttlSeconds}s`)
    .sign(key);
}

export async function verifyToken(
  secret: string,
  token: string,
): Promise<{ agentId: string; userId: string; fingerprint: string }> {
  const key = new TextEncoder().encode(secret);
  const { payload } = await jwtVerify(token, key);
  return {
    agentId: payload.agent_id as string,
    userId: payload.user_id as string,
    fingerprint: payload.fingerprint as string,
  };
}

export function generateToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export function generateChallenge(): string {
  return crypto.randomBytes(32).toString('base64');
}
