import crypto from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import { config } from './config.js';
import { getUser, type User } from './db.js';

const COOKIE_NAME = 'sigil_session';
const COOKIE_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

function sign(value: string): string {
  const mac = crypto.createHmac('sha256', config.sessionSecret).update(value).digest('base64url');
  return `${value}.${mac}`;
}

function unsign(signed: string): string | null {
  const idx = signed.lastIndexOf('.');
  if (idx < 0) return null;
  const value = signed.slice(0, idx);
  const mac = signed.slice(idx + 1);
  const expected = crypto.createHmac('sha256', config.sessionSecret).update(value).digest('base64url');
  const a = Buffer.from(mac);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return null;
  if (!crypto.timingSafeEqual(a, b)) return null;
  return value;
}

function parseCookies(header: string | undefined): Record<string, string> {
  if (!header) return {};
  const out: Record<string, string> = {};
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim();
    const val = part.slice(eq + 1).trim();
    if (key.length > 0) out[key] = decodeURIComponent(val);
  }
  return out;
}

export function setSession(res: Response, userId: string): void {
  const signed = sign(userId);
  const secure = config.nodeEnv === 'production' ? '; Secure' : '';
  res.setHeader(
    'Set-Cookie',
    `${COOKIE_NAME}=${encodeURIComponent(signed)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(COOKIE_MAX_AGE_MS / 1000)}${secure}`,
  );
}

export function clearSession(res: Response): void {
  const secure = config.nodeEnv === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`);
}

export function readUser(req: Request): User | null {
  const cookies = parseCookies(req.headers.cookie);
  const signed = cookies[COOKIE_NAME];
  if (!signed) return null;
  const userId = unsign(signed);
  if (!userId) return null;
  return getUser(userId);
}

declare module 'express-serve-static-core' {
  interface Request {
    user?: User;
  }
}

export function requireUser(req: Request, res: Response, next: NextFunction): void {
  const user = readUser(req);
  if (!user) {
    res.redirect('/login');
    return;
  }
  req.user = user;
  next();
}
