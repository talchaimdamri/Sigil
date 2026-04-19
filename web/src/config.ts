import crypto from 'node:crypto';
import path from 'node:path';

function required(name: string): string {
  const v = process.env[name];
  if (!v || v.length === 0) throw new Error(`env var ${name} is required`);
  return v;
}

function devFallback(name: string, generator: () => string): string {
  const v = process.env[name];
  if (v && v.length > 0) return v;
  if (process.env.NODE_ENV === 'production') {
    throw new Error(`env var ${name} is required in production`);
  }
  const generated = generator();
  process.env[name] = generated;
  console.warn(`[config] ${name} not set — generated ephemeral value for dev`);
  return generated;
}

export const config = {
  port: parseInt(process.env.PORT ?? '3000', 10),
  dataDir: process.env.DATA_DIR ?? path.resolve(process.cwd(), 'data'),
  publicUrl: (process.env.PUBLIC_URL ?? `http://localhost:${process.env.PORT ?? '3000'}`).replace(/\/$/, ''),
  jwtSecret: devFallback('JWT_SECRET', () => crypto.randomBytes(32).toString('hex')),
  sessionSecret: devFallback('SESSION_SECRET', () => crypto.randomBytes(32).toString('hex')),
  nodeEnv: process.env.NODE_ENV ?? 'development',
  platforms: [
    'linux-amd64',
    'linux-arm64',
    'darwin-amd64',
    'darwin-arm64',
    'windows-amd64',
  ] as const,
};

export function productionOnly() {
  if (config.nodeEnv !== 'production') return;
  // These throw if missing in prod:
  required('JWT_SECRET');
  required('SESSION_SECRET');
  required('PUBLIC_URL');
  required('DATA_DIR');
}
