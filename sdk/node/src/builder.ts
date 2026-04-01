import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs/promises';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';

const execFileAsync = promisify(execFile);

export interface BuildResult {
  binary: Buffer;
  sha256: string;
}

export interface Builder {
  type: 'local' | 'remote';
  build(privateKeySeedB64: string, platform: string): Promise<BuildResult>;
}

export function createBuilder(mode: string, options?: { garble?: boolean; upx?: boolean }): Builder {
  const useGarble = options?.garble ?? true;
  const useUPX = options?.upx ?? true;

  if (mode === 'local') {
    return {
      type: 'local',
      async build(privateKeySeedB64, platform) {
        const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'sigil-'));
        const outPath = path.join(tmpDir, 'identity');

        const args = [
          'build',
          '--private-key', privateKeySeedB64,
          '--platform', platform,
          '--output', outPath,
        ];
        if (!useGarble) args.push('--no-garble');
        if (!useUPX) args.push('--no-upx');

        try {
          await execFileAsync('sigil-builder', args, { timeout: 120000 });

          const binary = await fs.readFile(outPath);
          const sha256 = crypto.createHash('sha256').update(binary).digest('hex');

          return { binary, sha256 };
        } finally {
          await fs.rm(tmpDir, { recursive: true, force: true });
        }
      },
    };
  }

  // Remote builder — mode is a base URL
  const baseUrl = mode.replace(/\/$/, '');
  return {
    type: 'remote',
    async build(privateKeySeedB64, platform) {
      const res = await fetch(`${baseUrl}/build`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ private_key: privateKeySeedB64, platform }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: 'unknown' })) as { error: string };
        throw new Error(`Builder error: ${err.error} (${res.status})`);
      }

      const binary = Buffer.from(await res.arrayBuffer());
      const sha256 = res.headers.get('X-Binary-SHA256') || '';

      return { binary, sha256 };
    },
  };
}
