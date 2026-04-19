import { Sigil, SQLiteStorageAdapter } from '@sigil/server';
import { config } from './config.js';
import fs from 'node:fs';
import path from 'node:path';

fs.mkdirSync(config.dataDir, { recursive: true });

export const dbPath = path.join(config.dataDir, 'sigil.db');

export const storage = new SQLiteStorageAdapter(dbPath);

export const sigil = new Sigil({
  builder: 'local',
  platforms: [...config.platforms],
  jwtSecret: config.jwtSecret,
  storage,
  garble: false,
  upx: false,
});
