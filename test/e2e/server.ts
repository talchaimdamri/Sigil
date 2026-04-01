/**
 * Minimal Sigil test server for E2E testing.
 * Run: npx tsx test/e2e/server.ts
 */
import express from 'express';
import { Sigil } from '../../sdk/node/src/sigil.js';
import { createRouteHandlers, createMiddleware } from '../../sdk/node/src/middleware.js';
import { SQLiteStorageAdapter } from '../../sdk/node/src/storage/sqlite.js';

const app = express();
app.use(express.json());

const storage = new SQLiteStorageAdapter(':memory:');

const sigil = new Sigil({
  builder: 'local',
  platforms: ['darwin-arm64', 'darwin-amd64', 'linux-amd64', 'linux-arm64'],
  jwtSecret: 'test-secret-for-e2e-at-least-32-characters-long',
  storage,
  garble: false,  // garble v0.15 requires Go 1.25+; disable for testing with Go 1.24
  upx: false,     // UPX crashes on macOS 13+
});

// Add error logging for debugging
const originalEnroll = sigil.enroll.bind(sigil);
sigil.enroll = async (...args: Parameters<typeof sigil.enroll>) => {
  try {
    return await originalEnroll(...args);
  } catch (e) {
    console.error('Enroll error:', e);
    throw e;
  }
};

const handlers = createRouteHandlers(sigil);

// Mount routes
app.post('/sigil/agents', handlers.createAgent);
app.post('/sigil/enroll', handlers.enroll);
app.post('/sigil/auth/challenge', handlers.challenge);
app.post('/sigil/auth/verify', handlers.verify);
app.post('/sigil/agents/:id/rotate', handlers.rotate);
app.delete('/sigil/agents/:id/key', handlers.revoke);
app.post('/sigil/agents/:id/re-enroll', handlers.reEnroll);

// Protected test endpoint
app.get('/api/whoami', createMiddleware(sigil), (req: any, res: any) => {
  res.json({ agent: req.agent });
});

const PORT = 3456;
app.listen(PORT, () => {
  console.log(`Sigil test server running on http://localhost:${PORT}`);
  console.log('Ready for E2E testing.');
});
