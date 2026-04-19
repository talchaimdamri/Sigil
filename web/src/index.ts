import express from 'express';
import path from 'node:path';
import fs from 'node:fs';
import { config, productionOnly } from './config.js';
import './sigil.js'; // side effect: open DB, construct Sigil
import './db.js';    // side effect: create users + agent_meta tables
import { authRouter } from './routes/auth.js';
import { dashboardRouter } from './routes/dashboard.js';
import { agentRouter } from './routes/agent.js';
import { whoamiRouter } from './routes/whoami.js';
import { sigilRouter } from './routes/sigil.js';

productionOnly();

export function createApp(): express.Express {
  const app = express();

  app.disable('x-powered-by');
  app.use(express.json({ limit: '256kb' }));
  app.use(express.urlencoded({ extended: false, limit: '256kb' }));

  app.get('/healthz', (_req, res) => {
    res.type('text/plain').send('ok');
  });

  // Serve cross-compiled sigil CLI binaries so agents can `curl | install`
  // them in one step. Populated by the Dockerfile's go-builder stage.
  // Falls back to repo-root ./public for local dev (optional).
  const publicCandidates = [
    path.resolve(process.cwd(), 'public'),
    '/app/public',
  ];
  for (const dir of publicCandidates) {
    if (fs.existsSync(dir)) {
      app.use('/bin', express.static(path.join(dir, 'bin'), {
        maxAge: '1h',
        setHeaders: (res) => {
          res.setHeader('Content-Type', 'application/octet-stream');
        },
      }));
      break;
    }
  }

  app.use(sigilRouter);
  app.use(whoamiRouter);
  app.use(authRouter);
  app.use(agentRouter);
  app.use(dashboardRouter);

  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error('[error]', err);
    if (res.headersSent) return;
    res.status(500).type('text/plain').send('internal error');
  });

  return app;
}

// Start server unless imported by tests
const isEntryPoint = import.meta.url === `file://${process.argv[1]}`;
if (isEntryPoint) {
  const app = createApp();
  app.listen(config.port, () => {
    console.log(`[sigil-web] listening on :${config.port}`);
    console.log(`[sigil-web] public url: ${config.publicUrl}`);
    console.log(`[sigil-web] data dir: ${config.dataDir}`);
  });
}
