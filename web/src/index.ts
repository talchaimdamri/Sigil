import express from 'express';
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
