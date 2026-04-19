import { Router } from 'express';
import { sigil, storage } from '../sigil.js';
import {
  deleteAgentMeta,
  getAgentMeta,
  insertAgentMeta,
  listAgentsForUser,
} from '../db.js';
import { generateCodeword } from '../codewords.js';
import { rememberToken, forgetToken } from '../pending-tokens.js';
import { requireUser } from '../session.js';
import { dashboardPage } from '../views/dashboard.js';
import { send } from '../views/layout.js';

export const dashboardRouter: Router = Router();

dashboardRouter.get('/', requireUser, (req, res) => {
  const agents = listAgentsForUser(req.user!.id);
  send(res, dashboardPage(req.user!, agents));
});

dashboardRouter.post('/agents', requireUser, async (req, res) => {
  const name = String(req.body?.name ?? '').trim();
  if (!/^[A-Za-z0-9_.-]{1,32}$/.test(name)) {
    res.status(400).send('invalid agent name');
    return;
  }

  const created = await sigil.createAgent({ name, userId: req.user!.id });
  const codeword = generateCodeword();
  insertAgentMeta({ agentId: created.agentId, userId: req.user!.id, codeword });
  rememberToken(created.agentId, created.enrollmentToken, created.enrollmentExpiresAt);

  res.redirect(`/agents/${created.agentId}`);
});

dashboardRouter.post('/agents/:id/delete', requireUser, async (req, res) => {
  const id = String(req.params.id ?? '');
  const meta = getAgentMeta(id);
  if (!meta || meta.userId !== req.user!.id) {
    res.status(404).send('not found');
    return;
  }
  try {
    await sigil.revoke(id);
  } catch {
    // revoke is idempotent enough for us — if SDK rejects, proceed to clean up meta anyway
  }
  deleteAgentMeta(id);
  forgetToken(id);
  res.redirect('/');
});
