import { Router } from 'express';
import { sigil, storage } from '../sigil.js';
import { getAgentMeta } from '../db.js';
import { getPendingToken } from '../pending-tokens.js';
import { requireUser } from '../session.js';
import { agentDetailPage } from '../views/agent.js';
import { send } from '../views/layout.js';
import { config } from '../config.js';

export const agentRouter: Router = Router();

agentRouter.get('/agents/:id', requireUser, async (req, res) => {
  const id = String(req.params.id ?? '');
  const meta = getAgentMeta(id);
  if (!meta || meta.userId !== req.user!.id) {
    res.status(404).send('not found');
    return;
  }
  const agent = await storage.agents.get(id);
  if (!agent) {
    res.status(404).send('not found');
    return;
  }

  const token =
    agent.status === 'pending_enrollment' || agent.status === 'rotating'
      ? getPendingToken(agent.id)
      : null;

  send(
    res,
    agentDetailPage({
      user: req.user!,
      agent,
      codeword: meta.codeword,
      lastSeenAt: meta.lastSeenAt,
      enrollmentToken: token,
      publicUrl: config.publicUrl,
    }),
  );
});

agentRouter.get('/agents/:id/status.json', requireUser, async (req, res) => {
  const id = String(req.params.id ?? '');
  const meta = getAgentMeta(id);
  if (!meta || meta.userId !== req.user!.id) {
    res.status(404).json({ error: 'not_found' });
    return;
  }
  const agent = await storage.agents.get(id);
  if (!agent) {
    res.status(404).json({ error: 'not_found' });
    return;
  }
  const connected = !!meta.lastSeenAt && Date.now() - meta.lastSeenAt < 10_000;
  res.json({
    status: agent.status,
    last_seen_at: meta.lastSeenAt,
    connected,
  });
});
