import { Router, type Request } from 'express';
import { createMiddleware } from '@sigil/server';
import { sigil, storage } from '../sigil.js';
import { getAgentMeta, getUser, touchAgentMeta } from '../db.js';
import { config } from '../config.js';

export const whoamiRouter: Router = Router();

const auth = createMiddleware(sigil);

interface AgentRequest extends Request {
  agent?: { id: string; userId: string; fingerprint: string };
}

whoamiRouter.get('/api/whoami', auth, async (req: AgentRequest, res) => {
  const agentId = req.agent?.id;
  if (!agentId) {
    res.status(401).json({ error: 'missing_agent' });
    return;
  }
  const [agent, meta] = await Promise.all([
    storage.agents.get(agentId),
    Promise.resolve(getAgentMeta(agentId)),
  ]);
  if (!agent || !meta) {
    res.status(404).json({ error: 'agent_not_found' });
    return;
  }
  const user = getUser(meta.userId);

  touchAgentMeta(agentId);

  const serverHost = new URL(config.publicUrl).host;

  res.json({
    username: user?.name ?? null,
    agent_id: agent.id,
    agent_name: agent.name,
    codeword: meta.codeword,
    server: serverHost,
    fingerprint: agent.keyFingerprint,
  });
});
