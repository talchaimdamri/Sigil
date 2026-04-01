import type { Sigil } from './sigil.js';

export function createMiddleware(sigil: Sigil) {
  return async (req: any, res: any, next: any) => {
    const authHeader = req.headers?.authorization || req.headers?.Authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'missing_token' });
      return;
    }
    try {
      const agent = await sigil.verifyJWT(authHeader.slice(7));
      req.agent = { id: agent.agentId, userId: agent.userId, fingerprint: agent.fingerprint };
      next();
    } catch {
      res.status(401).json({ error: 'invalid_token' });
    }
  };
}

export function createRouteHandlers(sigil: Sigil) {
  return {
    createAgent: async (req: any, res: any) => {
      try {
        const result = await sigil.createAgent({ name: req.body.name, userId: req.body.user_id });
        res.status(201).json({
          agent_id: result.agentId,
          enrollment_token: result.enrollmentToken,
          enrollment_expires_at: result.enrollmentExpiresAt.toISOString(),
        });
      } catch (e: any) {
        handleError(res, e);
      }
    },
    enroll: async (req: any, res: any) => {
      try {
        const token = req.headers.authorization?.replace('Bearer ', '');
        const result = await sigil.enroll(token, req.body.platform);
        res.set('X-Agent-ID', result.agentId);
        res.set('X-Key-Fingerprint', result.fingerprint);
        res.set('Content-Type', 'application/octet-stream');
        res.send(result.binary);
      } catch (e: any) {
        handleError(res, e);
      }
    },
    challenge: async (req: any, res: any) => {
      try {
        const result = await sigil.challenge(req.body.agent_id);
        res.json({ challenge: result.challenge, expires_in: result.expiresIn });
      } catch (e: any) {
        handleError(res, e);
      }
    },
    verify: async (req: any, res: any) => {
      try {
        const result = await sigil.verify(req.body.agent_id, req.body.challenge, req.body.signature);
        res.json({ token: result.token, expires_in: result.expiresIn });
      } catch (e: any) {
        handleError(res, e);
      }
    },
    rotate: async (req: any, res: any) => {
      try {
        const result = await sigil.rotate(req.params.id);
        res.json({ enrollment_token: result.enrollmentToken, expires_at: result.expiresAt.toISOString() });
      } catch (e: any) {
        handleError(res, e);
      }
    },
    revoke: async (req: any, res: any) => {
      try {
        await sigil.revoke(req.params.id);
        res.json({ ok: true });
      } catch (e: any) {
        handleError(res, e);
      }
    },
    reEnroll: async (req: any, res: any) => {
      try {
        const result = await sigil.reEnroll(req.params.id);
        res.json({ enrollment_token: result.enrollmentToken, expires_at: result.expiresAt.toISOString() });
      } catch (e: any) {
        handleError(res, e);
      }
    },
  };
}

function handleError(res: any, e: any) {
  if (e.name === 'SigilError') {
    res.status(e.statusCode).json({ error: e.code });
  } else {
    res.status(500).json({ error: 'internal_error' });
  }
}
