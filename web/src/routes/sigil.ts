import { Router } from 'express';
import { createRouteHandlers } from '@sigil/server';
import { sigil } from '../sigil.js';

export const sigilRouter: Router = Router();

const h = createRouteHandlers(sigil);

sigilRouter.post('/sigil/agents', h.createAgent);
sigilRouter.post('/sigil/enroll', h.enroll);
sigilRouter.post('/sigil/auth/challenge', h.challenge);
sigilRouter.post('/sigil/auth/verify', h.verify);
sigilRouter.post('/sigil/agents/:id/rotate', h.rotate);
sigilRouter.delete('/sigil/agents/:id/key', h.revoke);
sigilRouter.post('/sigil/agents/:id/re-enroll', h.reEnroll);
