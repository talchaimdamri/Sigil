import { Router } from 'express';
import { upsertUser } from '../db.js';
import { setSession, clearSession, readUser } from '../session.js';
import { loginPage } from '../views/login.js';
import { send } from '../views/layout.js';

export const authRouter: Router = Router();

authRouter.get('/login', (req, res) => {
  if (readUser(req)) {
    res.redirect('/');
    return;
  }
  send(res, loginPage());
});

authRouter.post('/login', (req, res) => {
  const rawName = String(req.body?.name ?? '').trim();
  if (!/^[A-Za-z0-9_.-]{1,32}$/.test(rawName)) {
    send(res, loginPage('name must be 1-32 chars of letters, digits, . _ -'), 400);
    return;
  }
  const user = upsertUser(rawName);
  setSession(res, user.id);
  res.redirect('/');
});

authRouter.post('/logout', (_req, res) => {
  clearSession(res);
  res.redirect('/login');
});
