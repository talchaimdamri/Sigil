# Sigil Web

Minimal public test server for Sigil. Name-only login, per-agent codeword, single-container
deploy to Railway. No passwords, no email, no OTP.

## What it does

1. **Login** with a name (no password). Cookie-signed session.
2. **Create agent** in the dashboard — server calls `sigil.createAgent()`, generates a
   two-word codeword (e.g. `rosy-hoare`), shows a `sigil enroll ...` command and the codeword.
3. **Agent runs** `sigil enroll` then `sigil auth`, gets a JWT.
4. **Agent calls `/api/whoami`** (Sigil JWT-protected) and receives
   `{ username, agent_name, codeword, server, fingerprint }`.
5. **User eyeballs** the codeword returned by the agent against the dashboard —
   they should match. If they don't, the agent isn't talking to this server.

The codeword is the user-visible trust anchor; the cryptographic anchor is the
Ed25519 signature on the challenge (already handled by the SDK).

## Local development

```bash
# One-time: build the SDK so file:../sdk/node can resolve
(cd ../sdk/node && npm ci && npm run build)

# Install + run
cd web
npm install
# Needs sigil-builder on PATH and SIGIL_TEMPLATE_DIR pointing at builder/template
export PATH="$(cd .. && pwd)/bin:$PATH"
export SIGIL_TEMPLATE_DIR="$(cd .. && pwd)/builder/template"
npm run dev
# → http://localhost:3000
```

Sign in → create an agent → paste the enroll command into a second shell:

```bash
export HOME=/tmp/sigil-agent-scratch
export PATH="$(pwd)/bin:$PATH"  # from repo root
sigil enroll --server http://localhost:3000 --token <paste-from-ui>
JWT=$(sigil auth --server http://localhost:3000)
curl -s -H "Authorization: Bearer $JWT" http://localhost:3000/api/whoami | jq .
```

The `codeword` field should match the one on the agent detail page.

## Environment variables

| Var              | Required    | Default (dev)              | Notes |
| ---------------- | ----------- | -------------------------- | ----- |
| `PORT`           | no          | `3000`                     | Railway injects automatically |
| `PUBLIC_URL`     | prod yes    | `http://localhost:$PORT`   | Used in the copy-paste commands shown to the user |
| `DATA_DIR`       | prod yes    | `./data`                   | SQLite file + any future state |
| `JWT_SECRET`     | prod yes    | auto-generated (ephemeral) | 32+ bytes. Stable across restarts or JWTs invalidate |
| `SESSION_SECRET` | prod yes    | auto-generated (ephemeral) | 32+ bytes. Stable across restarts or logins are invalidated |
| `NODE_ENV`       | no          | `development`              | `production` enables Secure cookies + strict env checks |

## Deploy to Railway

Prerequisites:
- Railway account + Railway CLI: `brew install railway`
- Repo checked out locally
- Run these from the **repo root**, not from `web/`

```bash
# 1. Sign in
railway login

# 2. Create a new project and link this working copy to it
railway init                        # pick a name, e.g. "sigil-test"
railway link                        # choose the project you just created

# 3. Add a persistent volume for the SQLite file
railway volume add --mount-path /data

# 4. Set required secrets and config
railway variables set \
  JWT_SECRET="$(openssl rand -hex 32)" \
  SESSION_SECRET="$(openssl rand -hex 32)" \
  DATA_DIR=/data \
  NODE_ENV=production \
  PUBLIC_URL="https://placeholder.invalid"   # fixed after step 6

# 5. Deploy. Railway reads railway.json at the repo root → web/Dockerfile.
railway up

# 6. Generate a public hostname (note the URL it prints)
railway domain

# 7. Set PUBLIC_URL to the hostname from step 6 and redeploy
railway variables set PUBLIC_URL="https://<your-hostname>.up.railway.app"
railway redeploy
```

Verify:
```bash
curl https://<your-hostname>.up.railway.app/healthz     # → ok
open  https://<your-hostname>.up.railway.app/login
```

## Two-agent live test

On each of your real agent machines:

```bash
# 1. Install sigil CLI (copy from repo or let your agent install from source).
# 2. Get the enroll token from the dashboard for an agent you created.
# 3. Run:
sigil enroll --server https://<your-host> --token <token>
JWT=$(sigil auth --server https://<your-host>)
curl -s -H "Authorization: Bearer $JWT" https://<your-host>/api/whoami
```

Check that the `codeword` in the JSON response matches the one in the dashboard.
The dashboard status badge should flip to **connected** within 2 seconds.

Redeploy sanity check:
```bash
railway redeploy
# Log back in — your name, agents, and codewords should all survive.
```

## Architecture

- **One container**: Node server + Go toolchain + `sigil-builder` + `/template`.
- **One SQLite file** at `$DATA_DIR/sigil.db` on a Railway volume.
- **Tables**: Sigil SDK owns `sigil_agents`, `sigil_enrollment_tokens`, `sigil_challenges`.
  The web layer adds `users` and `agent_meta(codeword, last_seen_at)`.
- **Session**: HMAC-signed cookie carrying the `user.id`. No server-side session store.
- **Binary hardening**: first deploy ships `garble: false, upx: false` (faster builds,
  identical cryptographic guarantees). Flip to `true` in `web/src/sigil.ts` to enable
  the full hardening toolchain.

## Files

```
web/
  src/
    index.ts             # Express wiring
    config.ts            # env parsing
    sigil.ts             # constructs Sigil + SQLite adapter
    db.ts                # users + agent_meta tables, helpers
    session.ts           # HMAC-signed cookie
    codewords.ts         # two-word generator
    pending-tokens.ts    # in-memory cache of live enroll tokens (30min TTL)
    routes/
      auth.ts            # /login, /logout
      dashboard.ts       # /, POST /agents, POST /agents/:id/delete
      agent.ts           # /agents/:id, /agents/:id/status.json
      whoami.ts          # /api/whoami (Sigil JWT middleware)
      sigil.ts           # /sigil/* (SDK route handlers)
    views/
      layout.ts, login.ts, dashboard.ts, agent.ts
  Dockerfile
  package.json
```
