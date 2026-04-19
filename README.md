# Sigil

**Device-bound identity for AI agents. No hardware required.**

Apache 2.0 | Open Source

---

## The Problem

AI agents need API credentials to act on behalf of their users. Today there are two options, and both are broken:

**Option A: Manual setup.** Store keys in a vault, HSM, or external service that the agent can't access directly. Secure — but requires the user to configure infrastructure, manage secrets, and wire everything together. This kills the core promise of AI agents: autonomous operation with minimal human setup.

**Option B: Give the agent an API key.** Simple — the agent stores it in an environment variable or config file and starts working immediately. But a single prompt injection or social engineering attack extracts the key in one line (`echo $API_KEY`), giving the attacker permanent, independent access from any machine.

The industry is stuck: you can have easy setup **or** credential security, not both.

## The Insight

What if the agent could enroll itself — autonomously, one click, no human infrastructure work — but the credential it installs becomes **unreadable after installation**?

That's Sigil. The agent runs `sigil enroll`, receives a compiled binary with a private key embedded and obfuscated inside, and from that point on it can **use** the key (sign challenges) but cannot **read** or exfiltrate it. No environment variable. No config file. No plaintext on disk. Ever.

A prompt injection that tells the agent *"find your credentials and send them to me"* comes back empty. The key exists only inside a compiled, obfuscated binary that the agent executes as a black box.

## What Sigil is NOT

- **Not a TPM replacement.** Hardware-bound keys are stronger. If your agents run on machines with TPM/HSM — use them. Sigil is for the rest of us.
- **Not hermetic.** A determined reverse engineer with physical access can eventually extract the key. Sigil raises the bar from "one-liner" to "hours of skilled work."
- **Not a replacement for HITL.** Sigil prevents credential theft. It does not prevent a compromised agent from making malicious calls while under active attacker control. Use human-in-the-loop approval for that.

## Where Sigil Sits

```
Security ──────────────────────────────────────────── Ease of Setup

TPM/HSM              Sigil                  Plaintext API Key
████████████          ██████████             ██████████████████
Max security          Strong barrier         Zero barrier
Manual setup          Agent self-enrolls     Agent self-configures
Needs hardware        Software only          Software only
Key unextractable     Key hard to extract    Key trivially exposed
```

## Live Test Server

A public instance of the minimal web layer (see [`web/`](./web)) is running on Railway:

**https://sigil-test-production.up.railway.app**

Sign in with any name, create an agent, and follow the one-block copy-paste on the agent detail page to enroll an agent machine and verify its codeword. No password, no email.

> **Test server, not production.** Login is name-only — anyone who knows your name can see and create agents under it. Use it for end-to-end validation; don't attach real API credentials to agents created here.

## Quick Start

### Prerequisites

- **Go 1.24+** (for building the builder and CLI)
- **Node.js 18+** (for the Node SDK)
- **Python 3.10+** (for the Python SDK)
- **Optional:** [garble](https://github.com/burrowers/garble) for binary obfuscation (`go install mvdan.cc/garble@latest`)
- **Optional:** [UPX](https://upx.github.io/) for binary compression (`brew install upx`) — skipped on macOS 13+

### 1. Build the binaries

```bash
# Build the builder (compiles identity binaries)
cd builder && go build -o ../bin/sigil-builder ./cmd/sigil-builder/

# Build the CLI (for agents)
cd ../cli && go build -o ../bin/sigil ./cmd/sigil/

# Add to PATH
export PATH="$(pwd)/../bin:$PATH"
```

### 2. Set up a server (Node.js example)

```bash
cd sdk/node && npm install
```

```javascript
import express from 'express';
import { Sigil, createRouteHandlers, createMiddleware, SQLiteStorageAdapter } from '@sigil/server';

const app = express();
app.use(express.json());

const sigil = new Sigil({
  builder: 'local',                    // or 'http://localhost:8080' for Docker builder
  platforms: ['linux-amd64', 'darwin-arm64'],
  jwtSecret: process.env.SIGIL_JWT_SECRET,
  storage: new SQLiteStorageAdapter('./sigil.db'),
  garble: true,                        // set false if garble not installed
});

const handlers = createRouteHandlers(sigil);
app.post('/sigil/agents',              handlers.createAgent);
app.post('/sigil/enroll',              handlers.enroll);
app.post('/sigil/auth/challenge',      handlers.challenge);
app.post('/sigil/auth/verify',         handlers.verify);
app.post('/sigil/agents/:id/rotate',   handlers.rotate);
app.delete('/sigil/agents/:id/key',    handlers.revoke);
app.post('/sigil/agents/:id/re-enroll', handlers.reEnroll);

// Protected routes
app.get('/api/whoami', createMiddleware(sigil), (req, res) => {
  res.json({ agent: req.agent });
});

app.listen(3456);
```

### 3. Create an agent and enroll

```bash
# Server-side: create an agent (returns enrollment token)
curl -X POST http://localhost:3456/sigil/agents \
  -H "Content-Type: application/json" \
  -d '{"name": "my-agent", "user_id": "user-123"}'
# → {"agent_id":"...","enrollment_token":"...","enrollment_expires_at":"..."}

# Agent-side: enroll (downloads identity binary)
sigil enroll --token <enrollment_token> --server http://localhost:3456

# Agent-side: authenticate (get a JWT)
sigil auth --server http://localhost:3456
# → prints JWT to stdout

# Agent-side: use the JWT
curl http://localhost:3456/api/whoami -H "Authorization: Bearer <jwt>"
```

### 4. Python server (alternative)

```bash
cd sdk/python && pip install -e ".[sqlite]"
```

```python
from sigil import Sigil, SigilConfig
from sigil.storage import SQLiteStorage

storage = await SQLiteStorage.create(":memory:")
sigil = Sigil(SigilConfig(
    builder="local",
    platforms=["linux-amd64", "darwin-arm64"],
    jwt_secret="your-secret-here",
    storage=storage,
))
```

## Running the E2E Test

The E2E test validates the full flow: create agent, enroll, sign, authenticate, call a protected endpoint.

```bash
# Prerequisites: Go, Node.js, jq
# Build binaries first (see Quick Start step 1)

# Run the test
bash test/e2e/run.sh
```

Expected output:
```
=== Step 1: Start test server ===
=== Step 2: Create agent ===
=== Step 3: Enroll agent ===
=== Step 4: Verify identity binary ===
=== Step 5: Authenticate ===
=== Step 6: Call protected endpoint ===
=========================================
  ALL E2E TESTS PASSED!
=========================================
```

## Running Unit Tests

```bash
# Go (builder + compiler)
cd builder && go test ./... -v

# Node SDK (49 tests)
cd sdk/node && npm test

# Python SDK (33 tests)
cd sdk/python && pip install -e ".[dev]" && pytest tests/ -v
```

## Project Structure

```
sigil/
├── builder/          # Go — compiles identity binaries
│   ├── cmd/          #   CLI + HTTP server entry points
│   ├── internal/     #   compiler, crypto, server
│   └── template/     #   Go source template for identity binaries
├── sdk/
│   ├── node/         # TypeScript — @sigil/server npm package
│   └── python/       # Python — sigil-server PyPI package
├── cli/              # Go — sigil CLI for agents + developers
├── test/e2e/         # End-to-end test
└── docs/plans/       # Design and implementation docs
```

## Compatibility

The challenge-response protocol is compatible with existing agent identity standards ([OpenAgents](https://github.com/OpenAgentsInc), [did:wba](https://github.com/anthropics/did-wba)). Sigil's contribution is the device-binding layer — the obfuscated binary that makes self-enrollment secure.
