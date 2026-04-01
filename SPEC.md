# Sigil Technical Specification

**Version:** 0.1.0 (Draft)
**License:** Apache 2.0

---

## Table of Contents

1. [Concepts](#1-concepts)
2. [Enrollment Protocol](#2-enrollment-protocol)
3. [Authentication Flow](#3-authentication-flow)
4. [CLI Interface](#4-cli-interface)
5. [Identity Binary Internals](#5-identity-binary-internals)
5a. [Builder Service API](#5a-builder-service-api)
6. [Rotation](#6-rotation)
7. [Revocation](#7-revocation)
8. [Server Storage Schema](#8-server-storage-schema)
9. [Integration Guide](#9-integration-guide)
10. [Security Properties](#10-security-properties)
11. [Out of Scope (v1)](#11-out-of-scope-v1)

---

## 1. Concepts

| Term | Definition |
|------|-----------|
| **Enrollment Token** | One-time secret issued by the server to authorize a single enrollment. Valid 30 minutes. Burned after use. |
| **Identity Binary** | Compiled Go binary with an Ed25519 private key embedded and obfuscated. Exposes a CLI for signing challenges. The private key never exists as a readable file on disk. |
| **Key Fingerprint** | SHA256 hash of the public key. Used to verify enrollment completed correctly. |
| **Challenge** | Random 32-byte nonce issued by the server. Valid once. Expires in 30 seconds. |
| **Session Token** | Short-lived JWT (5 min) issued after successful challenge-response. Used for subsequent API calls. |

---

## 2. Enrollment Protocol

### Actors

- **User** — Owner of the account in the host system
- **Agent** — AI agent running on the user's machine
- **Server** — Host system running the Sigil server SDK

### Prerequisites

The host system has created an agent via `POST /sigil/agents` (see below) and provided the `enrollment_token` to the user.

### Agent Creation

Before enrollment can happen, the host system creates an agent record and receives an enrollment token.

```
User → Server:    POST /sigil/agents
                  Headers: Authorization: Bearer <user_session_token>
                  Body: {
                    "name": "my-coding-agent",
                    "user_id": "<external_user_id>"
                  }

Server:           1. Create agent record (status: "pending_enrollment")
                  2. Generate enrollment_token (random, 30 min TTL)
                  3. Store SHA256(token) — never store plaintext

Server → User:    201 Created
                  {
                    "agent_id": "<uuid>",
                    "enrollment_token": "<token>",
                    "enrollment_expires_at": "ISO8601"
                  }
```

The user then provides the `enrollment_token` and server URL to the agent (e.g., via environment variable, CLI argument, or chat message). This is the **only** secret the user ever handles, and it expires in 30 minutes.

### Enrollment Flow

```
Agent → Server:   POST /sigil/enroll
                  Headers: Authorization: Bearer <enrollment_token>
                  Body: { "platform": "linux-amd64" }

Server:           1. Validate token (unused, not expired, max 30 min)
                  2. Generate Ed25519 key pair
                  3. Store public key + agent metadata
                  4. Build identity binary via builder (local or remote):
                     - Local: SDK shells out to locally installed Go + garble + UPX
                     - Remote: SDK sends POST /build to builder service (see §5a)
                     - In both cases, the builder:
                       - Embeds private key as AES-256-GCM encrypted byte array
                       - Decryption key derived from obfuscated internal constant
                       - Builds with: garble -literals -seed=random build -ldflags="-s -w"
                       - Compresses with: upx --best
                  5. Burn enrollment_token (mark used)
                  6. Return binary + metadata

Server → Agent:   200 OK
                  Content-Type: application/octet-stream
                  X-Agent-ID: <agent_id>
                  X-Key-Fingerprint: sha256:<hex>
                  Body: <binary>

Agent:            1. Save binary to configured path
                  2. chmod +x
                  3. Verify: sigil fingerprint → compare with X-Key-Fingerprint
                  4. Delete enrollment_token from memory/disk
                  5. Store agent_id in local config
```

### Enrollment Token Rules

- Single use only
- 30 minute TTL (configurable by host system)
- Bound to specific agent_id
- Second use attempt → 403 + alert to user

### Supported Platforms

| Platform | GOOS | GOARCH |
|----------|------|--------|
| linux-amd64 | linux | amd64 |
| linux-arm64 | linux | arm64 |
| darwin-amd64 | darwin | amd64 |
| darwin-arm64 | darwin | arm64 |
| windows-amd64 | windows | amd64 |

### Error Responses

| Status | Error Code | Meaning |
|--------|-----------|---------|
| 401 | `token_expired` | Enrollment token TTL exceeded |
| 403 | `already_enrolled` | Token already used. Response includes `enrolled_at` timestamp |
| 400 | `unsupported_platform` | Platform not in supported list. Response includes `supported` array |

---

## 3. Authentication Flow

### Challenge-Response

```
Agent → Server:   POST /sigil/auth/challenge
                  Body: { "agent_id": "<agent_id>" }

Server:           1. Verify agent exists and status is "active"
                  2. Generate random 32-byte nonce (base64 encoded)
                  3. Store nonce with 30-sec TTL, marked single-use

Server → Agent:   200 OK
                  {
                    "challenge": "<base64 nonce>",
                    "expires_in": 30
                  }

Agent:            Executes: sigil sign <challenge>
                  Binary internally:
                    1. Decrypts private key into memory
                    2. Signs challenge with Ed25519
                    3. Zeros key from memory
                    4. Returns base64 signature to stdout

Agent → Server:   POST /sigil/auth/verify
                  {
                    "agent_id": "<agent_id>",
                    "challenge": "<challenge>",
                    "signature": "<base64 Ed25519 signature>"
                  }

Server:           1. Find challenge (must exist, not expired, not used)
                  2. Mark challenge as used
                  3. Look up public key for agent_id
                  4. Verify Ed25519 signature
                  5. Issue session token

Server → Agent:   200 OK
                  {
                    "token": "<JWT>",
                    "expires_in": 300
                  }
```

### Using the Session Token

```
Agent → Server:   Any API call
                  Headers: Authorization: Bearer <JWT>
```

When the JWT expires, the agent requests a new challenge.

### Why Challenge-Response (not TOTP)

- Each challenge is unique — replay is impossible
- Server stores only public keys — database breach has zero impact
- No clock synchronization required between agent and server
- Challenges expire in 30 seconds — tighter window than TOTP's 30-second codes

### Error Responses

| Status | Error Code | Meaning |
|--------|-----------|---------|
| 404 | `agent_not_found` | Unknown agent_id |
| 401 | `challenge_expired` | 30-second window exceeded |
| 401 | `challenge_used` | Replay attempt detected |
| 401 | `signature_invalid` | Signature does not match stored public key |
| 403 | `agent_revoked` | Agent has been revoked by user |
| 403 | `key_expired` | Key rotation required (server-enforced policy) |

---

## 4. CLI Interface

### Commands

```bash
# One-time enrollment
sigil enroll --token <enrollment_token> --server <url>
→ Downloads and installs identity binary
→ Verifies fingerprint
→ Prints agent_id on success
→ Exit 0

# Sign a challenge (core operation)
sigil sign <base64_challenge>
→ stdout: <base64 Ed25519 signature>
→ Exit 0

# Show public key fingerprint (for verification)
sigil fingerprint
→ stdout: sha256:<hex>
→ Exit 0

# Health check
sigil health
→ stdout: OK
→ Exit 0

# Version info
sigil version
→ stdout: sigil v0.1.0 (linux-amd64)
→ Exit 0

# Server-side: initialize Sigil in a project (auto-detects builder mode)
sigil init
→ Checks for Go + garble + UPX locally
→ If found: configures local builder mode
→ If not found: prompts to pull sigil/builder Docker image
→ Writes config to ./sigil.config.json
→ Exit 0
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (details on stderr) |

### Design Principles

- All output to stdout (machine-parseable)
- Errors to stderr
- No interactive prompts
- No network calls (except `enroll`, `init`, and `auth`)
- No file reads (except the binary itself)
- Stateless — all state lives on the server

---

## 5. Identity Binary Internals

### Architecture

```
┌─────────────────────────────────────┐
│         Compiled Go Binary          │
│                                     │
│  ┌───────────────────────────────┐  │
│  │  AES-256-GCM encrypted blob  │  │
│  │  containing Ed25519 private   │  │
│  │  key (32 bytes)               │  │
│  └───────────────────────────────┘  │
│                                     │
│  ┌───────────────────────────────┐  │
│  │  Obfuscated decryption key    │  │
│  │  (garble --literals)          │  │
│  └───────────────────────────────┘  │
│                                     │
│  sign(challenge):                   │
│    1. Decrypt private key → memory  │
│    2. Ed25519 sign(challenge)       │
│    3. Zero memory                   │
│    4. Return signature              │
│                                     │
│  Properties:                        │
│    - No network calls               │
│    - No file reads                  │
│    - No dependencies                │
│    - Stateless                      │
└─────────────────────────────────────┘
```

### Build Pipeline

The build pipeline lives in a dedicated **builder** component (`/builder` in the repo), not inside the SDK. The builder can run in two modes:

**Local mode:** The SDK shells out to the builder CLI, which requires Go + garble + UPX installed on the server machine.

```bash
sigil-builder build --private-key <key_bytes> --platform linux-amd64 --output ./identity
```

**Docker mode:** The builder runs as an HTTP service (see §5a). The SDK sends a build request over HTTP.

```bash
docker run -p 8080:8080 sigil/builder
```

**Internal steps (both modes):**

```bash
# 1. Generate Go source with embedded encrypted key
sigil-builder generate --private-key <key_bytes> --output ./agent-identity/

# 2. Compile with obfuscation
garble -literals -tiny build -ldflags="-s -w" -o identity ./agent-identity/

# 3. Compress (linux and windows only — UPX crashes on macOS 13+)
upx --best identity
```

> **Note:** UPX is skipped for darwin targets due to a known crash on macOS Ventura and later (UPX issue #612). Darwin binaries rely on garble obfuscation + stripped symbols only.

### Key Protection Layers

| Layer | What it does | What it defeats |
|-------|-------------|----------------|
| AES-256-GCM encryption | Key is not plaintext in the binary | `strings`, `hexdump`, casual inspection |
| garble --literals | Decryption constant is obfuscated at compile time | Static analysis of string literals |
| Strip debug symbols | No function names, no source paths | `objdump`, `nm`, basic reverse engineering |
| UPX compression | Binary is packed | Adds unpacking step before analysis |
| Memory zeroing | Key exists in memory only during sign operation | Memory dump between operations |

### What This Does NOT Defeat

- Dynamic analysis with debugger attached (GDB, Delve)
- Runtime memory dump during sign operation
- Dedicated reverse engineering with Ghidra/IDA Pro (hours of work)
- Physical access + time + expertise

This is a **barrier**, not a **guarantee**. See README.md for the full threat model.

---

## 5a. Builder Service API

The builder service exposes a single endpoint. It accepts a private key and target platform, and returns a compiled, obfuscated identity binary.

### `POST /build`

**Request:**

```json
{
  "private_key": "<base64 Ed25519 private key, 32 bytes>",
  "platform": "linux-amd64"
}
```

**Response (success):**

```
200 OK
Content-Type: application/octet-stream
X-Binary-SHA256: <hex hash of binary>
Body: <compiled binary>
```

**Response (error):**

| Status | Error Code | Meaning |
|--------|-----------|---------|
| 400 | `unsupported_platform` | Platform not in supported list |
| 400 | `invalid_key` | Key is not valid Ed25519 private key |
| 500 | `build_failed` | Compilation or compression failed |

### Security Considerations

- The builder receives the **raw private key**. The connection between SDK and builder MUST be trusted (localhost or TLS).
- The builder should not log or persist private keys.
- In Docker mode, the builder should run on the same host or private network — never exposed to the public internet.

### Docker Image

```dockerfile
# Published as sigil/builder
docker run -p 8080:8080 sigil/builder
```

The image bundles Go, garble, and UPX. No external dependencies required.

---

## 6. Rotation

### User-Initiated Rotation

```
User → Server:    POST /sigil/agents/{agent_id}/rotate

Server:           1. Generate new enrollment_token (30 min TTL)
                  2. Set agent status to "rotating"
                  3. Current key remains valid until new enrollment completes

Server → User:    200 OK
                  {
                    "enrollment_token": "<new token>",
                    "expires_at": "ISO8601"
                  }

Agent:            Runs: sigil enroll --token <new_token> --server <url>
                  → Receives new binary with new key pair
                  → Replaces old binary
                  → Server deletes old public key
                  → Agent status set to "active"
```

### Server-Enforced Rotation (Optional)

The host system can configure a maximum key age per agent (e.g., 90 days).

When the key expires:
- Authentication returns 403 `{"error": "key_expired", "action": "rotate"}`
- The user must initiate rotation via `POST /sigil/agents/{agent_id}/rotate`
- The agent cannot authenticate until rotation is complete

### Rotation During Active Use

During rotation, the agent's status is "rotating". The **old key remains valid** until the new enrollment completes. This prevents downtime during key rotation.

Once new enrollment completes:
1. Old public key is deleted
2. New public key is active
3. Status returns to "active"

---

## 7. Revocation

### Immediate Revocation

```
User → Server:    DELETE /sigil/agents/{agent_id}/key

Server:           1. Delete public key
                  2. Invalidate all active session tokens for this agent
                  3. Set agent status to "revoked"

Server → User:    200 OK
```

All subsequent authentication attempts fail immediately with 403 `agent_revoked`.

### Re-enrollment After Revocation

```
User → Server:    POST /sigil/agents/{agent_id}/re-enroll

Server:           1. Verify agent status is "revoked"
                  2. Generate new enrollment_token (30 min TTL)
                  3. Set agent status to "pending_enrollment"

Server → User:    200 OK
                  {
                    "enrollment_token": "<new token>",
                    "expires_at": "ISO8601"
                  }
```

The agent then runs the standard enrollment flow with the new token.

---

## 8. Server Storage Schema

**Important:** No secrets are stored server-side. A database breach exposes only public keys, which are useless to an attacker.

```sql
CREATE TABLE sigil_agents (
    agent_id         UUID PRIMARY KEY,
    name             TEXT NOT NULL,
    external_user_id TEXT NOT NULL,
    public_key       BYTEA,                -- Ed25519 public key, 32 bytes. NOT SECRET.
    key_fingerprint  TEXT,                  -- sha256 hex
    platform         TEXT,
    status           TEXT DEFAULT 'pending_enrollment',
                     -- pending_enrollment | active | rotating | revoked
    enrolled_at      TIMESTAMPTZ,
    last_auth_at     TIMESTAMPTZ,
    key_expires_at   TIMESTAMPTZ,
    created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE sigil_enrollment_tokens (
    token_hash       TEXT PRIMARY KEY,      -- SHA256 of token. NEVER store plaintext.
    agent_id         UUID REFERENCES sigil_agents(agent_id),
    expires_at       TIMESTAMPTZ NOT NULL,
    used             BOOLEAN DEFAULT FALSE,
    created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE sigil_challenges (
    challenge        TEXT PRIMARY KEY,
    agent_id         UUID REFERENCES sigil_agents(agent_id),
    expires_at       TIMESTAMPTZ NOT NULL,  -- created_at + 30 sec
    used             BOOLEAN DEFAULT FALSE,
    created_at       TIMESTAMPTZ DEFAULT NOW()
);
```

### Indexes

```sql
CREATE INDEX idx_sigil_agents_user ON sigil_agents(external_user_id);
CREATE INDEX idx_sigil_agents_status ON sigil_agents(status);
CREATE INDEX idx_sigil_tokens_agent ON sigil_enrollment_tokens(agent_id);
CREATE INDEX idx_sigil_challenges_agent ON sigil_challenges(agent_id);
CREATE INDEX idx_sigil_challenges_expires ON sigil_challenges(expires_at);
```

### Cleanup

Expired challenges and used enrollment tokens should be periodically purged:

```sql
-- Run periodically (e.g., every hour)
DELETE FROM sigil_challenges WHERE expires_at < NOW();
DELETE FROM sigil_enrollment_tokens WHERE used = TRUE OR expires_at < NOW();
```

---

## 9. Integration Guide

### Server-Side SDK (Node.js)

```javascript
import { Sigil } from '@sigil/server'

const sigil = new Sigil({
  // Builder mode: local Go toolchain or remote builder service
  builder: 'local',                    // uses locally installed Go + garble + UPX
  // builder: 'http://localhost:8080', // uses Docker builder service

  // Which platforms to support for binary compilation
  platforms: ['linux-amd64', 'linux-arm64', 'darwin-arm64'],

  // Timing configuration
  challengeTTL: 30,       // seconds — challenge expiry
  sessionTTL: 300,        // seconds — JWT expiry
  enrollmentTTL: 1800,    // seconds — enrollment token expiry (30 min)

  // Database adapter (Postgres, SQLite, MySQL, etc.)
  storage: yourDbAdapter,

  // Optional: max key age for server-enforced rotation
  maxKeyAge: '90d',       // null = no enforced rotation
})

// Mount Sigil routes on your Express/Fastify/etc. app
app.post('/sigil/agents',                  sigil.createAgent)     // create agent + get enrollment token
app.post('/sigil/enroll',                  sigil.enroll)
app.post('/sigil/auth/challenge',          sigil.challenge)
app.post('/sigil/auth/verify',             sigil.verify)
app.post('/sigil/agents/:id/rotate',       sigil.rotate)
app.delete('/sigil/agents/:id/key',        sigil.revoke)
app.post('/sigil/agents/:id/re-enroll',    sigil.reEnroll)

// Middleware for protected routes
// Verifies JWT and populates req.agent
app.use('/api/*', sigil.requireAuth)

// Access verified agent identity in your route handlers
app.post('/api/invoices', sigil.requireAuth, (req, res) => {
  console.log(req.agent.id)          // verified agent UUID
  console.log(req.agent.userId)      // external user ID
  console.log(req.agent.fingerprint) // key fingerprint
})
```

### Server-Side SDK (Python)

```python
from sigil.server import Sigil

sigil = Sigil(
    builder='local',                    # or 'http://localhost:8080' for Docker builder
    platforms=['linux-amd64', 'linux-arm64', 'darwin-arm64'],
    challenge_ttl=30,
    session_ttl=300,
    enrollment_ttl=1800,
    storage=your_db_adapter,
)

# Flask example
app.add_url_rule('/sigil/agents',         view_func=sigil.create_agent, methods=['POST'])
app.add_url_rule('/sigil/enroll',         view_func=sigil.enroll,       methods=['POST'])
app.add_url_rule('/sigil/auth/challenge', view_func=sigil.challenge,    methods=['POST'])
app.add_url_rule('/sigil/auth/verify',    view_func=sigil.verify,    methods=['POST'])

# Decorator for protected routes
@app.route('/api/invoices', methods=['POST'])
@sigil.require_auth
def create_invoice():
    agent = request.agent  # verified agent identity
```

### Agent-Side Integration

The agent-side requires no SDK. It's shell commands:

```bash
# Enrollment (one time)
sigil enroll --token $ENROLLMENT_TOKEN --server https://api.example.com

# Authentication (on every API session)
AGENT_ID=$(cat ~/.sigil/agent_id)

CHALLENGE=$(curl -s -X POST https://api.example.com/sigil/auth/challenge \
  -H "Content-Type: application/json" \
  -d "{\"agent_id\":\"$AGENT_ID\"}" | jq -r .challenge)

SIGNATURE=$(sigil sign "$CHALLENGE")

TOKEN=$(curl -s -X POST https://api.example.com/sigil/auth/verify \
  -H "Content-Type: application/json" \
  -d "{\"agent_id\":\"$AGENT_ID\",\"challenge\":\"$CHALLENGE\",\"signature\":\"$SIGNATURE\"}" \
  | jq -r .token)

# Use token for all API calls (valid 5 min)
curl -H "Authorization: Bearer $TOKEN" https://api.example.com/api/...
```

### Agent-Side Helper (Optional)

For convenience, a helper wrapper can automate the challenge-response flow:

```bash
# Handles challenge → sign → verify → returns JWT
sigil auth --server https://api.example.com
→ stdout: <JWT token>
```

---

## 10. Security Properties

### What Sigil Protects Against

| Threat | Without Sigil | With Sigil |
|--------|--------------|------------|
| Prompt injection extracts credential | `echo $API_KEY` → permanent access | No readable credential exists |
| Attacker intercepts enrollment | Gets API key → permanent access | Gets burned token → useless |
| Server database breached | API keys/secrets exposed | Only public keys exposed → useless |
| Credential reuse from another machine | Works (same API key) | Fails (no binary = no signing) |
| Replay captured authentication | Works (same API key) | Fails (challenge is single-use) |

### What Sigil Does NOT Protect Against

| Threat | Why | Mitigation |
|--------|-----|-----------|
| Binary reverse-engineered offline | Obfuscation is a barrier, not a guarantee | Key rotation policy, anomaly detection |
| Persistent agent compromise | Attacker relays signatures in real-time | Human-in-the-loop approval |
| Physical machine access | Attacker copies binary + reverse engineers | Revocation, re-enrollment |

### Difficulty Scale

```
Extracting an API key from env       →  echo $API_KEY          →  seconds
Extracting an API key from config    →  cat config.json        →  seconds
Extracting a key from Sigil binary   →  Ghidra + RE skills     →  hours to days
Extracting a key from TPM            →  not possible in SW     →  ∞
```

---

## 11. Out of Scope (v1)

The following features are intentionally excluded from v1 to keep the initial implementation focused:

- **Agent-to-agent authentication** — Sigil v1 covers agent-to-server only
- **Web of trust / vouching** — No trust propagation between agents
- **TPM/HSM integration** — Future: detect and prefer hardware if available
- **Key escrow / backup** — If the binary is lost, re-enroll
- **Multi-device enrollment** — One agent = one device = one key pair
- **Rate limiting** — Host system responsibility
- **Audit logging** — Host system responsibility (Sigil provides agent identity; the host system logs actions)

---

## Appendix A: Implementation Checklist

### Server Components

- [ ] Agent creation endpoint (POST /sigil/agents) with enrollment token generation
- [ ] Agent CRUD endpoints (list, delete)
- [ ] Enrollment token validation and burn
- [ ] Go binary compilation pipeline (per platform)
- [ ] garble + UPX build chain (local + Docker builder modes)
- [ ] Challenge generation and storage (with TTL)
- [ ] Ed25519 signature verification
- [ ] JWT session token issuance
- [ ] Key rotation flow
- [ ] Revocation flow
- [ ] Database schema and migrations
- [ ] Cleanup job for expired challenges/tokens

### Identity Binary (Go)

- [ ] Ed25519 key embedding with AES-256-GCM encryption
- [ ] `sign` command — decrypt, sign, zero, output
- [ ] `fingerprint` command
- [ ] `health` command
- [ ] `version` command
- [ ] Build script with garble + UPX
- [ ] Cross-compilation for all platforms
- [ ] Tests: sign/verify round-trip

### CLI Wrapper

- [ ] `sigil enroll` — call server, download binary, verify fingerprint
- [ ] `sigil sign` — delegate to identity binary
- [ ] `sigil fingerprint` — delegate to identity binary
- [ ] `sigil health` — delegate to identity binary
- [ ] `sigil version`
- [ ] `sigil auth` — convenience wrapper for challenge-response flow (optional)

### Testing

- [ ] Enrollment: happy path, expired token, reused token, unsupported platform
- [ ] Authentication: happy path, expired challenge, reused challenge, invalid signature, revoked agent
- [ ] Rotation: during active use, after expiry
- [ ] Revocation: immediate, re-enrollment
- [ ] Binary: verify key cannot be extracted with `strings`
- [ ] Cross-platform: verify binary works on all supported platforms
