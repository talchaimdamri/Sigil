# Sigil v1 Design

## Decisions Made

1. **Language split:** Go for builder + identity binary + CLI. TypeScript and Python for server SDKs.
2. **Builder architecture:** Two modes — local (shells out to Go + garble + UPX) and Docker (HTTP service). Developer chooses via config. `sigil init` auto-detects.
3. **Database:** Abstract storage interface. Built-in adapters for Postgres and SQLite. SQLite for dev, Postgres for production.
4. **Repo structure:** Monorepo. Four components: `/builder`, `/sdk/node`, `/sdk/python`, `/cli`.
5. **Both SDKs ship in v1.** They're thin wrappers — marginal effort.
6. **Build order:** Builder + identity binary first, then both SDKs in parallel, then CLI.
7. **JWT for session tokens.** Developer provides `jwtSecret` in SDK config.
8. **Agent creation endpoint** (`POST /sigil/agents`) added. Host system creates agent and gets enrollment token. This is the entry point.

## Decisions Rejected

- **Pre-compiled template binaries** (Option C for builder) — Identical binary structures across agents. Reverse engineer does work once, extracts key from any binary with trivial script. Defeats core value proposition.
- **Go for everything** — Most agent frameworks are TS/Python. Server SDK must speak their language.
- **Opaque session tokens** — Require DB lookup per request. JWT is stateless and standard.

## Repo Structure

```
sigil/
├── builder/                  # Go — core of the project
│   ├── cmd/
│   │   └── sigil-builder/    # CLI entry point (local mode) + HTTP server (docker mode)
│   ├── internal/
│   │   ├── compiler/         # Generate Go source, run garble + UPX
│   │   ├── crypto/           # Ed25519 key generation, AES-256-GCM encryption
│   │   └── server/           # HTTP handler for POST /build
│   ├── template/             # Go source template for identity binary
│   │   ├── cmd/identity/     # main.go — sign, fingerprint, health, version
│   │   └── internal/         # Decrypt-sign-zero logic
│   ├── Dockerfile
│   ├── go.mod
│   └── go.sum
├── sdk/
│   ├── node/                 # TypeScript — @sigil/server npm package
│   │   ├── src/
│   │   │   ├── sigil.ts      # Main Sigil class
│   │   │   ├── builder.ts    # Local + remote builder client
│   │   │   ├── auth.ts       # Challenge-response + JWT
│   │   │   ├── storage/      # Abstract interface + Postgres + SQLite adapters
│   │   │   └── middleware.ts  # requireAuth for Express/Fastify
│   │   ├── package.json
│   │   └── tsconfig.json
│   └── python/               # Python — sigil-server PyPI package
│       ├── sigil/
│       │   ├── server.py     # Main Sigil class
│       │   ├── builder.py    # Local + remote builder client
│       │   ├── auth.py       # Challenge-response + JWT
│       │   ├── storage/      # Abstract interface + Postgres + SQLite adapters
│       │   └── middleware.py  # require_auth for Flask/FastAPI
│       └── pyproject.toml
├── cli/                      # Go — sigil CLI for agents + developers
│   ├── cmd/
│   │   └── sigil/            # main.go
│   ├── internal/
│   │   ├── enroll/           # Download binary, verify fingerprint
│   │   ├── auth/             # Challenge-response convenience wrapper
│   │   └── init/             # Auto-detect builder mode
│   ├── go.mod
│   └── go.sum
├── docs/
├── SPEC.md
└── README.md
```

## Component Details

### Builder + Identity Binary (Go)

**Identity Binary Template** (`builder/template/`):
- `cmd/identity/main.go` — CLI: `sign`, `fingerprint`, `health`, `version`
- `internal/keys/keys.go` — Placeholder vars for encrypted key + nonce, injected at build time
- `internal/signer/signer.go` — Decrypt-sign-zero flow: derive AES key from obfuscated constant, decrypt Ed25519 private key, sign challenge, zero memory, return base64 signature

**Compiler** (`builder/internal/compiler/`):
1. Copy template source to temp directory
2. Generate random AES-256-GCM key, encrypt private key
3. Embed encrypted key + nonce + obfuscated AES key into source
4. `garble -literals -seed=random build -ldflags="-s -w"` with target GOOS/GOARCH
5. `upx --best` on output
6. Return binary bytes

Each identity binary gets a unique random AES key. Reverse-engineering one binary doesn't help with any other.

**Builder Service** (`builder/cmd/sigil-builder/`):
- `sigil-builder build --private-key <b64> --platform linux-amd64 --output ./out` (local CLI mode)
- `sigil-builder serve --port 8080` (HTTP server for Docker mode, single `POST /build` endpoint)

### Server SDKs (TS + Python)

Thin orchestration layers. Identical responsibilities:

**Storage interface** — four operation groups:
- `agents.*` — CRUD for agent records
- `enrollmentTokens.*` — Create, validate (unused + not expired), burn
- `challenges.*` — Create with 30s TTL, validate (unused + not expired), burn
- `cleanup()` — Purge expired challenges and burned tokens

Built-in adapters: Postgres and SQLite. Auto-create tables on first use.

**Route handlers** (framework-agnostic):
- `createAgent` — Create agent record, generate enrollment token
- `enroll` — Validate token, generate keypair, call builder, store public key, return binary
- `challenge` — Validate agent active, generate nonce, store, return
- `verify` — Validate challenge, verify Ed25519 signature, issue JWT
- `rotate` — Generate new enrollment token, set status "rotating"
- `revoke` — Delete public key, invalidate sessions, set status "revoked"
- `reEnroll` — Verify status "revoked", generate new enrollment token

**Middleware** (`requireAuth`): Verify JWT, populate request with agent identity.

Framework wrappers for Express/Fastify (TS), Flask/FastAPI (Python).

### CLI (Go)

Single binary, all platforms.

**For developers:**
- `sigil init` — Auto-detect builder mode, write `sigil.config.json`

**For agents:**
- `sigil enroll --token <token> --server <url>` — Download binary, verify fingerprint, save to `~/.sigil/`
- `sigil sign <challenge>` — Delegate to identity binary
- `sigil fingerprint` — Delegate to identity binary
- `sigil health` — Delegate to identity binary
- `sigil version` — Print CLI version
- `sigil auth --server <url>` — Convenience: challenge + sign + verify, print JWT

## End-to-End Flow

```
SETUP (once, by developer)
  1. Install SDK: npm install @sigil/server
  2. Run: sigil init → detects builder mode → writes sigil.config.json
  3. Mount routes, provide jwtSecret + storage adapter

AGENT CREATION (per agent, by host system)
  4. POST /sigil/agents { name, user_id } → { agent_id, enrollment_token }
  5. User gives enrollment_token to agent

ENROLLMENT (once per agent)
  6. sigil enroll --token <token> --server <url>
     → Server validates token, generates Ed25519 keypair
     → Builder compiles obfuscated identity binary
     → Server stores public key, burns token
     → Agent saves binary to ~/.sigil/

AUTHENTICATION (every session)
  7. sigil auth --server <url>
     → Request challenge → sign with identity binary → verify → JWT (5 min)
  8. Use JWT: Authorization: Bearer <jwt>
  9. JWT expires → repeat step 7
```

## Build Order

1. Builder + Identity Binary (Go)
2. TS SDK + Python SDK (parallel)
3. CLI
