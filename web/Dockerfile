# Build context must be the repo root (Railway: dockerfilePath = web/Dockerfile).
# Stages:
#   1. go-builder   — compiles sigil-builder (Go) from builder/
#   2. sdk-builder  — builds @sigil/server dist/ from sdk/node/
#   3. web-builder  — installs web/ deps (resolves file:../sdk/node) and compiles TS
#   4. runtime      — Node 20 + Go toolchain (needed by sigil-builder at run time)

# ─── Stage 1: Go ──────────────────────────────────────────────────────
FROM golang:1.24-alpine AS go-builder
WORKDIR /src/builder
COPY builder/go.mod builder/go.sum* ./
RUN go mod download
COPY builder ./
RUN go build -trimpath -ldflags="-s -w" -o /out/sigil-builder ./cmd/sigil-builder/

# ─── Stage 2: SDK (@sigil/server) ─────────────────────────────────────
FROM node:20-alpine AS sdk-builder
RUN apk add --no-cache python3 make g++
WORKDIR /app/sdk/node
COPY sdk/node/package.json sdk/node/package-lock.json* ./
RUN npm ci --include=dev
COPY sdk/node ./
RUN npm run build

# ─── Stage 3: web ─────────────────────────────────────────────────────
FROM node:20-alpine AS web-builder
RUN apk add --no-cache python3 make g++
WORKDIR /app
# Bring in the already-built SDK so file:../sdk/node resolves
COPY --from=sdk-builder /app/sdk /app/sdk
WORKDIR /app/web
COPY web/package.json web/package-lock.json* ./
# --install-links forces file:../sdk/node to be copied (not symlinked)
# so we can ship node_modules alone to the runtime stage.
RUN npm install --install-links=true --include=dev --no-audit --no-fund
COPY web ./
RUN npm run build

# ─── Stage 4: runtime ─────────────────────────────────────────────────
FROM node:20-alpine AS runtime
# sigil-builder shells out to `go build` at request time, so Go must be present.
RUN apk add --no-cache go git ca-certificates wget
COPY --from=go-builder /out/sigil-builder /usr/local/bin/sigil-builder
COPY --from=go-builder /src/builder/template /template
ENV SIGIL_TEMPLATE_DIR=/template \
    NODE_ENV=production \
    PORT=8080 \
    DATA_DIR=/data \
    GOCACHE=/tmp/go-cache \
    GOPATH=/tmp/go
WORKDIR /app
COPY --from=web-builder /app/web/dist /app/dist
COPY --from=web-builder /app/web/node_modules /app/node_modules
COPY --from=web-builder /app/web/package.json /app/package.json
RUN mkdir -p /data /tmp/go-cache /tmp/go
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -q --spider http://127.0.0.1:$PORT/healthz || exit 1
CMD ["node", "--enable-source-maps", "dist/index.js"]
