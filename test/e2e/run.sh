#!/bin/bash
# E2E test for Sigil: create agent → enroll → authenticate → call protected endpoint
set -e

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export PATH="$ROOT/bin:$HOME/go/bin:$PATH"

SERVER_URL="http://localhost:3456"
SIGIL_DIR="$ROOT/test/e2e/.sigil-test"

# Clean up from previous runs
rm -rf "$SIGIL_DIR"
export HOME_BACKUP="$HOME"

echo "=== Step 1: Start test server ==="
cd "$ROOT/sdk/node"
export NODE_PATH="$ROOT/sdk/node/node_modules"
export PATH="$ROOT/bin:$HOME/go/bin:$PATH"
npx tsx "$ROOT/test/e2e/server.ts" &
SERVER_PID=$!
cd "$ROOT"
sleep 3

# Ensure cleanup on exit
cleanup() {
  kill $SERVER_PID 2>/dev/null || true
  rm -rf "$SIGIL_DIR"
}
trap cleanup EXIT

# Check server is running
if ! curl -s "$SERVER_URL/sigil/auth/challenge" -X POST -H "Content-Type: application/json" -d '{"agent_id":"test"}' > /dev/null 2>&1; then
  echo "FAIL: Server not responding"
  exit 1
fi
echo "Server is running."

echo ""
echo "=== Step 2: Create agent ==="
CREATE_RESPONSE=$(curl -s -X POST "$SERVER_URL/sigil/agents" \
  -H "Content-Type: application/json" \
  -d '{"name": "test-agent", "user_id": "user-123"}')

echo "Response: $CREATE_RESPONSE"

AGENT_ID=$(echo "$CREATE_RESPONSE" | jq -r .agent_id)
ENROLLMENT_TOKEN=$(echo "$CREATE_RESPONSE" | jq -r .enrollment_token)

if [ "$AGENT_ID" = "null" ] || [ -z "$AGENT_ID" ]; then
  echo "FAIL: No agent_id in response"
  exit 1
fi
echo "Agent created: $AGENT_ID"
echo "Enrollment token: ${ENROLLMENT_TOKEN:0:16}..."

echo ""
echo "=== Step 3: Enroll agent ==="
# Override HOME so sigil CLI writes to our test directory
export HOME="$ROOT/test/e2e/.home"
mkdir -p "$HOME"

sigil enroll --token "$ENROLLMENT_TOKEN" --server "$SERVER_URL"
ENROLL_EXIT=$?

if [ $ENROLL_EXIT -ne 0 ]; then
  echo "FAIL: Enrollment failed"
  exit 1
fi
echo ""
echo "Enrollment succeeded!"

echo ""
echo "=== Step 4: Verify identity binary ==="
echo "Fingerprint: $(sigil fingerprint)"
echo "Health: $(sigil health)"
echo "Version: $(sigil version)"

echo ""
echo "=== Step 5: Authenticate ==="
JWT=$(sigil auth --server "$SERVER_URL")

if [ -z "$JWT" ]; then
  echo "FAIL: No JWT received"
  exit 1
fi
echo "JWT received: ${JWT:0:50}..."

echo ""
echo "=== Step 6: Call protected endpoint ==="
WHOAMI=$(curl -s "$SERVER_URL/api/whoami" -H "Authorization: Bearer $JWT")
echo "Whoami response: $WHOAMI"

WHOAMI_ID=$(echo "$WHOAMI" | jq -r .agent.id)
if [ "$WHOAMI_ID" = "$AGENT_ID" ]; then
  echo ""
  echo "========================================="
  echo "  ALL E2E TESTS PASSED!"
  echo "  Agent ID verified: $AGENT_ID"
  echo "========================================="
else
  echo "FAIL: Agent ID mismatch: expected $AGENT_ID, got $WHOAMI_ID"
  exit 1
fi

# Restore HOME
export HOME="$HOME_BACKUP"
