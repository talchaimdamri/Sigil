import { html, layout, raw, type Html } from './layout.js';
import type { User } from '../db.js';
import type { Agent } from '@sigil/server';

interface AgentDetailProps {
  user: User;
  agent: Agent;
  codeword: string;
  lastSeenAt: number | null;
  enrollmentToken: string | null;
  publicUrl: string;
}

export function agentDetailPage(props: AgentDetailProps): Html {
  const { user, agent, codeword, lastSeenAt, enrollmentToken, publicUrl } = props;
  const connected = !!lastSeenAt && Date.now() - lastSeenAt < 10_000;

  // Single self-contained block that an operator can paste into any Unix
  // shell on the agent machine. Detects platform, downloads the matching
  // sigil CLI, enrolls, authenticates, and prints the /api/whoami JSON.
  const oneShotBlock = enrollmentToken
    ? [
        `# 1. Detect platform and download the sigil CLI`,
        `OS=$(uname | tr '[:upper:]' '[:lower:]')`,
        `ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')`,
        `curl -fsSL -o /tmp/sigil "${publicUrl}/bin/sigil-$OS-$ARCH" && chmod +x /tmp/sigil`,
        ``,
        `# 2. Enroll this machine (one-shot token, 30-min TTL)`,
        `/tmp/sigil enroll --server ${publicUrl} --token ${enrollmentToken}`,
        ``,
        `# 3. Authenticate and fetch /api/whoami — codeword should be "${codeword}"`,
        `JWT=$(/tmp/sigil auth --server ${publicUrl})`,
        `curl -s -H "Authorization: Bearer $JWT" ${publicUrl}/api/whoami`,
      ].join('\n')
    : null;

  // For agents already enrolled (e.g. after first run, token burned).
  const verifyOnlyBlock = [
    `# This machine has already enrolled. Just re-auth and check /api/whoami.`,
    `JWT=$(/tmp/sigil auth --server ${publicUrl})`,
    `curl -s -H "Authorization: Bearer $JWT" ${publicUrl}/api/whoami`,
  ].join('\n');

  return layout(
    agent.name,
    user,
    html`
      <p style="margin-bottom: 0.5rem;">
        <a href="/">← all agents</a>
      </p>
      <h1>${agent.name}</h1>
      <div class="row" style="gap: 0.75rem; margin-bottom: 1.25rem;">
        <span id="agent-status" class="status ${raw(connected ? 'connected' : agent.status === 'active' ? 'idle' : 'pending')}">
          ${connected ? 'connected' : agent.status === 'pending_enrollment' || agent.status === 'rotating' ? 'pending' : agent.status === 'active' ? 'idle' : agent.status}
        </span>
        <span id="agent-last-seen" class="muted" style="font-size: 0.85rem;">
          ${lastSeenAt ? html`last seen ${relative(lastSeenAt)}` : html`not connected yet`}
        </span>
      </div>

      <h2>Codeword</h2>
      <div class="codeword">${codeword}</div>
      <p class="muted" style="margin-top: 0.5rem;">
        This word is unique to this agent. When the agent hits <code>/api/whoami</code>,
        the server echoes this word back. If it doesn't match what you see here,
        the agent isn't talking to this server.
      </p>

      <h2>How to connect this agent</h2>
      <div class="callout">
        <strong>What this does.</strong> Paste the block below into a shell on the machine
        you want to turn into an agent (for example, the host of an AI coding agent).
        It downloads a small binary called <code>sigil</code>, enrolls this machine
        with the server (generating a cryptographic key pair inside a compiled binary,
        never exposed as plaintext), and then asks the server
        <em>"who am I?"</em>. The response should contain the codeword above.
      </div>

      ${enrollmentToken
        ? html`
            <h3 style="font-size: 0.95rem; margin-top: 1.25rem; color: #9aa4b2;">One block, pastes as-is:</h3>
            <pre><code>${oneShotBlock}</code></pre>
            <p class="muted" style="font-size: 0.8rem;">
              Runs on macOS or Linux (amd64 / arm64). The <code>--token</code> is one-shot
              and burns the moment enrollment succeeds; you'll then see a JSON response
              whose <code>codeword</code> field must equal <code>${codeword}</code>.
            </p>
          `
        : html`
            <h3 style="font-size: 0.95rem; margin-top: 1.25rem; color: #9aa4b2;">Already enrolled — just verify:</h3>
            <pre><code>${verifyOnlyBlock}</code></pre>
            <p class="muted" style="font-size: 0.8rem;">
              Enrollment tokens are one-shot and expire after 30 minutes. To re-issue,
              revoke this agent below and create a new one.
            </p>
          `}

      <h2>Expected response</h2>
      <pre><code>{
  "username":   "${user.name}",
  "agent_name": "${agent.name}",
  "codeword":   "${codeword}",
  "server":     "${new URL(publicUrl).host}",
  "fingerprint":"sha256:…",
  "agent_id":   "${agent.id}"
}</code></pre>
      <p class="muted" style="margin-top: 0.35rem;">
        If <code>codeword</code> matches the big yellow word above, the agent has
        successfully proven (via Ed25519 signature on a server-issued challenge)
        that it is talking to this server and this account.
      </p>

      <h2 style="margin-top: 2rem;">Danger zone</h2>
      <form action="/agents/${agent.id}/delete" method="post"
            onsubmit="return confirm('Revoke and delete this agent?');">
        <button type="submit" class="danger">Revoke agent</button>
      </form>

      <script>
        (function () {
          var id = ${raw(JSON.stringify(agent.id))};
          async function poll() {
            try {
              var r = await fetch('/agents/' + id + '/status.json', { cache: 'no-store' });
              if (!r.ok) return;
              var j = await r.json();
              var el = document.getElementById('agent-status');
              var seen = document.getElementById('agent-last-seen');
              if (!el || !seen) return;
              el.className = 'status ' + (j.connected ? 'connected' : j.status === 'active' ? 'idle' : 'pending');
              el.textContent = j.connected ? 'connected' : (j.status === 'pending_enrollment' || j.status === 'rotating') ? 'pending' : j.status === 'active' ? 'idle' : j.status;
              seen.textContent = j.last_seen_at ? ('last seen ' + fmtAgo(j.last_seen_at)) : 'not connected yet';
            } catch (e) {}
          }
          function fmtAgo(ts) {
            var s = Math.max(0, Math.floor((Date.now() - ts) / 1000));
            if (s < 60) return s + 's ago';
            if (s < 3600) return Math.floor(s / 60) + 'm ago';
            return Math.floor(s / 3600) + 'h ago';
          }
          setInterval(poll, 2000);
        })();
      </script>
    `,
  );
}

function relative(ts: number): string {
  const s = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}
