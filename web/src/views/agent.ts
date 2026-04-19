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

  const enrollCmd = enrollmentToken
    ? `sigil enroll --server ${publicUrl} --token ${enrollmentToken}`
    : null;

  const verifyCmd = [
    `JWT=$(sigil auth --server ${publicUrl})`,
    `curl -s -H "Authorization: Bearer $JWT" ${publicUrl}/api/whoami`,
  ].join('\n');

  const connected = !!lastSeenAt && Date.now() - lastSeenAt < 10_000;

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
        This should appear in the agent's <code>whoami</code> response. If it doesn't match,
        the agent is not talking to this server.
      </p>

      ${enrollCmd
        ? html`
            <h2>1. Enroll on the agent machine</h2>
            <p class="muted">Run this where your agent lives. Token is one-shot and expires in 30 minutes.</p>
            <pre><code>${enrollCmd}</code></pre>
          `
        : null}

      <h2>${agent.status === 'active' ? '1' : '2'}. Verify connection</h2>
      <p class="muted">Authenticates and hits <code>/api/whoami</code>.</p>
      <pre><code>${verifyCmd}</code></pre>

      <div class="callout">
        Expected response: <code>{ "username": "${user.name}", "agent_name": "${agent.name}", "codeword": "${codeword}", ... }</code>.
        The codeword must match the one above.
      </div>

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
