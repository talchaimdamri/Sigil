import { html, layout, type Html } from './layout.js';
import type { AgentRow } from '../db.js';
import type { User } from '../db.js';

function statusBadge(status: string, lastSeenAt: number | null): Html {
  if (status === 'revoked') return html`<span class="status revoked">revoked</span>`;
  if (status === 'pending_enrollment' || status === 'rotating')
    return html`<span class="status pending">pending</span>`;
  if (status === 'active') {
    if (lastSeenAt && Date.now() - lastSeenAt < 10_000) {
      return html`<span class="status connected">connected</span>`;
    }
    return html`<span class="status idle">idle</span>`;
  }
  return html`<span class="status">${status}</span>`;
}

export function dashboardPage(user: User, agents: AgentRow[]): Html {
  return layout(
    'Agents',
    user,
    html`
      <h1>Your agents</h1>
      <form action="/agents" method="post" class="row" style="margin-bottom: 1.25rem;">
        <input type="text" name="name" required autocomplete="off"
               pattern="[A-Za-z0-9_.-]{1,32}" minlength="1" maxlength="32"
               placeholder="agent name (e.g. laptop)" />
        <button type="submit">Create agent</button>
      </form>

      ${agents.length === 0
        ? html`<p class="muted">No agents yet. Create one to get a code snippet for your agent machine.</p>`
        : html`<div>
            ${agents.map(
              (a) => html`<a href="/agents/${a.id}" style="text-decoration: none; color: inherit;">
                <div class="agent-row">
                  <div>
                    <div style="font-weight: 500;">${a.name}</div>
                    <div class="muted" style="font-size: 0.8rem; margin-top: 0.15rem;">
                      <code>${a.codeword}</code>
                      ${a.platform ? html` · ${a.platform}` : null}
                    </div>
                  </div>
                  ${statusBadge(a.status, a.lastSeenAt)}
                </div>
              </a>`,
            )}
          </div>`}
    `,
  );
}
