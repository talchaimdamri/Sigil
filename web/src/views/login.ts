import { html, layout, type Html } from './layout.js';

export function loginPage(error?: string): Html {
  return layout(
    'Sign in',
    null,
    html`
      <h1>Sign in</h1>
      <p class="muted">No password. Pick a name — it's only for telling your agents apart.</p>
      <form action="/login" method="post" style="margin-top: 1.25rem;">
        <div style="margin-bottom: 0.75rem;">
          <input type="text" name="name" required autofocus autocomplete="off"
                 pattern="[A-Za-z0-9_.-]{1,32}" minlength="1" maxlength="32"
                 placeholder="e.g. tal" />
        </div>
        ${error ? html`<div class="muted" style="color:#ff9a9a; margin-bottom: 0.75rem;">${error}</div>` : null}
        <button type="submit">Continue</button>
      </form>
    `,
  );
}
