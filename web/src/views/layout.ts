function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export type Html = { __html: string };

function isHtml(x: unknown): x is Html {
  return typeof x === 'object' && x !== null && '__html' in (x as object);
}

export function raw(s: string): Html {
  return { __html: s };
}

export function html(strings: TemplateStringsArray, ...values: unknown[]): Html {
  let out = '';
  for (let i = 0; i < strings.length; i++) {
    out += strings[i];
    if (i < values.length) {
      const v = values[i];
      if (v == null || v === false) continue;
      if (isHtml(v)) {
        out += v.__html;
      } else if (Array.isArray(v)) {
        for (const item of v) {
          if (isHtml(item)) out += item.__html;
          else if (item != null && item !== false) out += escapeHtml(String(item));
        }
      } else {
        out += escapeHtml(String(v));
      }
    }
  }
  return { __html: out };
}

const CSS = `
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    margin: 0; background: #0f1115; color: #e7ebf0; line-height: 1.5; }
  main { max-width: 760px; margin: 0 auto; padding: 2rem 1.25rem; }
  h1, h2 { color: #fff; letter-spacing: -0.01em; }
  h1 { font-size: 1.5rem; margin: 0 0 1.5rem; }
  h2 { font-size: 1.1rem; margin: 1.75rem 0 0.75rem; color: #9aa4b2; font-weight: 500; }
  a { color: #7cc4ff; text-decoration: none; }
  a:hover { text-decoration: underline; }
  header { border-bottom: 1px solid #1e2230; padding: 1rem 1.25rem;
    display: flex; justify-content: space-between; align-items: center;
    background: #13161c; }
  header .brand { font-weight: 600; color: #fff; }
  header .user { color: #9aa4b2; font-size: 0.9rem; }
  header form { display: inline; margin-left: 0.75rem; }
  input[type=text] { width: 100%; padding: 0.6rem 0.75rem; background: #1a1e27;
    border: 1px solid #2a303d; border-radius: 6px; color: #e7ebf0;
    font: inherit; }
  input[type=text]:focus { outline: none; border-color: #7cc4ff; }
  button { cursor: pointer; padding: 0.55rem 1rem; background: #2d6cdf;
    border: 0; border-radius: 6px; color: #fff; font: inherit; font-weight: 500; }
  button:hover { background: #3a78e8; }
  button.danger { background: #42252b; color: #ffb4b4; }
  button.danger:hover { background: #5a2b35; }
  button.ghost { background: transparent; color: #9aa4b2; }
  pre { background: #1a1e27; border: 1px solid #2a303d; border-radius: 6px;
    padding: 0.85rem 1rem; overflow-x: auto; font-size: 0.85rem;
    color: #cfd4dd; margin: 0.25rem 0; }
  code { font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace; }
  .codeword { font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
    font-size: 1.75rem; font-weight: 600; color: #ffd479; letter-spacing: 0.01em;
    padding: 1rem 1.25rem; background: #1a1e27; border: 1px solid #2a303d;
    border-radius: 6px; text-align: center; }
  .row { display: flex; gap: 0.5rem; align-items: center; }
  .muted { color: #9aa4b2; font-size: 0.9rem; }
  .agent-row { display: flex; justify-content: space-between; align-items: center;
    padding: 0.85rem 1rem; background: #13161c; border: 1px solid #1e2230;
    border-radius: 6px; margin-bottom: 0.5rem; }
  .agent-row:hover { border-color: #2a303d; }
  .status { display: inline-block; padding: 0.15rem 0.55rem; border-radius: 10px;
    font-size: 0.75rem; font-weight: 500; }
  .status.pending { background: #3d2f13; color: #ffcf7a; }
  .status.active { background: #143a2a; color: #6fe4ad; }
  .status.revoked { background: #3a1c1c; color: #ff9a9a; }
  .status.connected { background: #144030; color: #74efb0; }
  .status.idle { background: #1c242d; color: #9aa4b2; }
  .callout { padding: 1rem; background: #132238; border: 1px solid #1a3960;
    border-radius: 6px; margin: 1rem 0; color: #c7d8ef; font-size: 0.9rem; }
`;

export function layout(title: string, user: { name: string } | null, body: Html): Html {
  return html`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${title} · Sigil</title>
    <style>${raw(CSS)}</style>
  </head>
  <body>
    ${user
      ? html`<header>
          <div class="brand">Sigil</div>
          <div class="user">
            ${user.name}
            <form action="/logout" method="post"><button class="ghost" type="submit">logout</button></form>
          </div>
        </header>`
      : html`<header><div class="brand">Sigil</div></header>`}
    <main>${body}</main>
  </body>
</html>`;
}

export function send(res: import('express').Response, doc: Html, status = 200): void {
  res.status(status).type('html').send(doc.__html);
}
