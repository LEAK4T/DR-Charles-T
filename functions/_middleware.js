import { getSetting, json } from '../lib/auth.js';

// Runs on every request. Enforces the killswitch, then adds security headers.
const ALWAYS_OPEN = [/^\/admin(\.html)?\/?$/, /^\/api\/admin\//];

const OFFLINE_PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Temporarily unavailable</title>
<style>:root{color-scheme:light dark}body{margin:0;min-height:100vh;display:grid;place-items:center;font:16px system-ui,-apple-system,sans-serif;background:#F3F8FB;color:#182838;padding:16px}
@media (prefers-color-scheme:dark){body{background:#121B25;color:#EAF1F7}}main{max-width:32rem}h1{font-size:1.4rem;margin:0 0 8px}p{margin:0;opacity:.8;line-height:1.5}</style></head>
<body><main><h1>This site is temporarily unavailable</h1><p>The patient tracker has been taken offline by the office. Please contact the office manager.</p></main></body></html>`;

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  if (!ALWAYS_OPEN.some(r => r.test(url.pathname))) {
    let offline = false;
    try { offline = (await getSetting(env, 'offline', '0')) === '1'; }
    catch { offline = true; } // database unreachable: fail closed
    if (offline) {
      return withHeaders(url.pathname.startsWith('/api/')
        ? json({ error: 'offline' }, 503)
        : new Response(OFFLINE_PAGE, { status: 503, headers: { 'content-type': 'text/html; charset=utf-8' } }));
    }
  }

  let res;
  try { res = await next(); } catch { res = json({ error: 'server' }, 500); }
  return withHeaders(res);
}

function withHeaders(res) {
  const r = new Response(res.body, res);
  const h = r.headers;
  h.set('X-Robots-Tag', 'noindex, nofollow');
  h.set('X-Frame-Options', 'DENY');
  h.set('X-Content-Type-Options', 'nosniff');
  h.set('Referrer-Policy', 'no-referrer');
  h.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  h.set('Strict-Transport-Security', 'max-age=31536000');
  h.set('Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; " +
    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  h.set('Cache-Control', 'no-store');
  return r;
}
