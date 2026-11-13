// Shared helpers for the Pages Functions: staff accounts, sessions, admin checks,
// rate limits and the audit log. Nothing secret lives in the repo: password hashes
// and the cookie-signing key are stored in the D1 database.

const enc = new TextEncoder();
export const COOKIE = '__Host-tozzer_session';
const SESSION_HOURS = 12;
const ITER = 100000; // PBKDF2 rounds (Cloudflare's maximum)

export function json(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extra },
  });
}

export function b64url(bytes) {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromB64url(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(data)));
}

export async function safeEqual(a, b) {
  const [x, y] = await Promise.all([hmac('compare', String(a ?? '')), hmac('compare', String(b ?? ''))]);
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}

// Password hashing: "pbkdf2$<rounds>$<salt>$<hash>"
export async function hashSecret(secret, salt = crypto.getRandomValues(new Uint8Array(16))) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITER }, key, 256);
  return `pbkdf2$${ITER}$${b64url(salt)}$${b64url(bits)}`;
}
export async function checkSecret(secret, stored) {
  if (!stored || !stored.startsWith('pbkdf2$')) {
    await hashSecret(String(secret || 'x')); // same work either way, so timing reveals nothing
    return false;
  }
  const [, , salt] = stored.split('$');
  return safeEqual(await hashSecret(String(secret || ''), fromB64url(salt)), stored);
}

// Readable random strings for temporary passwords: no 0/O, 1/l/I.
const ALPHA = 'abcdefghjkmnpqrstuvwxyz23456789';
export function randomCode(groups = 3, size = 4) {
  const out = [];
  for (let g = 0; g < groups; g++) {
    const bytes = crypto.getRandomValues(new Uint8Array(size));
    out.push([...bytes].map(b => ALPHA[b % ALPHA.length]).join(''));
  }
  return out.join('-');
}

export async function getSetting(env, key, fallback = null) {
  const row = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind(key).first();
  return row ? row.value : fallback;
}
export async function setSetting(env, key, value) {
  await env.DB.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
    .bind(key, String(value)).run();
}

// Cookie-signing key: created once and kept in the database.
async function sessionSecret(env) {
  let s = await getSetting(env, 'session_secret');
  if (!s) {
    s = b64url(crypto.getRandomValues(new Uint8Array(32)));
    await env.DB.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)').bind('session_secret', s).run();
    s = await getSetting(env, 'session_secret');
  }
  return s;
}

export async function makeSessionCookie(env, user) {
  const version = await getSetting(env, 'session_version', '1');
  const payload = b64url(enc.encode(JSON.stringify({ u: user.id, sv: user.session_version, v: version, exp: Date.now() + SESSION_HOURS * 3600e3 })));
  const sig = b64url(await hmac(await sessionSecret(env), payload));
  return `${COOKIE}=${payload}.${sig}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_HOURS * 3600}`;
}
export const clearCookie = `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;

function readCookie(request) {
  const raw = request.headers.get('cookie') || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > -1 && part.slice(0, i).trim() === COOKIE) return part.slice(i + 1).trim();
  }
  return null;
}

// Returns the signed-in user row, or null. A session ends when it expires, when the
// admin signs everyone out, or when that user's password is changed, reset or removed.
export async function getSession(request, env) {
  const c = readCookie(request);
  if (!c || !c.includes('.')) return null;
  const [payload, sig] = c.split('.');
  const expect = b64url(await hmac(await sessionSecret(env), payload));
  if (!(await safeEqual(sig, expect))) return null;
  let data;
  try { data = JSON.parse(new TextDecoder().decode(fromB64url(payload))); } catch { return null; }
  if (!data || typeof data.exp !== 'number' || data.exp < Date.now()) return null;
  if (String(data.v) !== String(await getSetting(env, 'session_version', '1'))) return null;
  const user = await env.DB.prepare('SELECT id, username, session_version, offer_change, disabled, is_admin, is_manager FROM users WHERE id = ?').bind(data.u).first();
  if (!user || user.disabled || String(user.session_version) !== String(data.sv)) return null;
  return { id: user.id, name: user.username, offerChange: !!user.offer_change, isAdmin: !!user.is_admin, canManage: !!(user.is_admin || user.is_manager) };
}

// Blocks cross-site form posts: every write must be JSON and carry our header.
export function isApiWrite(request) {
  return request.headers.get('x-requested-with') === 'tracker' &&
    (request.headers.get('content-type') || '').startsWith('application/json');
}

export function clientIp(request) {
  return request.headers.get('cf-connecting-ip') || 'unknown';
}

export async function tooManyAttempts(env, ip, bucket, limit = 8, minutes = 15) {
  await env.DB.prepare('DELETE FROM login_attempts WHERE at < ?').bind(Date.now() - 24 * 3600e3).run();
  const row = await env.DB.prepare('SELECT COUNT(*) AS n FROM login_attempts WHERE ip = ? AND bucket = ? AND at >= ?')
    .bind(ip, bucket, Date.now() - minutes * 60e3).first();
  return (row?.n || 0) >= limit;
}
export async function recordFailure(env, ip, bucket) {
  await env.DB.prepare('INSERT INTO login_attempts (ip, bucket, at) VALUES (?, ?, ?)').bind(ip, bucket, Date.now()).run();
}

// Admin-page calls need a signed-in owner (is_admin) or manager login; ownerOnly calls need the owner.
// Writes must also come from our page as JSON.
export async function adminGuard(request, env, { ownerOnly = false } = {}) {
  if (request.headers.get('x-requested-with') !== 'tracker') return { res: json({ error: 'bad_request' }, 400) };
  if (request.method !== 'GET' && !isApiWrite(request)) return { res: json({ error: 'bad_request' }, 400) };
  const s = await getSession(request, env);
  if (!s) return { res: json({ error: 'signed_out' }, 401) };
  if (!s.canManage || (ownerOnly && !s.isAdmin)) return { res: json({ error: 'not_admin' }, 403) };
  return { s };
}

export const USERNAME = /^[a-z0-9][a-z0-9._-]{2,31}$/;
export function cleanUsername(s) { return String(s || '').trim().toLowerCase(); }
export function passwordProblem(p) {
  p = String(p || '');
  if (p.length < 10) return 'Use at least 10 characters.';
  if (p.length > 200) return 'Use 200 characters or fewer.';
  return null;
}

export async function audit(env, who, action, patientId = null, detail = null) {
  await env.DB.prepare('INSERT INTO audit (at, who, action, patient_id, detail) VALUES (?, ?, ?, ?, ?)')
    .bind(new Date().toISOString(), who, action, patientId, detail).run();
}
