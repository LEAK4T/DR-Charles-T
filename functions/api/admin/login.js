import { json, checkSecret, makeSessionCookie, clientIp, tooManyAttempts, recordFailure, audit, isApiWrite, cleanUsername, getSession } from '../../../lib/auth.js';

// Sign-in for the admin page. Lives under /api/admin/ so it still works while the killswitch is on.
// Only logins marked as admin get in.
export async function onRequestPost({ request, env }) {
  if (!isApiWrite(request)) return json({ error: 'bad_request' }, 400);
  const ip = clientIp(request);
  if (await tooManyAttempts(env, ip, 'admin', 5, 30)) return json({ error: 'locked' }, 429);

  let body = {};
  try { body = await request.json(); } catch {}
  const username = cleanUsername(body.username);
  const user = username
    ? await env.DB.prepare('SELECT id, username, pass_hash, session_version, disabled, is_admin FROM users WHERE username = ?').bind(username).first()
    : null;
  const ok = await checkSecret(String(body.password || ''), user && user.is_admin && !user.disabled ? user.pass_hash : null);
  if (!ok) {
    await recordFailure(env, ip, 'admin');
    await audit(env, username || '(blank)', 'admin_login_failed', null, ip);
    return json({ error: 'wrong_login' }, 401);
  }
  await env.DB.prepare('UPDATE users SET last_login = ? WHERE id = ?').bind(new Date().toISOString(), user.id).run();
  await audit(env, user.username, 'admin_login', null, ip);
  return json({ name: user.username }, 200, { 'set-cookie': await makeSessionCookie(env, user) });
}

// Lets the admin page check whether this browser is already signed in as an admin.
export async function onRequestGet({ request, env }) {
  const s = await getSession(request, env);
  if (!s) return json({ error: 'signed_out' }, 401);
  if (!s.isAdmin) return json({ error: 'not_admin' }, 403);
  return json({ name: s.name });
}
