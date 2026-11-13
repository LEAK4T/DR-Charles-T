import { json, checkSecret, makeSessionCookie, clientIp, tooManyAttempts, recordFailure, audit, isApiWrite, cleanUsername } from '../../lib/auth.js';

export async function onRequestPost({ request, env }) {
  if (!isApiWrite(request)) return json({ error: 'bad_request' }, 400);
  const ip = clientIp(request);
  if (await tooManyAttempts(env, ip, 'staff')) return json({ error: 'locked' }, 429);

  let body = {};
  try { body = await request.json(); } catch {}
  const username = cleanUsername(body.username);
  const password = String(body.password || '');

  const user = username
    ? await env.DB.prepare('SELECT id, username, pass_hash, session_version, offer_change, disabled, is_admin, is_manager FROM users WHERE username = ?').bind(username).first()
    : null;
  const good = await checkSecret(password, user && !user.disabled ? user.pass_hash : null);
  if (!good) {
    await recordFailure(env, ip, 'staff');
    await audit(env, username || '(blank)', 'login_failed', null, ip);
    return json({ error: 'wrong_login' }, 401);
  }
  await env.DB.prepare('UPDATE users SET last_login = ? WHERE id = ?').bind(new Date().toISOString(), user.id).run();
  await audit(env, user.username, 'login', null, ip);
  return json({ name: user.username, offerChange: !!user.offer_change, canManage: !!(user.is_admin || user.is_manager) }, 200, { 'set-cookie': await makeSessionCookie(env, user) });
}
