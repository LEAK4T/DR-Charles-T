import { json, getSession, isApiWrite, audit, hashSecret, cleanUsername, USERNAME, passwordProblem, makeSessionCookie } from '../../lib/auth.js';

// First sign-in only: the user may choose a new username and/or password, or keep the ones they were given.
// Either answer clears the offer so it never shows again (until the admin resets their password).
export async function onRequestPost({ request, env }) {
  const s = await getSession(request, env);
  if (!s) return json({ error: 'signed_out' }, 401);
  if (!isApiWrite(request)) return json({ error: 'bad_request' }, 400);
  if (!s.offerChange) return json({ error: 'already_done' }, 409);

  let body = {};
  try { body = await request.json(); } catch {}

  if (body.keep) {
    await env.DB.prepare('UPDATE users SET offer_change = 0 WHERE id = ?').bind(s.id).run();
    await audit(env, s.name, 'kept_login');
    return json({ name: s.name, canManage: s.canManage });
  }

  const username = body.username === undefined ? s.name : cleanUsername(body.username);
  if (!USERNAME.test(username)) return json({ error: 'bad_username' }, 400);
  if (username !== s.name) {
    const taken = await env.DB.prepare('SELECT 1 FROM users WHERE username = ? AND id != ?').bind(username, s.id).first();
    if (taken) return json({ error: 'username_taken' }, 409);
  }
  const newPass = body.password ? String(body.password) : '';
  if (newPass) {
    const p = passwordProblem(newPass);
    if (p) return json({ error: 'weak_password', message: p }, 400);
  }

  if (newPass) {
    await env.DB.prepare('UPDATE users SET username = ?, pass_hash = ?, offer_change = 0, session_version = session_version + 1 WHERE id = ?')
      .bind(username, await hashSecret(newPass), s.id).run();
  } else {
    await env.DB.prepare('UPDATE users SET username = ?, offer_change = 0 WHERE id = ?').bind(username, s.id).run();
  }
  await audit(env, username, 'changed_login', null, [username !== s.name ? `was ${s.name}` : '', newPass ? 'new password' : ''].filter(Boolean).join(', '));

  // A new password ends old sessions, so hand this browser a fresh one.
  const user = await env.DB.prepare('SELECT id, session_version FROM users WHERE id = ?').bind(s.id).first();
  return json({ name: username, canManage: s.canManage }, 200, { 'set-cookie': await makeSessionCookie(env, user) });
}
