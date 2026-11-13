import { json, adminGuard, audit, hashSecret, randomCode, cleanUsername, USERNAME, checkSecret, passwordProblem, makeSessionCookie } from '../../../lib/auth.js';
import { status } from './status.js';

// Staff logins and the admin's own password. Temporary passwords are shown to the admin once and never stored in plain text.
export async function onRequestPost({ request, env }) {
  const g = await adminGuard(request, env);
  if (g.res) return g.res;
  let body = {};
  try { body = await request.json(); } catch {}
  const a = body.action;

  if (a === 'create') {
    const username = cleanUsername(body.username);
    if (!USERNAME.test(username)) return json({ error: 'bad_username' }, 400);
    if (await env.DB.prepare('SELECT 1 FROM users WHERE username = ?').bind(username).first()) return json({ error: 'username_taken' }, 409);
    const temp = randomCode();
    await env.DB.prepare('INSERT INTO users (id, username, pass_hash, offer_change, session_version, disabled, created_at) VALUES (?, ?, ?, 1, 1, 0, ?)')
      .bind(crypto.randomUUID(), username, await hashSecret(temp), new Date().toISOString()).run();
    await audit(env, g.s.name, 'user_created', null, username);
    return json({ ...(await status(env)), me: g.s.name, issued: { username, password: temp } });
  }

  if (a === 'reset' || a === 'disable' || a === 'enable' || a === 'remove') {
    const user = await env.DB.prepare('SELECT id, username FROM users WHERE id = ?').bind(String(body.id || '')).first();
    if (!user) return json({ error: 'not_found' }, 404);
    if (user.id === g.s.id) return json({ error: 'not_yourself' }, 400); // never lock yourself out
    if (a === 'reset') {
      const temp = randomCode();
      await env.DB.prepare('UPDATE users SET pass_hash = ?, offer_change = 1, session_version = session_version + 1 WHERE id = ?')
        .bind(await hashSecret(temp), user.id).run();
      await audit(env, g.s.name, 'password_reset', null, user.username);
      return json({ ...(await status(env)), me: g.s.name, issued: { username: user.username, password: temp } });
    }
    if (a === 'remove') {
      await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(user.id).run();
    } else {
      await env.DB.prepare('UPDATE users SET disabled = ?, session_version = session_version + 1 WHERE id = ?').bind(a === 'disable' ? 1 : 0, user.id).run();
    }
    await audit(env, g.s.name, 'user_' + (a === 'remove' ? 'removed' : a + 'd'), null, user.username);
    return json({ ...(await status(env)), me: g.s.name });
  }

  if (a === 'change-my-password') {
    const me = await env.DB.prepare('SELECT id, pass_hash FROM users WHERE id = ?').bind(g.s.id).first();
    if (!(await checkSecret(String(body.current || ''), me.pass_hash))) return json({ error: 'wrong_current' }, 400);
    const p = passwordProblem(body.password);
    if (p) return json({ error: 'weak_password', message: p }, 400);
    await env.DB.prepare('UPDATE users SET pass_hash = ?, offer_change = 0, session_version = session_version + 1 WHERE id = ?')
      .bind(await hashSecret(String(body.password)), g.s.id).run();
    await audit(env, g.s.name, 'changed_own_password');
    const fresh = await env.DB.prepare('SELECT id, session_version FROM users WHERE id = ?').bind(g.s.id).first();
    return json({ ...(await status(env)), me: g.s.name }, 200, { 'set-cookie': await makeSessionCookie(env, fresh) });
  }

  return json({ error: 'unknown_action' }, 400);
}
