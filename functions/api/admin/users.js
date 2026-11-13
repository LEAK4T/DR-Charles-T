import { json, adminGuard, audit, hashSecret, randomCode, cleanUsername, USERNAME, checkSecret, passwordProblem, makeSessionCookie } from '../../../lib/auth.js';
import { status } from './status.js';

// Staff logins and your own password. Owners and managers can manage logins; nobody can change the owner's login
// from here except the owner (own password only), and only the owner can make or unmake managers. Temporary passwords are shown to the admin once and never stored in plain text.
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
    return json({ ...(await status(env)), me: g.s.name, role: g.s.isAdmin ? 'owner' : 'manager', issued: { username, password: temp } });
  }

  if (a === 'reset' || a === 'disable' || a === 'enable' || a === 'remove') {
    const user = await env.DB.prepare('SELECT id, username, is_admin FROM users WHERE id = ?').bind(String(body.id || '')).first();
    if (!user) return json({ error: 'not_found' }, 404);
    if (user.id === g.s.id) return json({ error: 'not_yourself' }, 400); // never lock yourself out
    if (user.is_admin) return json({ error: 'protected' }, 403); // the owner's login can't be touched from here
    if (a === 'reset') {
      const temp = randomCode();
      await env.DB.prepare('UPDATE users SET pass_hash = ?, offer_change = 1, session_version = session_version + 1 WHERE id = ?')
        .bind(await hashSecret(temp), user.id).run();
      await audit(env, g.s.name, 'password_reset', null, user.username);
      return json({ ...(await status(env)), me: g.s.name, role: g.s.isAdmin ? 'owner' : 'manager', issued: { username: user.username, password: temp } });
    }
    if (a === 'remove') {
      await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(user.id).run();
    } else {
      await env.DB.prepare('UPDATE users SET disabled = ?, session_version = session_version + 1 WHERE id = ?').bind(a === 'disable' ? 1 : 0, user.id).run();
    }
    await audit(env, g.s.name, 'user_' + (a === 'remove' ? 'removed' : a + 'd'), null, user.username);
    return json({ ...(await status(env)), me: g.s.name, role: g.s.isAdmin ? 'owner' : 'manager' });
  }

  if (a === 'set-role') {
    if (!g.s.isAdmin) return json({ error: 'not_admin' }, 403);
    const user = await env.DB.prepare('SELECT id, username, is_admin FROM users WHERE id = ?').bind(String(body.id || '')).first();
    if (!user) return json({ error: 'not_found' }, 404);
    if (user.is_admin) return json({ error: 'protected' }, 403);
    const manager = body.manager ? 1 : 0;
    await env.DB.prepare('UPDATE users SET is_manager = ?, session_version = session_version + 1 WHERE id = ?').bind(manager, user.id).run();
    await audit(env, g.s.name, manager ? 'made_manager' : 'made_staff', null, user.username);
    return json({ ...(await status(env)), me: g.s.name, role: 'owner' });
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
    return json({ ...(await status(env)), me: g.s.name, role: g.s.isAdmin ? 'owner' : 'manager' }, 200, { 'set-cookie': await makeSessionCookie(env, fresh) });
  }

  return json({ error: 'unknown_action' }, 400);
}
