import { json, adminGuard, getSetting, setSetting, audit, clientIp, makeSessionCookie } from '../../../lib/auth.js';

// Status for the admin page (owner or manager). The killswitch itself is owner-only.
export async function status(env) {
  const [offline, changed, count, recent, users] = await Promise.all([
    getSetting(env, 'offline', '0'),
    getSetting(env, 'offline_changed_at', null),
    env.DB.prepare('SELECT COUNT(*) AS n FROM patients').first(),
    env.DB.prepare('SELECT at, who, action, patient_id, detail FROM audit ORDER BY id DESC LIMIT 25').all(),
    env.DB.prepare('SELECT id, username, offer_change, disabled, is_admin, is_manager, created_at, last_login FROM users ORDER BY is_admin DESC, is_manager DESC, username').all(),
  ]);
  return {
    offline: offline === '1', changedAt: changed, patients: count?.n || 0, activity: recent.results,
    users: users.results.map(u => ({ id: u.id, username: u.username, isAdmin: !!u.is_admin, isManager: !!u.is_manager, firstLoginPending: !!u.offer_change, disabled: !!u.disabled, createdAt: u.created_at, lastLogin: u.last_login })),
  };
}

export async function onRequestGet({ request, env }) {
  const g = await adminGuard(request, env);
  if (g.res) return g.res;
  return json({ ...(await status(env)), me: g.s.name, role: g.s.isAdmin ? 'owner' : 'manager' });
}

export async function onRequestPost({ request, env }) {
  const g = await adminGuard(request, env, { ownerOnly: true });
  if (g.res) return g.res;
  let body = {};
  try { body = await request.json(); } catch {}
  const ip = clientIp(request);
  if (body.action === 'offline' || body.action === 'online') {
    await setSetting(env, 'offline', body.action === 'offline' ? '1' : '0');
    await setSetting(env, 'offline_changed_at', new Date().toISOString());
    if (body.action === 'offline') await bumpSessions(env);
    await audit(env, g.s.name, body.action === 'offline' ? 'killswitch_on' : 'killswitch_off', null, ip);
  } else if (body.action === 'signout-all') {
    await bumpSessions(env);
    await audit(env, g.s.name, 'signout_all', null, ip);
  } else {
    return json({ error: 'unknown_action' }, 400);
  }
  const extra = {};
  if (body.action === 'offline' || body.action === 'signout-all') {
    const me = await env.DB.prepare('SELECT id, session_version FROM users WHERE id = ?').bind(g.s.id).first();
    extra['set-cookie'] = await makeSessionCookie(env, me);
  }
  return json({ ...(await status(env)), me: g.s.name, role: 'owner' }, 200, extra);
}

// Changing the version invalidates every existing login cookie.
async function bumpSessions(env) {
  const v = Number(await getSetting(env, 'session_version', '1')) || 1;
  await setSetting(env, 'session_version', String(v + 1));
}
