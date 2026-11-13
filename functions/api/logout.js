import { json, clearCookie, getSession, audit } from '../../lib/auth.js';

export async function onRequestPost({ request, env }) {
  const s = await getSession(request, env);
  if (s) await audit(env, s.name, 'logout');
  return json({ ok: true }, 200, { 'set-cookie': clearCookie });
}
