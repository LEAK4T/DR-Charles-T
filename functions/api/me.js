import { json, getSession } from '../../lib/auth.js';

export async function onRequestGet({ request, env }) {
  const s = await getSession(request, env);
  return s ? json({ name: s.name, offerChange: s.offerChange, canManage: s.canManage }) : json({ error: 'signed_out' }, 401);
}
