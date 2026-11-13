import { json, getSession } from '../../lib/auth.js';

export async function onRequestGet({ request, env }) {
  const s = await getSession(request, env);
  return s ? json({ name: s.name, offerChange: s.offerChange, isAdmin: s.isAdmin }) : json({ error: 'signed_out' }, 401);
}
