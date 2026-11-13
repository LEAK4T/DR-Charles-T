import { json, getSession, isApiWrite, audit } from '../../../lib/auth.js';
import { cleanPatch, rowToPatient } from '../../../lib/patients.js';

export async function onRequestGet({ request, env }) {
  const s = await getSession(request, env);
  if (!s) return json({ error: 'signed_out' }, 401);
  const { results } = await env.DB.prepare('SELECT id, data, created_at, updated_at, updated_by FROM patients ORDER BY created_at DESC').all();
  return json({ patients: results.map(rowToPatient) });
}

export async function onRequestPost({ request, env }) {
  const s = await getSession(request, env);
  if (!s) return json({ error: 'signed_out' }, 401);
  if (!isApiWrite(request)) return json({ error: 'bad_request' }, 400);
  let body;
  try { body = await request.json(); } catch { return json({ error: 'bad_json' }, 400); }
  const data = cleanPatch(body);
  if (!data) return json({ error: 'bad_fields' }, 400);
  if (!String(data.name || '').trim()) return json({ error: 'name_required' }, 400);
  for (const k of Object.keys(data)) if (data[k] === '' || data[k] === null) delete data[k];

  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const who = s.name;
  await env.DB.prepare('INSERT INTO patients (id, data, created_at, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)')
    .bind(id, JSON.stringify(data), now, now, who).run();
  await audit(env, s.name, 'create', id);
  return json({ id }, 201);
}
