import { json, getSession, isApiWrite, audit } from '../../../lib/auth.js';
import { cleanPatch } from '../../../lib/patients.js';

export async function onRequestPatch({ request, env, params }) {
  const s = await getSession(request, env);
  if (!s) return json({ error: 'signed_out' }, 401);
  if (!isApiWrite(request)) return json({ error: 'bad_request' }, 400);
  let body;
  try { body = await request.json(); } catch { return json({ error: 'bad_json' }, 400); }
  const patch = cleanPatch(body);
  if (!patch) return json({ error: 'bad_fields' }, 400);
  if ('name' in patch && !String(patch.name || '').trim()) return json({ error: 'name_required' }, 400);

  const row = await env.DB.prepare('SELECT data FROM patients WHERE id = ?').bind(params.id).first();
  if (!row) return json({ error: 'not_found' }, 404);
  const data = JSON.parse(row.data);
  for (const [k, v] of Object.entries(patch)) {
    if (v === '' || v === null) delete data[k]; else data[k] = v;
  }
  const who = s.name;
  await env.DB.prepare('UPDATE patients SET data = ?, updated_at = ?, updated_by = ? WHERE id = ?')
    .bind(JSON.stringify(data), new Date().toISOString(), who, params.id).run();
  await audit(env, s.name, 'update', params.id, Object.keys(patch).join(','));
  return json({ ok: true });
}

export async function onRequestDelete({ request, env, params }) {
  const s = await getSession(request, env);
  if (!s) return json({ error: 'signed_out' }, 401);
  if (request.headers.get('x-requested-with') !== 'tracker') return json({ error: 'bad_request' }, 400);
  const r = await env.DB.prepare('DELETE FROM patients WHERE id = ?').bind(params.id).run();
  if (!r.meta || !r.meta.changes) return json({ error: 'not_found' }, 404);
  await audit(env, s.name, 'delete', params.id);
  return json({ ok: true });
}
