// Validates a patient patch: plain field names, short string/boolean/number values.
const KEY = /^[A-Za-z][A-Za-z0-9]{0,40}$/;
const SERVER_KEYS = new Set(['id', 'createdAt', 'updatedAt', 'updatedBy']);

export function cleanPatch(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  const out = {};
  const entries = Object.entries(body);
  if (entries.length > 80) return null;
  for (const [k, v] of entries) {
    if (SERVER_KEYS.has(k)) continue;
    if (!KEY.test(k)) return null;
    if (v === null || typeof v === 'boolean') out[k] = v;
    else if (typeof v === 'number' && Number.isFinite(v)) out[k] = String(v);
    else if (typeof v === 'string' && v.length <= 5000) out[k] = v;
    else return null;
  }
  return out;
}

export function rowToPatient(r) {
  let data = {};
  try { data = JSON.parse(r.data); } catch {}
  return { ...data, id: r.id, createdAt: r.created_at, updatedAt: r.updated_at, updatedBy: r.updated_by };
}
