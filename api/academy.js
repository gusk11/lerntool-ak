// Student accounts + live progress for the teacher view. Storage: Upstash Redis (Vercel Marketplace) via REST.
const crypto = require('crypto');
const DB_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const DB_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

async function redis(...cmd) {
  const r = await fetch(DB_URL, { method: 'POST', headers: { Authorization: 'Bearer ' + DB_TOKEN }, body: JSON.stringify(cmd) });
  const j = await r.json();
  if (j.error) throw Error(j.error);
  return j.result;
}
const hash = (pin, salt) => crypto.scryptSync(String(pin), salt, 32).toString('hex');
const same = (a, b) => crypto.timingSafeEqual(crypto.createHash('sha256').update(String(a)).digest(), crypto.createHash('sha256').update(String(b)).digest());
const key = id => 'acad:student:' + id;

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });
  if (!DB_URL || !DB_TOKEN) return res.status(500).json({ error: 'Storage is not connected yet (Upstash Redis in Vercel).' });
  const b = req.body || {};
  try {
    if (b.action === 'teacher') {
      const pw = process.env.TEACHER_PASSWORD || process.env.teacher_password;
      if (!pw || !same(b.password || '', pw)) return res.status(401).json({ error: 'Wrong teacher password.' });
      const ids = await redis('SMEMBERS', 'acad:students');
      const vals = ids.length ? await redis('MGET', ...ids.map(key)) : [];
      const students = vals.filter(Boolean).map(v => { const s = JSON.parse(v); return { ...(s.state || {}), name: s.name, updated: s.updated }; });
      return res.json({ students });
    }

    const name = String(b.name || '').trim();
    const pin = String(b.pin || '');
    if (!/^[\p{L}\p{N} _.-]{2,24}$/u.test(name)) return res.status(400).json({ error: 'Name: 2–24 letters or numbers.' });
    if (!/^\d{4,8}$/.test(pin)) return res.status(400).json({ error: 'PIN: 4–8 digits.' });
    if (b.state !== undefined && JSON.stringify(b.state).length > 900000) return res.status(413).json({ error: 'Progress too large to save.' });
    const id = name.toLowerCase();

    if (b.action === 'register') {
      const salt = crypto.randomBytes(16).toString('hex');
      const rec = { name, salt, pin: hash(pin, salt), state: b.state || null, updated: Date.now() };
      if (!(await redis('SET', key(id), JSON.stringify(rec), 'NX'))) return res.status(409).json({ error: 'This name is already taken.' });
      await redis('SADD', 'acad:students', id);
      return res.json({ state: rec.state });
    }

    const raw = await redis('GET', key(id));
    const rec = raw && JSON.parse(raw);
    if (!rec || !same(hash(pin, rec.salt), rec.pin)) return res.status(401).json({ error: 'Wrong name or PIN.' });
    if (b.action === 'login') return res.json({ state: rec.state, name: rec.name });
    if (b.action === 'save') {
      rec.state = b.state;
      rec.updated = Date.now();
      await redis('SET', key(id), JSON.stringify(rec));
      return res.json({ ok: true });
    }
    return res.status(400).json({ error: 'Unknown action.' });
  } catch (e) {
    return res.status(500).json({ error: 'Server error: ' + e.message });
  }
};
