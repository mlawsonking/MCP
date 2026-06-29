// typosquat-scan — generate lookalike names for a package and flag which are registered/suspicious.
// GET /api/typosquat-scan?name=<pkg>&ecosystem=npm|pypi|...
const { eco, validName, meta, typosquats } = require('../lib/pkg.js');
const { sendJson, handleOptions } = require('../lib/common.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const q = req.query || {};
  const name = String(q.name || q.package || '').trim();
  const e = eco(q.ecosystem || 'npm');
  if (!name) return sendJson(res, 400, { ok: false, error: 'Missing required ?name= parameter' });
  if (!e) return sendJson(res, 400, { ok: false, error: 'Unknown ecosystem' });
  if (!validName(name)) return sendJson(res, 400, { ok: false, error: 'Invalid package name' });

  const variants = typosquats(name).slice(0, 20);
  const checked = await Promise.all(variants.map(async (vn) => {
    const m = await meta(e.kind, vn, { downloads: false });
    if (m.exists !== true) return null;
    const suspicious = typeof m.age_days === 'number' ? m.age_days < 365 : true;
    return { name: vn, age_days: m.age_days, latest: m.latest, suspicious };
  }));
  const found = checked.filter(Boolean);
  return sendJson(res, 200, {
    ok: true, name, ecosystem: e.kind, variants_checked: variants.length,
    registered: found.length, suspicious: found.filter((f) => f.suspicious).length,
    matches: found, ms: Date.now() - started,
  });
};
