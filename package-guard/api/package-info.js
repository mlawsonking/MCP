// package-info — registry metadata: latest, deprecated, license, repo, downloads, age.
// GET /api/package-info?name=<pkg>&ecosystem=npm|pypi|go|...
const { eco, validName, meta } = require('../lib/pkg.js');
const { sendJson, handleOptions, track } = require('../lib/common.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const q = req.query || {};
  const name = String(q.name || q.package || '').trim();
  const e = eco(q.ecosystem || 'npm');
  if (!name) return sendJson(res, 400, { ok: false, error: 'Missing required ?name= parameter' });
  if (!e) return sendJson(res, 400, { ok: false, error: 'Unknown ecosystem' });
  if (!validName(name)) return sendJson(res, 400, { ok: false, error: 'Invalid package name' });

  const m = await meta(e.kind, name);
  // Counted before the 404 branch, not after it. "This package does not exist" is a successful
  // answer and it is the one that catches a hallucinated dependency, so leaving it out of the beacon
  // would undercount the most useful thing this endpoint does. The 502 below is a failed lookup and
  // stays uncounted.
  if (m.exists !== null) track(req, 'guard_call', { product: 'package-guard', endpoint: 'package-info' });
  if (m.exists === false) return sendJson(res, 404, { ok: true, name, ecosystem: e.kind, exists: false });
  if (m.exists === null) return sendJson(res, 502, { ok: false, error: 'Registry lookup failed', detail: m.error });
  return sendJson(res, 200, { ok: true, name, ecosystem: e.kind, ...m, ms: Date.now() - started });
};
