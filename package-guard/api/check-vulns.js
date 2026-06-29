// check-vulns — known vulnerabilities (and malware advisories) for a package, via OSV.dev.
// GET /api/check-vulns?name=<pkg>&ecosystem=npm|pypi|go|...&version=<optional>
const { eco, validName, vulns } = require('../lib/pkg.js');
const { sendJson, handleOptions } = require('../lib/common.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const q = req.query || {};
  const name = String(q.name || q.package || '').trim();
  const e = eco(q.ecosystem || 'npm');
  const version = q.version ? String(q.version).trim() : undefined;
  if (!name) return sendJson(res, 400, { ok: false, error: 'Missing required ?name= parameter' });
  if (!e) return sendJson(res, 400, { ok: false, error: 'Unknown ecosystem' });
  if (!validName(name)) return sendJson(res, 400, { ok: false, error: 'Invalid package name' });

  const v = await vulns(e.osv, name, version);
  if (v.error) return sendJson(res, 502, { ok: false, error: 'OSV lookup failed', detail: v.error });
  return sendJson(res, 200, {
    ok: true, name, ecosystem: e.kind, version: version || 'all',
    count: v.list.length, malicious: v.list.some((x) => x.malicious),
    vulnerabilities: v.list, ms: Date.now() - started,
  });
};
