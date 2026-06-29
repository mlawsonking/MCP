// audit-deps — batch supply-chain audit of a dependency list (the agent's "check everything" call).
// GET  /api/audit-deps?packages=react,lodash,leftpad&ecosystem=npm
// POST { "ecosystem":"npm", "dependencies": {"react":"^18","lodash":"4.17.21"} }
//      { "ecosystem":"npm", "packageJson": "<package.json text>" }
//      { "ecosystem":"pypi", "requirements": "flask==2.0.1\nrequests>=2" }
// For each: exists? (hallucination/slopsquat), known vulns/malware (OSV), deprecated. Returns a summary.

const { eco, validName, meta, fetchJson } = require('../lib/pkg.js');
const { sendJson, handleOptions } = require('../lib/common.js');

const cleanVer = (v) => { const m = String(v || '').match(/\d+\.\d+(?:\.\d+)?/); return m ? m[0] : undefined; };

function parseInput(q, body) {
  const out = {};
  if (body && body.dependencies && typeof body.dependencies === 'object') Object.assign(out, body.dependencies);
  if (body && typeof body.packageJson === 'string') {
    try { const j = JSON.parse(body.packageJson); Object.assign(out, j.dependencies || {}, j.devDependencies || {}); } catch {}
  }
  if (body && typeof body.requirements === 'string') {
    for (const line of body.requirements.split(/\r?\n/)) {
      const m = line.trim().match(/^([A-Za-z0-9._-]+)\s*(?:[=<>!~]+\s*([0-9][\w.]*))?/);
      if (m && m[1] && !line.trim().startsWith('#')) out[m[1]] = m[2] || '';
    }
  }
  if (q.packages) for (const n of String(q.packages).split(',')) { const t = n.trim(); if (t) out[t] = out[t] || ''; }
  return out;
}

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const q = req.query || {};
  const body = req.body || {};
  const e = eco(q.ecosystem || body.ecosystem || 'npm');
  if (!e) return sendJson(res, 400, { ok: false, error: 'Unknown ecosystem' });

  const deps = parseInput(q, body);
  let names = Object.keys(deps).filter(validName);
  if (names.length === 0) return sendJson(res, 400, { ok: false, error: 'No dependencies provided. Use ?packages=a,b or POST {dependencies|packageJson|requirements}.' });
  const truncated = names.length > 40;
  names = names.slice(0, 40);

  // OSV batch (one call) for all packages.
  const queries = names.map((n) => { const v = cleanVer(deps[n]); return v ? { package: { name: n, ecosystem: e.osv }, version: v } : { package: { name: n, ecosystem: e.osv } }; });
  const osv = await fetchJson('https://api.osv.dev/v1/querybatch', { method: 'POST', body: { queries }, timeoutMs: 9000 });
  const osvResults = (osv.ok && osv.json && osv.json.results) || [];

  // Existence/deprecation per package (parallel, no downloads call).
  const metas = await Promise.all(names.map((n) => meta(e.kind, n, { downloads: false })));

  const report = names.map((n, i) => {
    const m = metas[i] || {};
    const vs = (osvResults[i] && osvResults[i].vulns) || [];
    const malicious = vs.some((v) => /^MAL-/i.test(v.id || ''));
    let verdict = 'safe';
    const flags = [];
    if (m.exists === false) { verdict = 'danger'; flags.push('does-not-exist (hallucination/slopsquat risk)'); }
    else if (malicious) { verdict = 'danger'; flags.push('malicious'); }
    else {
      if (vs.length) { verdict = 'caution'; flags.push(`${vs.length} vuln(s)`); }
      if (m.deprecated) { verdict = verdict === 'safe' ? 'caution' : verdict; flags.push('deprecated'); }
    }
    return { name: n, requested: deps[n] || undefined, exists: m.exists, latest: m.latest, vulns: vs.length, malicious, deprecated: !!m.deprecated, verdict, flags };
  });

  const tally = (k, val) => report.filter((r) => r[k] === val).length;
  return sendJson(res, 200, {
    ok: true, ecosystem: e.kind, total: report.length, truncated: truncated || undefined,
    summary: {
      danger: tally('verdict', 'danger'), caution: tally('verdict', 'caution'), safe: tally('verdict', 'safe'),
      missing: report.filter((r) => r.exists === false).length,
      malicious: report.filter((r) => r.malicious).length,
      vulnerable: report.filter((r) => r.vulns > 0).length,
      deprecated: report.filter((r) => r.deprecated).length,
    },
    packages: report, ms: Date.now() - started,
  });
};
