// verify-package — the pre-install guard for AI coding agents.
// GET /api/verify-package?name=<pkg>&ecosystem=npm|pypi|go|crates|rubygems&version=<optional>
// Answers: does it EXIST (else likely hallucination/slopsquat + suggestions)? vulnerabilities/malware?
// slopsquat-risk (new + low-downloads + name near a popular package)? deprecated? license? → a verdict.
// Free data: OSV.dev + npm/PyPI registries. Deterministic, no LLM.

const { eco, validName, meta, vulns, npmSearch, levenshtein } = require('../lib/pkg.js');
const { sendJson, handleOptions } = require('../lib/common.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const q = req.query || {};
  const name = String(q.name || q.package || '').trim();
  const e = eco(q.ecosystem || 'npm');
  const version = q.version ? String(q.version).trim() : undefined;

  if (!name) return sendJson(res, 400, { ok: false, error: 'Missing required ?name= parameter' });
  if (!e) return sendJson(res, 400, { ok: false, error: 'Unknown ecosystem. Use npm, pypi, go, crates, rubygems, maven, or nuget.' });
  if (!validName(name)) return sendJson(res, 400, { ok: false, error: 'Invalid package name' });

  const m = await meta(e.kind, name);

  // Does not exist → the slopsquat / hallucination case.
  if (m.exists === false) {
    let suggestions = [];
    if (e.kind === 'npm') {
      const hits = await npmSearch(name, 10);
      suggestions = hits.map((h) => h.name).filter((n) => n && n !== name)
        .sort((a, b) => levenshtein(a, name) - levenshtein(b, name)).slice(0, 5);
    }
    return sendJson(res, 200, {
      ok: true, name, ecosystem: e.kind, exists: false, verdict: 'danger',
      likely_hallucination: true,
      reasons: ['Package does not exist in the registry — likely an AI-hallucinated or unregistered name. Attackers register these ("slopsquatting"). Do NOT install.'],
      suggestions, ms: Date.now() - started,
    });
  }
  if (m.exists === null) return sendJson(res, 502, { ok: false, error: 'Registry lookup failed', detail: m.error });

  // Exists → assess.
  const v = await vulns(e.osv, name, version || m.latest);
  const vlist = v.list || [];
  const malicious = vlist.some((x) => x.malicious);
  const hasVuln = vlist.length > 0;

  const reasons = [];
  const slopSignals = [];
  if (typeof m.age_days === 'number' && m.age_days < 90) slopSignals.push(`very new (${m.age_days}d old)`);
  if (typeof m.weekly_downloads === 'number' && m.weekly_downloads < 50) slopSignals.push(`near-zero downloads (${m.weekly_downloads}/wk)`);

  // Name close to a popular package? (npm) — possible typosquat/confusion target.
  let confusable = null;
  if (e.kind === 'npm') {
    const hits = await npmSearch(name, 5);
    const near = hits.find((h) => h.name && h.name !== name && levenshtein(h.name.replace(/^@[^/]+\//, ''), name.replace(/^@[^/]+\//, '')) <= 2);
    if (near) confusable = near.name;
  }
  if (confusable && slopSignals.length) slopSignals.push(`name is 1–2 edits from "${confusable}"`);

  let slopsquat_risk = 'low';
  if (slopSignals.length >= 2 && confusable) slopsquat_risk = 'high';
  else if (slopSignals.length >= 1) slopsquat_risk = 'medium';

  // Verdict.
  let verdict = 'safe';
  if (malicious) { verdict = 'danger'; reasons.push('Flagged as MALICIOUS in OSV — do not install.'); }
  else if (slopsquat_risk === 'high') { verdict = 'danger'; reasons.push('High slopsquat/typosquat risk: ' + slopSignals.join(', ') + '.'); }
  if (hasVuln && !malicious) { if (verdict === 'safe') verdict = 'caution'; reasons.push(`${vlist.length} known vulnerability(ies) (OSV).`); }
  if (m.deprecated) { if (verdict === 'safe') verdict = 'caution'; reasons.push('Package is deprecated.'); }
  if (slopsquat_risk === 'medium' && verdict === 'safe') { verdict = 'caution'; reasons.push('Some slopsquat signals: ' + slopSignals.join(', ') + '.'); }
  if (verdict === 'safe') reasons.push('Exists, no known vulnerabilities, healthy signals.');

  return sendJson(res, 200, {
    ok: true, name, ecosystem: e.kind, exists: true, verdict,
    version_checked: version || m.latest, latest: m.latest,
    age_days: m.age_days, weekly_downloads: m.weekly_downloads, deprecated: m.deprecated,
    license: m.license, repository: m.repository,
    slopsquat: { risk: slopsquat_risk, signals: slopSignals, confusable_with: confusable || undefined },
    vulnerabilities: { count: vlist.length, malicious, list: vlist.slice(0, 5) },
    reasons, ms: Date.now() - started,
  });
};
