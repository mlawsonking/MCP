// Package-intelligence helpers — npm + PyPI registries + OSV.dev. All free, read-only.
// No SSRF concern: hosts are fixed; the user controls only a package NAME (validated below).

const ECO = {
  npm: { osv: 'npm', kind: 'npm' },
  pypi: { osv: 'PyPI', kind: 'pypi' }, python: { osv: 'PyPI', kind: 'pypi' }, pip: { osv: 'PyPI', kind: 'pypi' },
  go: { osv: 'Go', kind: 'go' }, golang: { osv: 'Go', kind: 'go' },
  crates: { osv: 'crates.io', kind: 'crates' }, rust: { osv: 'crates.io', kind: 'crates' }, cargo: { osv: 'crates.io', kind: 'crates' },
  rubygems: { osv: 'RubyGems', kind: 'rubygems' }, ruby: { osv: 'RubyGems', kind: 'rubygems' }, gem: { osv: 'RubyGems', kind: 'rubygems' },
  maven: { osv: 'Maven', kind: 'maven' }, nuget: { osv: 'NuGet', kind: 'nuget' },
};
function eco(name) { return ECO[String(name || 'npm').toLowerCase()] || null; }
function validName(n) { return typeof n === 'string' && n.length >= 1 && n.length <= 214 && /^[@a-zA-Z0-9._/-]+$/.test(n); }

async function fetchJson(url, { method = 'GET', body, timeoutMs = 7000 } = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const opts = { method, signal: ctrl.signal, headers: { Accept: 'application/json', 'User-Agent': 'agent-tools-pkg/1.0 (+https://github.com/mlawsonking/MCP)' } };
    if (body) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    const r = await fetch(url, opts);
    let json = null;
    try { json = await r.json(); } catch {}
    return { ok: r.ok, status: r.status, json };
  } catch (e) { return { ok: false, status: 0, error: String((e && e.message) || e) }; }
  finally { clearTimeout(t); }
}

function levenshtein(a, b) {
  a = String(a); b = String(b);
  const m = a.length, n = b.length;
  if (!m) return n; if (!n) return m;
  const d = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 0; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++)
    d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[m][n];
}

function npmPath(name) { return name.startsWith('@') ? '@' + name.slice(1).replace('/', '%2F') : encodeURIComponent(name); }

// Normalized metadata: { exists, latest, created, modified, age_days, weekly_downloads, deprecated, license, repository, description }
async function meta(kind, name, opts = {}) {
  const wantDownloads = opts.downloads !== false;
  if (kind === 'pypi') {
    const r = await fetchJson(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
    if (r.status === 404) return { exists: false };
    if (!r.ok || !r.json) return { exists: null, error: r.error || `pypi ${r.status}` };
    const info = r.json.info || {};
    const rels = r.json.releases || {};
    let first = null, last = null;
    for (const v of Object.values(rels)) for (const f of (v || [])) {
      const d = f.upload_time_iso_8601 || f.upload_time; if (!d) continue;
      if (!first || d < first) first = d; if (!last || d > last) last = d;
    }
    let weekly;
    if (wantDownloads) {
      const ds = await fetchJson(`https://pypistats.org/api/packages/${encodeURIComponent(name)}/recent`);
      if (ds.ok && ds.json && ds.json.data) weekly = ds.json.data.last_week;
    }
    return {
      exists: true, latest: info.version, created: first || undefined, modified: last || undefined,
      age_days: first ? Math.floor((Date.now() - new Date(first)) / 86400000) : undefined,
      weekly_downloads: weekly, deprecated: false,
      license: info.license || (info.classifiers || []).find((c) => c.startsWith('License ::')) || undefined,
      repository: (info.project_urls && (info.project_urls.Source || info.project_urls.Homepage)) || info.home_page || undefined,
      description: info.summary || undefined,
    };
  }
  // npm (default)
  const r = await fetchJson(`https://registry.npmjs.org/${npmPath(name)}`);
  if (r.status === 404) return { exists: false };
  if (!r.ok || !r.json) return { exists: null, error: r.error || `npm ${r.status}` };
  const d = r.json;
  const latest = d['dist-tags'] && d['dist-tags'].latest;
  const lv = (d.versions && latest && d.versions[latest]) || {};
  const created = d.time && d.time.created;
  let weekly;
  if (wantDownloads) {
    const ds = await fetchJson(`https://api.npmjs.org/downloads/point/last-week/${name}`);
    if (ds.ok && ds.json && typeof ds.json.downloads === 'number') weekly = ds.json.downloads;
  }
  return {
    exists: true, latest, created, modified: d.time && d.time.modified,
    age_days: created ? Math.floor((Date.now() - new Date(created)) / 86400000) : undefined,
    weekly_downloads: weekly, deprecated: !!lv.deprecated,
    license: lv.license || d.license || undefined,
    repository: (d.repository && (d.repository.url || d.repository)) || undefined,
    description: d.description || lv.description || undefined,
  };
}

// OSV vulnerabilities (incl. malware "MAL-" advisories). Returns [] if none.
async function vulns(osvEcosystem, name, version) {
  const pkg = { name, ecosystem: osvEcosystem };
  const body = version ? { version, package: pkg } : { package: pkg };
  const r = await fetchJson('https://api.osv.dev/v1/query', { method: 'POST', body });
  if (!r.ok || !r.json) return { error: r.error || `osv ${r.status}`, list: [] };
  const list = (r.json.vulns || []).map((v) => ({
    id: v.id,
    summary: v.summary || (v.details ? String(v.details).slice(0, 160) : undefined),
    aliases: v.aliases,
    malicious: /^MAL-/i.test(v.id || '') || (v.id || '').toUpperCase().includes('MALWARE'),
    severity: (v.severity && v.severity[0] && v.severity[0].score) || undefined,
    fixed: (((v.affected || [])[0] || {}).ranges || []).flatMap((rg) => (rg.events || []).filter((e) => e.fixed).map((e) => e.fixed))[0],
  }));
  return { list };
}

// npm search for "did you mean" suggestions (npm only).
async function npmSearch(text, size = 5) {
  const r = await fetchJson(`https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(text)}&size=${size}`);
  if (!r.ok || !r.json || !r.json.objects) return [];
  return r.json.objects.map((o) => ({
    name: o.package && o.package.name,
    downloads: (o.searchScore && o.package) ? undefined : undefined,
    score: o.score && o.score.final,
  })).filter((o) => o.name);
}

// Generate plausible typosquat variants of a name.
function typosquats(name) {
  const base = name.replace(/^@[^/]+\//, ''); // ignore scope for variant gen
  const set = new Set();
  const add = (s) => { if (s && s !== base && /^[a-z0-9._-]+$/i.test(s) && s.length >= 2) set.add(s); };
  // deletions
  for (let i = 0; i < base.length; i++) add(base.slice(0, i) + base.slice(i + 1));
  // adjacent transpositions
  for (let i = 0; i < base.length - 1; i++) add(base.slice(0, i) + base[i + 1] + base[i] + base.slice(i + 2));
  // doubled chars
  for (let i = 0; i < base.length; i++) add(base.slice(0, i) + base[i] + base[i] + base.slice(i));
  // common confusions
  const conf = [['l', '1'], ['1', 'l'], ['o', '0'], ['0', 'o'], ['rn', 'm'], ['m', 'rn'], ['-', '_'], ['_', '-'], ['.', '-'], ['i', 'l'], ['s', 'z']];
  for (const [a, b] of conf) if (base.includes(a)) add(base.split(a).join(b));
  // hyphen insert/remove
  add(base.replace(/-/g, '')); add(base.replace(/_/g, ''));
  return [...set].slice(0, 30);
}

module.exports = { eco, validName, fetchJson, levenshtein, meta, vulns, npmSearch, typosquats };
