// GENERATED FILE - do not edit here. Your change will be overwritten.
// Source of truth: agent-guards/tools/packages.js
// Regenerate: node scripts/sync-shared.js
// Package Guard tools. Five tools; every one of them needs the network, so none of them work
// offline and all five say so rather than answering from an absent lookup.
//
// Response shapes match what the hosted API returns today, field for field, because the
// package-guard-mcp package is a facade over this and anyone already parsing its output must keep
// working. Fields may be added, never renamed or removed. The single dropped field is `upgrade`,
// which was only ever a hosted-plan advert and means nothing locally.
//
// The data behind these tools: registry.npmjs.org and pypi.org for existence and metadata,
// api.npmjs.org and pypistats.org for weekly downloads, api.osv.dev for vulnerabilities and malware
// advisories. Nothing here downloads or executes package contents, so nothing here can see what a
// package actually does.

const { eco, validName, meta, vulns, npmSearch, levenshtein, typosquats, fetchJson } = require('../engines/packages');
const { unavailable } = require('./_schema');

// engines/packages.js meta() has a client for PyPI and a client for npm, and nothing else: every
// other ecosystem falls through to the npm branch. So a request for a Go, crates.io, RubyGems, Maven
// or NuGet name gets existence, age, downloads and deprecation from registry.npmjs.org, describing a
// different package that happens to share the name. The declared enums keep npm and pypi as the only
// values an MCP client can send to the registry-backed tools, but eco() accepts the aliases and a
// direct core caller can reach this path, so the output names the registry that actually answered
// instead of letting npm data pass as Go data.
function registrySource(kind) { return kind === 'pypi' ? 'pypi.org' : 'registry.npmjs.org'; }
function registryLimitation(kind) {
  if (kind === 'npm' || kind === 'pypi') return undefined;
  return `There is no ${kind} registry client here. The registry fields in this response came from `
    + `registry.npmjs.org, so they describe an npm package of that name if one exists and say nothing `
    + `about ${kind}. Only OSV vulnerability data is ${kind}-specific. Use check_vulns for ${kind}.`;
}
// check_vulns has no registry fields of its own, so it reports the same gap from the other side:
// which tools an agent must not reach for next.
function crossToolLimitation(kind) {
  if (kind === 'npm' || kind === 'pypi') return undefined;
  return `OSV covers ${kind}, but there is no ${kind} registry client here, so this tool is the only `
    + `one of the five that is correct for ${kind}. verify_package, package_info, audit_deps and `
    + `typosquat_scan would silently read registry.npmjs.org and answer about an npm package instead.`;
}

// Version ranges are not resolved, only mined for digits: "^4.17.20" is checked as 4.17.20.
const cleanVer = (v) => { const m = String(v || '').match(/\d+\.\d+(?:\.\d+)?/); return m ? m[0] : undefined; };

// Port of the audit-deps handler's parseInput, with `packages` accepted as an array (MCP) or a
// comma-separated string (the query-string form). Returns the dependency map plus anything that was
// supplied but could not be read, because silently dropping an input is its own kind of false pass.
function parseDeps(args) {
  const out = {};
  const inputErrors = [];
  if (args.dependencies && typeof args.dependencies === 'object') Object.assign(out, args.dependencies);
  if (typeof args.packageJson === 'string' && args.packageJson.trim()) {
    try {
      const j = JSON.parse(args.packageJson);
      Object.assign(out, j.dependencies || {}, j.devDependencies || {});
    } catch (e) {
      inputErrors.push(`packageJson did not parse as JSON (${String((e && e.message) || e)}), so none of its dependencies were read.`);
    }
  }
  if (typeof args.requirements === 'string') {
    for (const line of args.requirements.split(/\r?\n/)) {
      const m = line.trim().match(/^([A-Za-z0-9._-]+)\s*(?:[=<>!~]+\s*([0-9][\w.]*))?/);
      if (m && m[1] && !line.trim().startsWith('#')) out[m[1]] = m[2] || '';
    }
  }
  const list = Array.isArray(args.packages) ? args.packages
    : (typeof args.packages === 'string' ? args.packages.split(',') : []);
  for (const n of list) { const t = String(n || '').trim(); if (t) out[t] = out[t] || ''; }
  return { deps: out, inputErrors };
}

module.exports = [
  {
    name: 'verify_package',
    product: 'package-guard',
    description:
      'The pre-install guard for npm and PyPI. Call it before installing or recommending a package. '
      + 'Returns safe, caution or danger from deterministic checks: is the name registered, does OSV hold '
      + 'vulnerability or malware advisories for it, how old is it, weekly downloads, deprecation, license. '
      + 'If the name is not in the registry, likely_hallucination is set and npm names come with a "did you '
      + 'mean" list (PyPI names get an empty list). That flag means "not in this registry" and cannot tell an '
      + 'AI-invented name from a typo, a rename, or a package that only lives in a private registry. '
      + 'The slopsquat and typosquat score is a heuristic, not a finding: it adds up age under 90 days, under '
      + '50 weekly downloads, and a name within 2 edits of an npm search hit, so it both false-alarms on new '
      + 'legitimate packages and misses well-aged malicious ones. Package contents are never downloaded or '
      + 'analysed, so a malicious package with no OSV advisory reads as safe here. '
      + 'vulnerabilities.checked=false with count=null means the OSV lookup failed and the package was NOT '
      + 'checked: treat that as unknown, not as clean.',
    needs: ['registry.npmjs.org', 'pypi.org', 'api.osv.dev'],
    input: {
      name: { type: 'string', description: 'Package name (e.g. "express", "@scope/pkg", "requests").' },
      ecosystem: { type: 'string', optional: true, enum: ['npm', 'pypi'], description: 'Package ecosystem: npm or pypi (default npm). Other ecosystems have no registry client here. Use check_vulns for those.' },
      version: { type: 'string', optional: true, description: 'Specific version to check vulns against (default: latest).' },
    },
    async run(args, ctx = {}) {
      const t0 = Date.now();
      const name = String(args.name || args.package || '').trim();
      const e = eco(args.ecosystem || 'npm');
      const version = args.version ? String(args.version).trim() : undefined;

      if (!name) return { ok: false, error: 'Provide name' };
      if (!e) return { ok: false, error: 'Unknown ecosystem. Use npm, pypi, go, crates, rubygems, maven, or nuget.' };
      if (!validName(name)) return { ok: false, error: 'Invalid package name' };
      if (ctx.offline) return unavailable('verify_package', ['registry.npmjs.org', 'pypi.org', 'api.osv.dev'], 'offline mode: existence, vulnerabilities and download counts are all remote lookups');

      const m = await meta(e.kind, name);
      const limitation = registryLimitation(e.kind);

      // Does not exist -> the slopsquat / hallucination case.
      if (m.exists === false) {
        let suggestions = [];
        if (e.kind === 'npm') {
          const hits = await npmSearch(name, 10);
          suggestions = hits.map((h) => h.name).filter((n) => n && n !== name)
            .sort((a, b) => levenshtein(a, name) - levenshtein(b, name)).slice(0, 5);
        }
        return {
          ok: true, name, ecosystem: e.kind, exists: false, verdict: 'danger',
          likely_hallucination: true,
          reasons: ['Package does not exist in the registry — likely an AI-hallucinated or unregistered name. Attackers register these ("slopsquatting"). Do NOT install.'],
          suggestions,
          registry_source: registrySource(e.kind), registry_limitation: limitation,
          ms: Date.now() - t0,
        };
      }
      // A registry that could not be reached is not a registry that said no.
      if (m.exists === null) return { ...unavailable('verify_package', [registrySource(e.kind)], 'Registry lookup failed'), detail: m.error };

      // Exists -> assess.
      const v = await vulns(e.osv, name, version || m.latest);
      const vlist = v.list || [];
      const malicious = vlist.some((x) => x.malicious);
      const hasVuln = vlist.length > 0;
      // OSV returning an error is not the same as OSV returning nothing. Before this, an unreachable
      // OSV produced an empty list, which read as "no known vulnerabilities" and shipped verdict
      // "safe".
      const vulnChecked = !v.error;

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
      if (!vulnChecked) {
        if (verdict === 'safe') verdict = 'caution';
        reasons.push(`The OSV vulnerability lookup failed (${v.error}), so this package was NOT checked for known vulnerabilities or malware. Treat that as unknown, not as clean.`);
      }
      // Same rule for the registry half: a verdict built on the wrong registry is not a clean bill.
      if (limitation) { if (verdict === 'safe') verdict = 'caution'; reasons.push(limitation); }
      if (verdict === 'safe') reasons.push('Exists, no known vulnerabilities, healthy signals.');

      return {
        ok: true, name, ecosystem: e.kind, exists: true, verdict,
        version_checked: version || m.latest, latest: m.latest,
        age_days: m.age_days, weekly_downloads: m.weekly_downloads, deprecated: m.deprecated,
        license: m.license, repository: m.repository,
        slopsquat: { risk: slopsquat_risk, signals: slopSignals, confusable_with: confusable || undefined },
        vulnerabilities: { checked: vulnChecked, count: vulnChecked ? vlist.length : null, malicious, list: vlist.slice(0, 5), error: v.error || undefined },
        reasons,
        registry_source: registrySource(e.kind), registry_limitation: limitation,
        ms: Date.now() - t0,
      };
    },
  },

  {
    name: 'check_vulns',
    product: 'package-guard',
    description:
      'Known vulnerabilities and malware advisories for a package, optionally for one version, from the '
      + 'OSV.dev database. This is the one tool here that is correct for all seven ecosystems it accepts '
      + '(npm, PyPI, Go, crates.io, RubyGems, Maven, NuGet), because it queries OSV directly and never '
      + 'touches a registry. It therefore cannot tell you whether the package exists, who publishes it, or '
      + 'whether it is maintained. An empty list means OSV held nothing for that name and version, not that '
      + 'the package is safe: OSV only knows what has been reported. A failed lookup returns an error and '
      + 'never an empty list.',
    needs: ['api.osv.dev'],
    input: {
      name: { type: 'string', description: 'Package name.' },
      ecosystem: { type: 'string', optional: true, enum: ['npm', 'pypi', 'go', 'crates', 'rubygems', 'maven', 'nuget'], description: 'Package ecosystem (default npm).' },
      version: { type: 'string', optional: true, description: 'Version (omit to check all versions).' },
    },
    async run(args, ctx = {}) {
      const t0 = Date.now();
      const name = String(args.name || args.package || '').trim();
      const e = eco(args.ecosystem || 'npm');
      const version = args.version ? String(args.version).trim() : undefined;

      if (!name) return { ok: false, error: 'Provide name' };
      if (!e) return { ok: false, error: 'Unknown ecosystem' };
      if (!validName(name)) return { ok: false, error: 'Invalid package name' };
      if (ctx.offline) return unavailable('check_vulns', ['api.osv.dev'], 'offline mode: the OSV advisory database is remote and there is no local copy');

      const v = await vulns(e.osv, name, version);
      if (v.error) return { ...unavailable('check_vulns', ['api.osv.dev'], 'OSV lookup failed'), detail: v.error };

      const out = {
        ok: true, name, ecosystem: e.kind, version: version || 'all',
        count: v.list.length, malicious: v.list.some((x) => x.malicious),
        vulnerabilities: v.list,
        // Say what did not run: no registry was contacted, so "count: 0" is an OSV fact and not an
        // existence check. A name nobody has ever published also returns count 0.
        registry_checked: false,
        note: 'OSV.dev only. No registry was queried, so this says nothing about whether the package exists or who publishes it. Use verify_package (npm and PyPI) for that.',
        ms: Date.now() - t0,
      };
      // The other four tools cannot do this ecosystem at all. Better said here than discovered later.
      const limitation = crossToolLimitation(e.kind);
      if (limitation) out.registry_limitation = limitation;
      return out;
    },
  },

  {
    name: 'package_info',
    product: 'package-guard',
    description:
      'Registry metadata for an npm or PyPI package: latest version, first and last publish dates, age, '
      + 'weekly downloads, deprecation, license, repository and description. Use it to judge whether a '
      + 'dependency is maintained. It makes no security judgement and runs no vulnerability lookup. '
      + 'Weekly downloads come from api.npmjs.org or pypistats.org and the field is simply absent when '
      + 'those are unavailable, so a missing weekly_downloads is not a zero. License and repository are '
      + 'whatever the publisher declared, unverified.',
    needs: ['registry.npmjs.org', 'pypi.org'],
    input: {
      name: { type: 'string', description: 'Package name.' },
      ecosystem: { type: 'string', optional: true, enum: ['npm', 'pypi'], description: 'Package ecosystem: npm or pypi (default npm). Other ecosystems have no registry client here. Use check_vulns for those.' },
    },
    async run(args, ctx = {}) {
      const t0 = Date.now();
      const name = String(args.name || args.package || '').trim();
      const e = eco(args.ecosystem || 'npm');

      if (!name) return { ok: false, error: 'Provide name' };
      if (!e) return { ok: false, error: 'Unknown ecosystem' };
      if (!validName(name)) return { ok: false, error: 'Invalid package name' };
      if (ctx.offline) return unavailable('package_info', ['registry.npmjs.org', 'pypi.org'], 'offline mode: registry metadata is a remote lookup');

      const m = await meta(e.kind, name);
      const limitation = registryLimitation(e.kind);
      if (m.exists === false) {
        return {
          ok: true, name, ecosystem: e.kind, exists: false,
          registry_source: registrySource(e.kind), registry_limitation: limitation,
          ms: Date.now() - t0,
        };
      }
      if (m.exists === null) return { ...unavailable('package_info', [registrySource(e.kind)], 'Registry lookup failed'), detail: m.error };
      return {
        ok: true, name, ecosystem: e.kind, ...m,
        registry_source: registrySource(e.kind), registry_limitation: limitation,
        ms: Date.now() - t0,
      };
    },
  },

  {
    name: 'audit_deps',
    product: 'package-guard',
    description:
      'Audit a set of npm or PyPI dependencies in one call. Give it a list of names, or the text of a '
      + 'package.json (its dependencies and devDependencies), or the text of a requirements.txt. Returns a '
      + 'per-package report (exists, vulns, malicious, deprecated, verdict, flags) and a summary. '
      + 'Direct entries only: no lockfile is parsed and no transitive dependency is resolved, so this is not '
      + 'a full-tree audit and a vulnerable grandchild dependency will not appear. First 40 names, the rest '
      + 'are dropped and truncated is set. A version range is reduced to the digits inside it, so ^4.17.20 is '
      + 'checked as 4.17.20 and the real resolved version may differ. When the batch OSV call fails, every '
      + 'package reports vulns=null with vulns_checked=false rather than a reassuring zero.',
    needs: ['registry.npmjs.org', 'pypi.org', 'api.osv.dev'],
    input: {
      packages: { type: 'array', optional: true, description: 'List of package names.' },
      packageJson: { type: 'string', optional: true, description: 'Raw package.json content.' },
      requirements: { type: 'string', optional: true, description: 'Raw requirements.txt content.' },
      ecosystem: { type: 'string', optional: true, enum: ['npm', 'pypi'], description: 'Package ecosystem: npm or pypi (default npm). Other ecosystems have no registry client here. Use check_vulns for those.' },
    },
    async run(args, ctx = {}) {
      const t0 = Date.now();
      const e = eco(args.ecosystem || 'npm');
      if (!e) return { ok: false, error: 'Unknown ecosystem' };

      const { deps, inputErrors } = parseDeps(args);
      let names = Object.keys(deps).filter(validName);
      if (names.length === 0) {
        const out = { ok: false, error: 'No dependencies provided. Pass packages: ["a","b"], or packageJson, or requirements.' };
        if (inputErrors.length) { out.error += ' ' + inputErrors.join(' '); out.input_errors = inputErrors; }
        return out;
      }
      if (ctx.offline) return unavailable('audit_deps', ['registry.npmjs.org', 'pypi.org', 'api.osv.dev'], 'offline mode: every package in the list needs a registry and an OSV lookup');

      const truncated = names.length > 40;
      names = names.slice(0, 40);

      // OSV batch (one call) for all packages.
      const queries = names.map((n) => { const v = cleanVer(deps[n]); return v ? { package: { name: n, ecosystem: e.osv }, version: v } : { package: { name: n, ecosystem: e.osv } }; });
      const osv = await fetchJson('https://api.osv.dev/v1/querybatch', { method: 'POST', body: { queries }, timeoutMs: 9000 });
      // One failed batch call used to become an empty result array, which came out the other end as
      // "0 vulnerabilities" for every package in the list. Same bug class verify_package already
      // guards against, so it is tracked the same way here: checked flag, null count, no clean verdict.
      const osvChecked = !!(osv.ok && osv.json && Array.isArray(osv.json.results));
      const osvError = osvChecked ? undefined : (osv.error || `osv ${osv.status}`);
      const osvResults = osvChecked ? osv.json.results : [];

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
        // The two "did not run" cases. Neither may leave a package sitting at safe.
        if (m.exists === null) {
          if (verdict === 'safe') verdict = 'caution';
          flags.push(`registry-lookup-failed (${m.error || 'unknown error'}): existence NOT checked`);
        }
        if (!osvChecked) {
          if (verdict === 'safe') verdict = 'caution';
          flags.push('osv-lookup-failed: NOT checked for vulnerabilities or malware');
        }
        return {
          name: n, requested: deps[n] || undefined, exists: m.exists, latest: m.latest,
          vulns: osvChecked ? vs.length : null, malicious, deprecated: !!m.deprecated,
          verdict, flags, vulns_checked: osvChecked, exists_checked: m.exists !== null,
        };
      });

      const tally = (k, val) => report.filter((r) => r[k] === val).length;
      const out = {
        ok: true, ecosystem: e.kind, total: report.length, truncated: truncated || undefined,
        summary: {
          danger: tally('verdict', 'danger'), caution: tally('verdict', 'caution'), safe: tally('verdict', 'safe'),
          missing: report.filter((r) => r.exists === false).length,
          malicious: report.filter((r) => r.malicious).length,
          vulnerable: report.filter((r) => r.vulns > 0).length,
          deprecated: report.filter((r) => r.deprecated).length,
          // Added: how many packages had a lookup that did not run. Read this before the rest.
          unchecked: report.filter((r) => !r.vulns_checked || !r.exists_checked).length,
        },
        packages: report,
        vulnerabilities_checked: osvChecked,
        registry_source: registrySource(e.kind), registry_limitation: registryLimitation(e.kind),
        ms: Date.now() - t0,
      };
      if (!osvChecked) {
        out.osv_error = osvError;
        out.note = `The batch OSV lookup failed (${osvError}), so no package in this list was checked for known vulnerabilities or malware. vulns is null, not zero. Treat every verdict below as unknown on that axis.`;
      }
      if (inputErrors.length) out.input_errors = inputErrors;
      return out;
    },
  },

  {
    name: 'typosquat_scan',
    product: 'package-guard',
    description:
      'Generate lookalike names around an npm or PyPI package and report which ones are actually '
      + 'registered and which look recent enough to be suspicious. The variants are heuristic and ASCII '
      + 'only: single-character deletions, adjacent transpositions, doubled letters, the swaps l/1, o/0, '
      + 'rn/m, -/_, ./-, i/l and s/z, and the name with every hyphen or underscore dropped. Up to 20 '
      + 'variants, no Unicode homoglyphs, no prefix or suffix squats such as name-js or python-name, so an '
      + 'empty result is not evidence that nobody is squatting the name. "suspicious" means only that the '
      + 'variant is registered and is either under a year old or has no creation date, which catches new '
      + 'squats and also flags legitimate new packages. Registration is not evidence of malice: nothing '
      + 'here inspects what a variant contains.',
    needs: ['registry.npmjs.org', 'pypi.org'],
    input: {
      name: { type: 'string', description: 'Package name to scan around.' },
      ecosystem: { type: 'string', optional: true, enum: ['npm', 'pypi'], description: 'Package ecosystem: npm or pypi (default npm). Other ecosystems have no registry client here. Use check_vulns for those.' },
    },
    async run(args, ctx = {}) {
      const t0 = Date.now();
      const name = String(args.name || args.package || '').trim();
      const e = eco(args.ecosystem || 'npm');

      if (!name) return { ok: false, error: 'Provide name' };
      if (!e) return { ok: false, error: 'Unknown ecosystem' };
      if (!validName(name)) return { ok: false, error: 'Invalid package name' };
      if (ctx.offline) return unavailable('typosquat_scan', ['registry.npmjs.org', 'pypi.org'], 'offline mode: variants are only meaningful once the registry says which of them are registered');

      const variants = typosquats(name).slice(0, 20);
      const results = await Promise.all(variants.map(async (vn) => {
        const m = await meta(e.kind, vn, { downloads: false });
        // exists === null is a failed lookup, not an unregistered name. The API handler folded the
        // two together, so a registry outage produced "registered: 0", which reads as all clear.
        if (m.exists === null) return { unchecked: vn, error: m.error };
        if (m.exists !== true) return null;
        const suspicious = typeof m.age_days === 'number' ? m.age_days < 365 : true;
        return { match: { name: vn, age_days: m.age_days, latest: m.latest, suspicious } };
      }));

      const found = results.filter((r) => r && r.match).map((r) => r.match);
      const unchecked = results.filter((r) => r && r.unchecked);
      // Nothing got through: there is no scan to report, only a failure.
      if (variants.length && unchecked.length === variants.length) {
        return { ...unavailable('typosquat_scan', [registrySource(e.kind)], 'Registry lookup failed for every variant'), detail: unchecked[0].error };
      }

      const out = {
        ok: true, name, ecosystem: e.kind, variants_checked: variants.length,
        registered: found.length, suspicious: found.filter((f) => f.suspicious).length,
        matches: found,
        registry_source: registrySource(e.kind), registry_limitation: registryLimitation(e.kind),
        ms: Date.now() - t0,
      };
      // variants_checked keeps its original meaning (variants generated and attempted). The count
      // that did not come back is reported next to it rather than folded into "not registered".
      if (unchecked.length) {
        out.variants_unchecked = unchecked.length;
        out.checks_skipped = unchecked.map((u) => ({ id: u.unchecked, reason: u.error || 'registry lookup failed' }));
        out.note = `${unchecked.length} of ${variants.length} variants could not be looked up, so "registered" is a floor, not a total.`;
      }
      return out;
    },
  },
];
