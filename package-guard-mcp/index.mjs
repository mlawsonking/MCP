#!/usr/bin/env node
// package-guard-mcp — MCP server: the pre-install supply-chain guard for AI coding agents.
// Tools call the live Package Guard API (OSV.dev + npm/PyPI). Deterministic, no LLM.
// Registry-backed tools are npm + PyPI only; check_vulns is a pure OSV query and covers all seven.
//   verify_package  -> the guard: name registered? vulns/malware? age+downloads? -> a verdict
//   check_vulns     -> known vulnerabilities + malware advisories (OSV)
//   package_info    -> latest/deprecated/license/repo/downloads/age
//   audit_deps      -> check a list of direct dependencies (no lockfile, no tree resolution)
//   typosquat_scan  -> generate lookalikes and flag registered/suspicious ones

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const API = process.env.PACKAGE_GUARD_API || 'https://package-guard.vercel.app';

const ok = (text) => ({ content: [{ type: 'text', text }] });
const err = (msg) => ({ content: [{ type: 'text', text: `Error: ${msg}` }], isError: true });
async function get(path, params) {
  const qs = new URLSearchParams(Object.fromEntries(Object.entries(params).filter(([, v]) => v != null && v !== ''))).toString();
  const r = await fetch(`${API}${path}?${qs}`, { headers: { Accept: 'application/json' } });
  return r.json();
}

// OSV covers seven ecosystems, but only npm and PyPI have a registry client behind them,
// so every tool except check_vulns is limited to those two.
const ECO_OSV = z.enum(['npm', 'pypi', 'go', 'crates', 'rubygems', 'maven', 'nuget']).optional().describe('Package ecosystem (default npm).');
const ECO = z.enum(['npm', 'pypi']).optional().describe('Package ecosystem: npm or pypi (default npm). Other ecosystems have no registry client here. Use check_vulns for those.');
const server = new McpServer({ name: 'package-guard', version: '1.0.0' });

server.tool(
  'verify_package',
  'THE PRE-INSTALL GUARD, for npm and PyPI. Call before installing or recommending a package. Returns a verdict (safe/caution/danger) from deterministic checks: whether the registry has that name (if not, likely_hallucination is set, and on npm a "did you mean" list comes with it; PyPI names get an empty list). That flag means "not in this registry" and cannot tell an AI-invented name from a typo, a rename, or a package that only exists in a private registry. It also returns known vulnerabilities and malware from OSV, age and weekly downloads, whether the name is within 2 edits of an npm search hit, deprecation, and license. It never fetches or analyses package contents, so a malicious package with no OSV advisory reads as safe. vulnerabilities.checked=false with count=null means the OSV lookup failed and the package was NOT checked: treat as unknown, not clean.',
  { name: z.string().describe('Package name (e.g. "express", "@scope/pkg", "requests").'), ecosystem: ECO, version: z.string().optional().describe('Specific version to check vulns against (default: latest).') },
  async ({ name, ecosystem, version }) => { try { const j = await get('/api/verify-package', { name, ecosystem, version }); return j.ok || j.exists === false ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'verify failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

server.tool(
  'check_vulns',
  'List known vulnerabilities and malware advisories for a package (optionally a specific version) from the OSV.dev database. Covers npm, PyPI, Go, crates.io, RubyGems, Maven and NuGet. This is the only tool here that is correct for all seven. An empty list means OSV had nothing for that name and version, not that the package is safe; a failed lookup is an error, never an empty list.',
  { name: z.string().describe('Package name.'), ecosystem: ECO_OSV, version: z.string().optional().describe('Version (omit to check all versions).') },
  async ({ name, ecosystem, version }) => { try { const j = await get('/api/check-vulns', { name, ecosystem, version }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'vuln lookup failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

server.tool(
  'package_info',
  'Registry metadata for a package from npm or PyPI: latest version, deprecation status, license, repository, weekly downloads, and age. Use to judge whether a dependency is maintained. Weekly downloads come from api.npmjs.org or pypistats.org and are omitted when those are unavailable.',
  { name: z.string().describe('Package name.'), ecosystem: ECO },
  async ({ name, ecosystem }) => { try { const j = await get('/api/package-info', { name, ecosystem }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'lookup failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

server.tool(
  'audit_deps',
  'Audit a set of npm or PyPI dependencies in one call. Provide EITHER a list of package names, OR a package.json text (its dependencies and devDependencies), OR a requirements.txt text. Returns a per-package report (exists/vulns/malicious/deprecated/verdict) plus a summary. Direct entries only: no lockfile is parsed and no transitive dependency is resolved, so this is not a full-tree audit. First 40 names. A version range is reduced to the digits inside it, so ^4.17.20 is checked as 4.17.20. If the batch OSV call fails, every package reports vulns 0. This tool does not yet flag an unchecked lookup the way verify_package does.',
  {
    packages: z.array(z.string()).optional().describe('List of package names.'),
    packageJson: z.string().optional().describe('Raw package.json content.'),
    requirements: z.string().optional().describe('Raw requirements.txt content.'),
    ecosystem: ECO,
  },
  async ({ packages, packageJson, requirements, ecosystem }) => {
    try {
      let j;
      if (packages && packages.length) j = await get('/api/audit-deps', { packages: packages.join(','), ecosystem });
      else {
        const r = await fetch(`${API}/api/audit-deps`, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ packageJson, requirements, ecosystem: ecosystem || 'npm' }) });
        j = await r.json();
      }
      return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'audit failed');
    } catch (e) { return err(String((e && e.message) || e)); }
  }
);

server.tool(
  'typosquat_scan',
  'Generate lookalike (typosquat) names for an npm or PyPI package and report which are actually registered and which are recent enough to look suspicious. ASCII edits only: deletions, adjacent transpositions, doubled letters, the swaps l/1, o/0, rn/m, -/_, .-, i-l, s-z, and the name with every hyphen or underscore dropped. Up to 20 variants, no Unicode homoglyphs. "suspicious" means the variant is registered and either under a year old or has no creation date in the registry.',
  { name: z.string().describe('Package name to scan around.'), ecosystem: ECO },
  async ({ name, ecosystem }) => { try { const j = await get('/api/typosquat-scan', { name, ecosystem }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'scan failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

const transport = new StdioServerTransport();
await server.connect(transport);
console.error('package-guard-mcp running (5 tools).');
