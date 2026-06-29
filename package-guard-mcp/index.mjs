#!/usr/bin/env node
// package-guard-mcp — MCP server: the pre-install supply-chain guard for AI coding agents.
// Tools call the live Package Guard API (OSV.dev + npm/PyPI). Deterministic, no LLM.
//   verify_package  -> the guard: exists? slopsquat/hallucination? vulns/malware? -> a verdict
//   check_vulns     -> known vulnerabilities + malware advisories (OSV)
//   package_info    -> latest/deprecated/license/repo/downloads/age
//   audit_deps      -> batch-audit a whole dependency list
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

const ECO = z.enum(['npm', 'pypi', 'go', 'crates', 'rubygems', 'maven', 'nuget']).optional().describe('Package ecosystem (default npm).');
const server = new McpServer({ name: 'package-guard', version: '1.0.0' });

server.tool(
  'verify_package',
  'THE PRE-INSTALL GUARD. Before installing or recommending a package, call this. Returns a verdict (safe/caution/danger): whether the package EXISTS (if not, it is likely an AI hallucination or "slopsquat" — do not install — plus suggested real names), plus known vulnerabilities/malware, slopsquat/typosquat risk, deprecation, and license. Use on every dependency an agent is about to add.',
  { name: z.string().describe('Package name (e.g. "express", "@scope/pkg", "requests").'), ecosystem: ECO, version: z.string().optional().describe('Specific version to check vulns against (default: latest).') },
  async ({ name, ecosystem, version }) => { try { const j = await get('/api/verify-package', { name, ecosystem, version }); return j.ok || j.exists === false ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'verify failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

server.tool(
  'check_vulns',
  'List known vulnerabilities and malware advisories for a package (optionally a specific version) using the OSV.dev database. Covers npm, PyPI, Go, crates.io, RubyGems, Maven, NuGet.',
  { name: z.string().describe('Package name.'), ecosystem: ECO, version: z.string().optional().describe('Version (omit to check all versions).') },
  async ({ name, ecosystem, version }) => { try { const j = await get('/api/check-vulns', { name, ecosystem, version }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'vuln lookup failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

server.tool(
  'package_info',
  'Registry metadata for a package: latest version, deprecation status, license, repository, weekly downloads, and age. Use to judge whether a dependency is healthy and maintained.',
  { name: z.string().describe('Package name.'), ecosystem: ECO },
  async ({ name, ecosystem }) => { try { const j = await get('/api/package-info', { name, ecosystem }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'lookup failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

server.tool(
  'audit_deps',
  'Batch-audit a whole dependency list at once. Provide EITHER a list of package names, OR a package.json text, OR a requirements.txt text. Returns a per-package report (exists/vulns/malicious/deprecated/verdict) plus a summary. Use to vet an entire manifest before install/commit.',
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
  'Generate plausible lookalike (typosquat) names for a package and report which are actually registered and which look suspicious (recently created). Use for brand protection or to vet a name an agent is unsure about.',
  { name: z.string().describe('Package name to scan around.'), ecosystem: ECO },
  async ({ name, ecosystem }) => { try { const j = await get('/api/typosquat-scan', { name, ecosystem }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'scan failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

const transport = new StdioServerTransport();
await server.connect(transport);
console.error('package-guard-mcp running (5 tools).');
