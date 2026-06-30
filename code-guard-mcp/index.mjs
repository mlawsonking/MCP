#!/usr/bin/env node
// code-guard-mcp — MCP server: security scan for AI-generated code. Deterministic, no LLM.
//   scan_code  -> scan a code snippet for vulns before committing/running it
//   scan_diff  -> scan only the added lines of a unified diff
//   list_rules -> the rule catalog (coverage)

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const API = process.env.CODE_GUARD_API || 'https://code-guard-api.vercel.app';
const ok = (text) => ({ content: [{ type: 'text', text }] });
const err = (msg) => ({ content: [{ type: 'text', text: `Error: ${msg}` }], isError: true });
async function post(path, body) { const r = await fetch(`${API}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) }); return r.json(); }
async function get(path) { const r = await fetch(`${API}${path}`, { headers: { Accept: 'application/json' } }); return r.json(); }

const server = new McpServer({ name: 'code-guard', version: '1.0.0' });

server.tool(
  'scan_code',
  'Security-scan a snippet of code you (the agent) just generated, BEFORE committing or running it. Deterministic rule engine (no LLM) for the high-frequency vulnerability classes in AI-written code: command/code/SQL injection, SSRF, hardcoded secrets & API keys, weak crypto, unsafe deserialization (pickle/yaml), disabled TLS verification, XSS / template injection. Returns findings (rule id, category, severity, line, message, remediation) and a verdict: pass / review / block. Fast first-line check, not a full audit.',
  { code: z.string().describe('The source code to scan.'), language: z.string().optional().describe('python | javascript | typescript | … (optional; auto-detected).') },
  async ({ code, language }) => { try { const j = await post('/api/scan-code', { code, language }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'scan failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

server.tool(
  'scan_diff',
  'Scan only the ADDED lines of a unified diff (your just-written change), with correct new-file line numbers. Use in a commit loop to catch vulnerabilities you just introduced. Returns findings + a verdict: pass / review / block.',
  { diff: z.string().describe('A unified diff (git diff).'), language: z.string().optional() },
  async ({ diff, language }) => { try { const j = await post('/api/scan-diff', { diff, language }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'scan failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

server.tool(
  'list_rules',
  'List the deterministic rule catalog Code Guard checks (rule id, category, severity, language), so you know its coverage.',
  {},
  async () => { try { const j = await get('/api/rules'); return j.ok ? ok(JSON.stringify(j, null, 2)) : err('failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

const transport = new StdioServerTransport();
await server.connect(transport);
console.error('code-guard-mcp running (3 tools).');
