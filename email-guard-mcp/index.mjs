#!/usr/bin/env node
// email-guard-mcp — MCP server: email safety for AI agents. Deterministic, no LLM.
//   scan_inbound      -> "AI agent phishing" defense: injection/hijack + spoof + risky links before the agent acts
//   scan_outbound     -> secret/PII leak + deliverability + recipient-burn check before the agent sends
//   check_domain_auth -> SPF/DKIM/DMARC/MX/age/disposable posture for a domain

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const API = process.env.EMAIL_GUARD_API || 'https://email-guard-api.vercel.app';
const ok = (text) => ({ content: [{ type: 'text', text }] });
const err = (msg) => ({ content: [{ type: 'text', text: `Error: ${msg}` }], isError: true });
async function post(path, body) { const r = await fetch(`${API}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) }); return r.json(); }
async function get(path, params) { const qs = new URLSearchParams(Object.fromEntries(Object.entries(params).filter(([, v]) => v != null && v !== ''))).toString(); const r = await fetch(`${API}${path}?${qs}`, { headers: { Accept: 'application/json' } }); return r.json(); }

const server = new McpServer({ name: 'email-guard', version: '1.0.0' });

server.tool(
  'scan_inbound',
  'Scan an INBOUND email before the agent acts on it — the defense against "AI agent phishing." Detects prompt-injection / hijack instructions hidden in the body (including zero-width, bidi, and hidden-HTML payloads), spoofed or impersonating senders (SPF/DKIM/DMARC fail, brand impersonation, reply-to mismatch, disposable or brand-new domains), and risky links. Returns a verdict (allow/review/block) plus SAFE structured metadata, so you act on facts rather than the raw injection-laden text. Pass a raw RFC822 email as `email`, or the structured fields.',
  { email: z.string().optional().describe('Raw RFC822 email (headers + body).'), from: z.string().optional(), subject: z.string().optional(), body: z.string().optional(), html: z.string().optional() },
  async (a) => { try { const j = await post('/api/scan-inbound', a.email ? { email: a.email } : a); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'scan failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

server.tool(
  'scan_outbound',
  'Scan an OUTBOUND email before the agent sends it. Detects leaked secrets / API keys and PII in the body (returns a redacted copy), deliverability/spam problems that would burn the sender domain (spam-trigger words, missing List-Unsubscribe, image-heavy, risky links), and recipient risk (disposable domain, or no MX records = guaranteed bounce). Returns a verdict: allow/review/block.',
  { from: z.string().optional(), to: z.string().optional(), subject: z.string().optional(), body: z.string().optional(), html: z.string().optional(), email: z.string().optional().describe('Or a raw RFC822 email instead of the fields.') },
  async (a) => { try { const j = await post('/api/scan-outbound', a); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'scan failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

server.tool(
  'check_domain_auth',
  'Check the email-auth posture of a domain (or an email address): SPF + DMARC records and policy, MX, domain age (RDAP), and whether it is a disposable/throwaway domain. Use to verify a sender is who they claim, or that a recipient domain can actually receive mail. Returns an authPosture: weak / enforced.',
  { domain: z.string().describe('Domain (example.com) or an email address.') },
  async ({ domain }) => { try { const j = await get('/api/check-domain-auth', { domain }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'check failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

const transport = new StdioServerTransport();
await server.connect(transport);
console.error('email-guard-mcp running (3 tools).');
